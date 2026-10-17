#include "transport.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <random>

namespace resolvex {
namespace {

class SocketFd {
public:
    explicit SocketFd(int fd = -1) : fd_(fd) {}
    ~SocketFd() {
        if (fd_ >= 0) ::close(fd_);
    }
    SocketFd(const SocketFd&) = delete;
    SocketFd& operator=(const SocketFd&) = delete;

    int get() const { return fd_; }
    void reset(int fd = -1) {
        if (fd_ >= 0) ::close(fd_);
        fd_ = fd;
    }
    int release() {
        int temp = fd_;
        fd_ = -1;
        return temp;
    }

private:
    int fd_;
};

struct ParsedIp {
    int family = AF_INET;
    sockaddr_storage storage{};
    socklen_t len = 0;
};

ParsedIp parse_endpoint(const Endpoint& ep) {
    ParsedIp res;
    std::memset(&res.storage, 0, sizeof(res.storage));

    in_addr addr4;
    in6_addr addr6;
    if (inet_pton(AF_INET, ep.ip.c_str(), &addr4) == 1) {
        res.family = AF_INET;
        auto* sa = reinterpret_cast<sockaddr_in*>(&res.storage);
#ifdef __APPLE__
        sa->sin_len = sizeof(sockaddr_in);
#endif
        sa->sin_family = AF_INET;
        sa->sin_port = htons(ep.port);
        sa->sin_addr = addr4;
        res.len = sizeof(sockaddr_in);
    } else if (inet_pton(AF_INET6, ep.ip.c_str(), &addr6) == 1) {
        res.family = AF_INET6;
        auto* sa = reinterpret_cast<sockaddr_in6*>(&res.storage);
#ifdef __APPLE__
        sa->sin6_len = sizeof(sockaddr_in6);
#endif
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons(ep.port);
        sa->sin6_addr = addr6;
        res.len = sizeof(sockaddr_in6);
    } else {
        throw std::invalid_argument("'" + ep.ip + "' is not a valid IPv4 or IPv6 address");
    }
    return res;
}

bool same_address(const sockaddr_storage& a, const sockaddr_storage& b) {
    if (a.ss_family != b.ss_family) return false;
    if (a.ss_family == AF_INET) {
        auto* a4 = reinterpret_cast<const sockaddr_in*>(&a);
        auto* b4 = reinterpret_cast<const sockaddr_in*>(&b);
        return a4->sin_port == b4->sin_port &&
               a4->sin_addr.s_addr == b4->sin_addr.s_addr;
    } else if (a.ss_family == AF_INET6) {
        auto* a6 = reinterpret_cast<const sockaddr_in6*>(&a);
        auto* b6 = reinterpret_cast<const sockaddr_in6*>(&b);
        return a6->sin6_port == b6->sin6_port &&
               std::memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(in6_addr)) == 0;
    }
    return false;
}

}  // namespace

// -------------------------------------------------------- PosixTransport ---

ExchangeResult PosixTransport::exchange(const Endpoint& server, const Bytes& query,
                                      int timeout_ms, std::uint16_t expected_id,
                                      bool allow_tcp_fallback) {
    const auto start = std::chrono::steady_clock::now();
    Bytes udp_reply = exchange_udp(server, query, timeout_ms, expected_id);

    // Check truncation flag (TC bit: bit 9 of flags, located in byte 2, mask 0x02)
    const bool truncated = udp_reply.size() >= 4 && (udp_reply[2] & 0x02) != 0;
    if (truncated && allow_tcp_fallback) {
        const auto remaining = timeout_ms - std::chrono::duration_cast<std::chrono::milliseconds>(
                                                std::chrono::steady_clock::now() - start).count();
        const int tcp_timeout = std::max<int>(1000, static_cast<int>(remaining));
        Bytes tcp_reply = exchange_tcp(server, query, tcp_timeout, expected_id);
        const double latency = std::chrono::duration<double, std::milli>(
                                   std::chrono::steady_clock::now() - start).count();
        return {std::move(tcp_reply), true, latency};
    }

    const double latency = std::chrono::duration<double, std::milli>(
                               std::chrono::steady_clock::now() - start).count();
    return {std::move(udp_reply), false, latency};
}

Bytes PosixTransport::exchange_udp(const Endpoint& server, const Bytes& query,
                                   int timeout_ms, std::uint16_t expected_id) {
    const ParsedIp parsed = parse_endpoint(server);
    SocketFd sock(::socket(parsed.family, SOCK_DGRAM, 0));
    if (sock.get() < 0) {
        throw NetworkError(std::string("UDP socket() failed: ") + std::strerror(errno));
    }

    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ::setsockopt(sock.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    const ssize_t sent = ::sendto(sock.get(), query.data(), query.size(), 0,
                                  reinterpret_cast<const sockaddr*>(&parsed.storage), parsed.len);
    if (sent < 0) {
        throw NetworkError(std::string("sendto() failed: ") + std::strerror(errno));
    }
    if (static_cast<std::size_t>(sent) != query.size()) {
        throw NetworkError("sendto() sent a partial UDP packet");
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    Bytes buffer(4096);
    int ignored = 0;

    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        if (remaining <= 0) {
            std::string msg = "timed out after " + std::to_string(timeout_ms) + " ms waiting for a reply";
            if (ignored > 0) msg += " (ignored " + std::to_string(ignored) + " unexpected packet(s))";
            throw TimeoutError(msg);
        }

        pollfd pfd;
        pfd.fd = sock.get();
        pfd.events = POLLIN;
        pfd.revents = 0;
        const int ready = ::poll(&pfd, 1, static_cast<int>(remaining));
        if (ready < 0) {
            if (errno == EINTR) continue;
            throw NetworkError(std::string("poll() failed: ") + std::strerror(errno));
        }
        if (ready == 0) continue;

        sockaddr_storage from{};
        socklen_t from_len = sizeof(from);
        const ssize_t n = ::recvfrom(sock.get(), buffer.data(), buffer.size(), 0,
                                     reinterpret_cast<sockaddr*>(&from), &from_len);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (errno == ECONNREFUSED) throw NetworkError("connection refused (nothing listening on DNS port)");
            throw NetworkError(std::string("recvfrom() failed: ") + std::strerror(errno));
        }

        if (!same_address(from, parsed.storage) || n < 2) {
            ++ignored;
            continue;
        }

        const std::uint16_t id = static_cast<std::uint16_t>((buffer[0] << 8) | buffer[1]);
        if (id != expected_id) {
            ++ignored;
            continue;
        }

        return Bytes(buffer.begin(), buffer.begin() + n);
    }
}

Bytes PosixTransport::exchange_tcp(const Endpoint& server, const Bytes& query,
                                   int timeout_ms, std::uint16_t expected_id) {
    const ParsedIp parsed = parse_endpoint(server);
    SocketFd sock(::socket(parsed.family, SOCK_STREAM, 0));
    if (sock.get() < 0) {
        throw NetworkError(std::string("TCP socket() failed: ") + std::strerror(errno));
    }

    // Set non-blocking mode to support timed connection
    int flags = ::fcntl(sock.get(), F_GETFL, 0);
    if (flags < 0 || ::fcntl(sock.get(), F_SETFL, flags | O_NONBLOCK) < 0) {
        throw NetworkError("failed to set non-blocking TCP socket");
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

    int res = ::connect(sock.get(), reinterpret_cast<const sockaddr*>(&parsed.storage), parsed.len);
    if (res < 0) {
        if (errno != EINPROGRESS) {
            throw NetworkError(std::string("TCP connect() failed: ") + std::strerror(errno));
        }

        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) throw TimeoutError("TCP connection timed out");

        pollfd pfd;
        pfd.fd = sock.get();
        pfd.events = POLLOUT;
        pfd.revents = 0;
        int pr = ::poll(&pfd, 1, static_cast<int>(remaining));
        if (pr <= 0) throw TimeoutError("TCP connection timed out in poll");

        int err = 0;
        socklen_t elen = sizeof(err);
        if (::getsockopt(sock.get(), SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0) {
            throw NetworkError(std::string("TCP connect error: ") + (err ? std::strerror(err) : "failed"));
        }
    }

    // Send 2-byte length prefix + query
    Bytes tcp_send;
    tcp_send.reserve(query.size() + 2);
    tcp_send.push_back(static_cast<std::uint8_t>(query.size() >> 8));
    tcp_send.push_back(static_cast<std::uint8_t>(query.size() & 0xFF));
    tcp_send.insert(tcp_send.end(), query.begin(), query.end());

    std::size_t total_sent = 0;
    while (total_sent < tcp_send.size()) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) throw TimeoutError("TCP send timed out");

        pollfd pfd{sock.get(), POLLOUT, 0};
        int pr = ::poll(&pfd, 1, static_cast<int>(remaining));
        if (pr <= 0) throw TimeoutError("TCP send poll timed out");

        ssize_t n = ::send(sock.get(), tcp_send.data() + total_sent, tcp_send.size() - total_sent, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            throw NetworkError(std::string("TCP send failed: ") + std::strerror(errno));
        }
        total_sent += static_cast<std::size_t>(n);
    }

    // Read 2-byte length prefix
    std::uint8_t len_buf[2];
    std::size_t len_read = 0;
    while (len_read < 2) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) throw TimeoutError("TCP recv length prefix timed out");

        pollfd pfd{sock.get(), POLLIN, 0};
        int pr = ::poll(&pfd, 1, static_cast<int>(remaining));
        if (pr <= 0) throw TimeoutError("TCP recv length prefix poll timed out");

        ssize_t n = ::recv(sock.get(), len_buf + len_read, 2 - len_read, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            throw NetworkError(std::string("TCP recv failed: ") + std::strerror(errno));
        }
        if (n == 0) throw NetworkError("TCP server closed connection before sending length");
        len_read += static_cast<std::size_t>(n);
    }

    const std::uint16_t expected_bytes = static_cast<std::uint16_t>((len_buf[0] << 8) | len_buf[1]);
    if (expected_bytes < 12) throw DnsError("TCP DNS response length too short");

    Bytes reply(expected_bytes);
    std::size_t reply_read = 0;
    while (reply_read < expected_bytes) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) throw TimeoutError("TCP recv payload timed out");

        pollfd pfd{sock.get(), POLLIN, 0};
        int pr = ::poll(&pfd, 1, static_cast<int>(remaining));
        if (pr <= 0) throw TimeoutError("TCP recv payload poll timed out");

        ssize_t n = ::recv(sock.get(), reply.data() + reply_read, expected_bytes - reply_read, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            throw NetworkError(std::string("TCP recv payload failed: ") + std::strerror(errno));
        }
        if (n == 0) throw NetworkError("TCP server closed connection prematurely");
        reply_read += static_cast<std::size_t>(n);
    }

    const std::uint16_t id = static_cast<std::uint16_t>((reply[0] << 8) | reply[1]);
    if (id != expected_id) {
        throw DnsError("TCP transaction ID mismatch");
    }

    return reply;
}

// --------------------------------------------------------- MockTransport ---

std::string MockTransport::make_key(const std::string& server_ip, const std::string& domain, RecordType type) const {
    std::string key = server_ip + "|" + normalize_domain(domain) + "|" + record_type_name(static_cast<std::uint16_t>(type));
    return key;
}

void MockTransport::register_response(const std::string& server_ip, const std::string& domain,
                                     RecordType type, const Bytes& udp_reply, const Bytes& tcp_reply) {
    MockResponse mr;
    mr.udp_reply = udp_reply;
    mr.tcp_reply = tcp_reply.empty() ? udp_reply : tcp_reply;
    responses_[make_key(server_ip, domain, type)] = std::move(mr);
}

void MockTransport::register_timeout(const std::string& server_ip, const std::string& domain, RecordType type) {
    MockResponse mr;
    mr.timeout = true;
    responses_[make_key(server_ip, domain, type)] = std::move(mr);
}

void MockTransport::register_refused(const std::string& server_ip, const std::string& domain, RecordType type) {
    MockResponse mr;
    mr.connection_refused = true;
    responses_[make_key(server_ip, domain, type)] = std::move(mr);
}

ExchangeResult MockTransport::exchange(const Endpoint& server, const Bytes& query,
                                     int /*timeout_ms*/, std::uint16_t expected_id,
                                     bool allow_tcp_fallback) {
    if (query.size() < 12) throw DnsError("query packet too short");

    // Decode query question
    std::size_t off = 12;
    std::string qname = decode_name(query, off);
    std::uint16_t qtype = static_cast<std::uint16_t>((query[off] << 8) | query[off + 1]);
    RecordType rtype = static_cast<RecordType>(qtype);

    log_.push_back({server, qname, rtype, false});

    std::string key = make_key(server.ip, qname, rtype);
    auto it = responses_.find(key);
    if (it == responses_.end()) {
        throw NetworkError("MockTransport: no mock response registered for " + key);
    }

    if (it->second.timeout) {
        throw TimeoutError("MockTransport: simulated timeout for " + key);
    }
    if (it->second.connection_refused) {
        throw NetworkError("MockTransport: simulated connection refused for " + key);
    }

    Bytes reply = it->second.udp_reply;
    if (reply.size() >= 2) {
        reply[0] = static_cast<std::uint8_t>(expected_id >> 8);
        reply[1] = static_cast<std::uint8_t>(expected_id & 0xFF);
    }

    bool truncated = reply.size() >= 4 && (reply[2] & 0x02) != 0;
    if (truncated && allow_tcp_fallback) {
        Bytes tcp_reply = exchange_tcp(server, query, 1000, expected_id);
        return {std::move(tcp_reply), true, 1.0};
    }

    return {std::move(reply), false, 1.0};
}

Bytes MockTransport::exchange_tcp(const Endpoint& server, const Bytes& query,
                                 int /*timeout_ms*/, std::uint16_t expected_id) {
    if (query.size() < 12) throw DnsError("query packet too short");

    std::size_t off = 12;
    std::string qname = decode_name(query, off);
    std::uint16_t qtype = static_cast<std::uint16_t>((query[off] << 8) | query[off + 1]);
    RecordType rtype = static_cast<RecordType>(qtype);

    log_.push_back({server, qname, rtype, true});

    std::string key = make_key(server.ip, qname, rtype);
    auto it = responses_.find(key);
    if (it == responses_.end()) {
        throw NetworkError("MockTransport TCP: no mock response registered for " + key);
    }

    if (it->second.timeout) throw TimeoutError("MockTransport TCP: simulated timeout for " + key);
    if (it->second.connection_refused) throw NetworkError("MockTransport TCP: simulated connection refused for " + key);

    Bytes reply = it->second.tcp_reply;
    if (reply.size() >= 2) {
        reply[0] = static_cast<std::uint8_t>(expected_id >> 8);
        reply[1] = static_cast<std::uint8_t>(expected_id & 0xFF);
    }
    return reply;
}

}  // namespace resolvex
