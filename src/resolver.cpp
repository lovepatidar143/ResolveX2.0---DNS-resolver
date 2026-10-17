// resolver.cpp - UDP transport (POSIX sockets) and query orchestration.
// Packet building/parsing lives in dns.cpp; this file only moves bytes and
// decides what to do with the parsed result.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <random>

#include "dns.hpp"

namespace resolvex {
namespace {

// RAII wrapper: the descriptor is always closed, even when an exception unwinds.
class UdpSocket {
public:
    UdpSocket() : fd_(::socket(AF_INET, SOCK_DGRAM, 0)) {
        if (fd_ < 0) throw NetworkError(std::string("socket() failed: ") + std::strerror(errno));
    }
    ~UdpSocket() {
        if (fd_ >= 0) ::close(fd_);
    }
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    int fd() const { return fd_; }

private:
    int fd_;
};

sockaddr_in make_address(const std::string& ip, std::uint16_t port) {
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof addr);
#ifdef __APPLE__
    addr.sin_len = sizeof addr;
#endif
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
        throw std::invalid_argument("'" + ip + "' is not a valid IPv4 address");
    }
    return addr;
}

std::uint16_t random_transaction_id() {
    std::random_device rd;
    return static_cast<std::uint16_t>(rd() & 0xFFFF);
}

// Sends `query` and waits for a reply that comes from the server we asked AND
// carries our transaction ID. Anything else is discarded (it could be a stray
// or spoofed packet) and we keep waiting until the deadline.
Bytes exchange_udp(const Bytes& query, const sockaddr_in& server, int timeout_ms, std::uint16_t expected_id) {
    UdpSocket sock;

    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ::setsockopt(sock.fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);  // backstop; poll() drives the deadline

    const ssize_t sent = ::sendto(sock.fd(), query.data(), query.size(), 0,
                                  reinterpret_cast<const sockaddr*>(&server), sizeof server);
    if (sent < 0) throw NetworkError(std::string("sendto() failed: ") + std::strerror(errno));
    if (static_cast<std::size_t>(sent) != query.size()) throw NetworkError("sendto() sent a partial packet");

    const Clock::time_point deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    Bytes buffer(4096);
    int ignored = 0;

    for (;;) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        if (remaining <= 0) {
            std::string msg = "timed out after " + std::to_string(timeout_ms) + " ms waiting for a reply";
            if (ignored > 0) msg += " (ignored " + std::to_string(ignored) + " unexpected packet(s))";
            throw TimeoutError(msg);
        }

        pollfd pfd;
        pfd.fd = sock.fd();
        pfd.events = POLLIN;
        pfd.revents = 0;
        const int ready = ::poll(&pfd, 1, static_cast<int>(remaining));
        if (ready < 0) {
            if (errno == EINTR) continue;
            throw NetworkError(std::string("poll() failed: ") + std::strerror(errno));
        }
        if (ready == 0) continue;  // loop re-checks the deadline

        sockaddr_in from;
        socklen_t from_len = sizeof from;
        const ssize_t n = ::recvfrom(sock.fd(), buffer.data(), buffer.size(), 0,
                                     reinterpret_cast<sockaddr*>(&from), &from_len);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (errno == ECONNREFUSED) throw NetworkError("connection refused (nothing is listening on that DNS port)");
            throw NetworkError(std::string("recvfrom() failed: ") + std::strerror(errno));
        }

        const bool from_server = from.sin_addr.s_addr == server.sin_addr.s_addr && from.sin_port == server.sin_port;
        if (!from_server || n < 2) {
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

}  // namespace

bool is_valid_ipv4(const std::string& text) {
    in_addr addr;
    return inet_pton(AF_INET, text.c_str(), &addr) == 1;
}

std::string server_label(const QueryOptions& options) {
    return options.server + ":" + std::to_string(options.port);
}

QueryResult Resolver::resolve(const std::string& domain, RecordType type, const QueryOptions& options) {
    const Clock::time_point start = Clock::now();

    QueryResult result;
    result.domain = normalize_domain(domain);  // throws std::invalid_argument
    result.type = type;
    result.server = server_label(options);
    if (!is_valid_ipv4(options.server)) {
        throw std::invalid_argument("'" + options.server + "' is not a valid IPv4 address");
    }

    const CacheKey key{result.domain, static_cast<std::uint16_t>(type), kClassIN, result.server};

    if (cache_.lookup(key, result.answers)) {
        result.cache_hit = true;
        result.status = QueryStatus::Ok;
        result.message = "NOERROR (served from cache)";
    } else {
        query_upstream(result, options, key);
    }

    result.latency_ms = std::chrono::duration<double, std::milli>(Clock::now() - start).count();

    ++stats_.total;
    (result.cache_hit ? stats_.cache_hits : stats_.cache_misses)++;
    (result.status == QueryStatus::Error ? stats_.failed : stats_.successful)++;
    stats_.total_latency_ms += result.latency_ms;
    return result;
}

void Resolver::query_upstream(QueryResult& result, const QueryOptions& options, const CacheKey& key) {
    try {
        const std::uint16_t id = random_transaction_id();
        const Bytes query = encode_query(result.domain, result.type, id);
        const Question expected{result.domain, static_cast<std::uint16_t>(result.type), kClassIN};

        const sockaddr_in server = make_address(options.server, options.port);
        const Bytes reply = exchange_udp(query, server, options.timeout_ms, id);
        const Response response = parse_response(reply, id, expected);
        result.rcode = response.rcode;

        if (response.truncated) {
            result.status = QueryStatus::Error;
            result.message = "response truncated (TC flag set); results would be incomplete and TCP fallback is not implemented";
        } else if (response.rcode != 0) {
            result.status = QueryStatus::Error;  // errors are never cached
            result.message = rcode_message(response.rcode);
        } else if (response.answers.empty()) {
            result.status = QueryStatus::NoData;
            result.message = "NOERROR, but the server returned no " + record_type_name(static_cast<std::uint16_t>(result.type)) + " records";
        } else {
            result.status = QueryStatus::Ok;
            result.message = "NOERROR";
            result.answers = response.answers;
            cache_.store(key, response.answers);
        }
    } catch (const NetworkError& e) {
        result.status = QueryStatus::Error;
        result.message = e.what();
    } catch (const DnsError& e) {
        result.status = QueryStatus::Error;
        result.message = std::string("malformed response rejected: ") + e.what();
    }
}

}  // namespace resolvex
