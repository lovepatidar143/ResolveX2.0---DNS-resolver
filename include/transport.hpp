#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "dns.hpp"

namespace resolvex {

struct Endpoint {
    std::string ip;
    std::uint16_t port = 53;

    std::string to_string() const {
        if (ip.find(':') != std::string::npos) {
            return "[" + ip + "]:" + std::to_string(port);
        }
        return ip + ":" + std::to_string(port);
    }
};

struct ExchangeResult {
    Bytes reply;
    bool via_tcp = false;
    double latency_ms = 0.0;
};

class ITransport {
public:
    virtual ~ITransport() = default;

    // Performs query exchange. If UDP response is truncated and allow_tcp_fallback is true,
    // falls back to TCP automatically.
    virtual ExchangeResult exchange(const Endpoint& server, const Bytes& query,
                                   int timeout_ms, std::uint16_t expected_id,
                                   bool allow_tcp_fallback = true) = 0;

    // Direct TCP exchange
    virtual Bytes exchange_tcp(const Endpoint& server, const Bytes& query,
                               int timeout_ms, std::uint16_t expected_id) = 0;
};

// Production POSIX sockets transport supporting IPv4, IPv6, UDP, and TCP fallback.
class PosixTransport : public ITransport {
public:
    PosixTransport() = default;

    ExchangeResult exchange(const Endpoint& server, const Bytes& query,
                           int timeout_ms, std::uint16_t expected_id,
                           bool allow_tcp_fallback = true) override;

    Bytes exchange_tcp(const Endpoint& server, const Bytes& query,
                       int timeout_ms, std::uint16_t expected_id) override;

private:
    Bytes exchange_udp(const Endpoint& server, const Bytes& query,
                       int timeout_ms, std::uint16_t expected_id);
};

// Deterministic Mock Transport for unit tests and simulated offline scenarios.
class MockTransport : public ITransport {
public:
    struct MockResponse {
        Bytes udp_reply;
        Bytes tcp_reply;
        bool timeout = false;
        bool connection_refused = false;
    };

    struct QueryLogEntry {
        Endpoint server;
        std::string domain;
        RecordType type = RecordType::A;
        bool is_tcp = false;
    };

    MockTransport() = default;

    void register_response(const std::string& server_ip, const std::string& domain,
                           RecordType type, const Bytes& udp_reply, const Bytes& tcp_reply = {});

    void register_timeout(const std::string& server_ip, const std::string& domain, RecordType type);

    void register_refused(const std::string& server_ip, const std::string& domain, RecordType type);

    ExchangeResult exchange(const Endpoint& server, const Bytes& query,
                           int timeout_ms, std::uint16_t expected_id,
                           bool allow_tcp_fallback = true) override;

    Bytes exchange_tcp(const Endpoint& server, const Bytes& query,
                       int timeout_ms, std::uint16_t expected_id) override;

    const std::vector<QueryLogEntry>& query_log() const { return log_; }
    void clear_log() { log_.clear(); }

private:
    std::string make_key(const std::string& server_ip, const std::string& domain, RecordType type) const;

    std::map<std::string, MockResponse> responses_;
    std::vector<QueryLogEntry> log_;
};

}  // namespace resolvex
