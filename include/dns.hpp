// dns.hpp - the single public header for ResolveX.
//
// Layers (each implemented in its own .cpp file):
//   dns.cpp      : DNS wire format only (encode query, parse response). No sockets.
//   resolver.cpp : UDP networking + orchestration (cache lookup, query, stats).
//   cache.cpp    : bounded in-memory TTL cache.
//   main.cpp     : CLI, output formatting and the offline test suite.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace resolvex {

using Bytes = std::vector<std::uint8_t>;

constexpr std::uint16_t kClassIN = 1;

// ---------------------------------------------------------------- errors ---

// A packet violated the DNS wire format (truncated, bad pointer, wrong ID...).
class DnsError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// A socket-level problem (send/receive failure, timeout).
class NetworkError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class TimeoutError : public NetworkError {
public:
    using NetworkError::NetworkError;
};

// ------------------------------------------------------------- DNS types ---

enum class RecordType : std::uint16_t {
    A = 1,
    NS = 2,
    CNAME = 5,
    MX = 15,
    AAAA = 28,
};

std::string record_type_name(std::uint16_t type);
bool parse_record_type(const std::string& text, RecordType& out);

// Lower-cases, strips one trailing dot and validates labels (1-63 chars,
// [a-z0-9-_], no leading/trailing '-'), total length <= 253.
// Throws std::invalid_argument on bad input. ASCII only (no IDN/punycode).
std::string normalize_domain(const std::string& domain);

struct Header {
    std::uint16_t id = 0;
    std::uint16_t flags = 0;
    std::uint16_t qdcount = 0;
    std::uint16_t ancount = 0;
    std::uint16_t nscount = 0;
    std::uint16_t arcount = 0;

    bool is_response() const { return (flags & 0x8000) != 0; }
    std::uint8_t opcode() const { return static_cast<std::uint8_t>((flags >> 11) & 0x0F); }
    bool truncated() const { return (flags & 0x0200) != 0; }
    std::uint8_t rcode() const { return static_cast<std::uint8_t>(flags & 0x000F); }
};

struct Question {
    std::string name;  // normalized, no trailing dot
    std::uint16_t type = 0;
    std::uint16_t cls = kClassIN;
};

struct ResourceRecord {
    std::string name;
    std::uint16_t type = 0;
    std::uint16_t cls = 0;
    std::uint32_t ttl = 0;
    std::string data;                 // A/AAAA text, NS/CNAME target, MX exchange
    std::uint16_t mx_preference = 0;  // only meaningful when type == MX
};

struct Response {
    Header header;
    Question question;
    std::vector<ResourceRecord> answers;  // empty if truncated or rcode != 0
    bool truncated = false;
    std::uint8_t rcode = 0;
};

// -------------------------------------------------------- wire-format API ---

Bytes encode_name(const std::string& normalized_name);
Bytes encode_query(const std::string& domain, RecordType type, std::uint16_t id);

Header parse_header(const Bytes& packet);

// Decodes a (possibly compressed) name starting at `offset`. On return `offset`
// points just past the name as it appears at the original position.
// Returns "" for the root name. Throws DnsError on any malformed input.
std::string decode_name(const Bytes& packet, std::size_t& offset);

// Fully validates a response: length, transaction ID, QR bit, echoed question,
// record bounds. Throws DnsError when malformed or when `expected_id` differs.
Response parse_response(const Bytes& packet, std::uint16_t expected_id,
                        const Question& expected_question);

std::string rcode_message(std::uint8_t rcode);

// ----------------------------------------------------------------- cache ---

using Clock = std::chrono::steady_clock;
using ClockFn = std::function<Clock::time_point()>;

struct CacheKey {
    std::string name;    // normalized domain
    std::uint16_t type;  // query type
    std::uint16_t cls;   // query class
    std::string server;  // "ip:port" of the upstream that answered

    bool operator<(const CacheKey& o) const;
};

// Bounded TTL cache. Eviction: when full, drop expired entries first, then the
// entry that would expire soonest. The clock is injectable so tests can
// simulate the passage of time without sleeping.
class DnsCache {
public:
    explicit DnsCache(std::size_t max_entries = 256, ClockFn clock = nullptr);

    // On hit, fills `answers` with records whose TTL is the *remaining* TTL.
    bool lookup(const CacheKey& key, std::vector<ResourceRecord>& answers);

    // Returns false (and stores nothing) if there are no answers or the
    // smallest TTL is zero. Entry lifetime = smallest TTL among the answers.
    bool store(const CacheKey& key, const std::vector<ResourceRecord>& answers);

    std::size_t size() const { return entries_.size(); }
    std::size_t max_entries() const { return max_entries_; }

private:
    struct Entry {
        std::vector<ResourceRecord> answers;
        Clock::time_point stored_at;
        Clock::time_point expires_at;
    };

    void purge_expired(Clock::time_point now);
    void make_room(Clock::time_point now);

    std::size_t max_entries_;
    ClockFn clock_;
    std::map<CacheKey, Entry> entries_;
};

// ----------------------------------------------------------------- stats ---

// In-memory only: statistics are lost when the process exits.
struct Stats {
    std::uint64_t total = 0;
    std::uint64_t successful = 0;
    std::uint64_t failed = 0;
    std::uint64_t cache_hits = 0;
    std::uint64_t cache_misses = 0;
    double total_latency_ms = 0.0;  // summed over all queries (hits included)

    double average_latency_ms() const {
        return total == 0 ? 0.0 : total_latency_ms / static_cast<double>(total);
    }
};

// -------------------------------------------------------------- resolver ---

struct QueryOptions {
    std::string server = "1.1.1.1";  // IPv4 dotted quad
    std::uint16_t port = 53;
    int timeout_ms = 3000;
};

enum class QueryStatus {
    Ok,      // NOERROR with at least one answer
    NoData,  // NOERROR but no records of the requested type
    Error,   // timeout, malformed packet, truncated, or non-zero RCODE
};

struct QueryResult {
    std::string domain;
    RecordType type = RecordType::A;
    std::string server;  // "ip:port"
    QueryStatus status = QueryStatus::Error;
    std::string message;  // human readable status/error detail
    std::uint8_t rcode = 0;
    bool cache_hit = false;
    double latency_ms = 0.0;
    std::vector<ResourceRecord> answers;
};

bool is_valid_ipv4(const std::string& text);
std::string server_label(const QueryOptions& options);

class Resolver {
public:
    Resolver(DnsCache& cache, Stats& stats) : cache_(cache), stats_(stats) {}

    // Throws std::invalid_argument for a bad domain or server address.
    // Network/DNS failures are reported through QueryResult, not exceptions.
    QueryResult resolve(const std::string& domain, RecordType type, const QueryOptions& options);

private:
    void query_upstream(QueryResult& result, const QueryOptions& options, const CacheKey& key);

    DnsCache& cache_;
    Stats& stats_;
};

}  // namespace resolvex
