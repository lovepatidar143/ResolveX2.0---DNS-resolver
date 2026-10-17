// dns.hpp - DNS types, data structures, and wire-format encoding/parsing.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
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
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    OPT = 41,
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
    bool authoritative() const { return (flags & 0x0400) != 0; }
    bool truncated() const { return (flags & 0x0200) != 0; }
    bool recursion_desired() const { return (flags & 0x0100) != 0; }
    bool recursion_available() const { return (flags & 0x0080) != 0; }
    bool authentic_data() const { return (flags & 0x0020) != 0; }
    bool checking_disabled() const { return (flags & 0x0010) != 0; }
    std::uint8_t rcode() const { return static_cast<std::uint8_t>(flags & 0x000F); }
};

struct Question {
    std::string name;  // normalized, no trailing dot
    std::uint16_t type = 0;
    std::uint16_t cls = kClassIN;
};

struct SoaData {
    std::string mname;
    std::string rname;
    std::uint32_t serial = 0;
    std::uint32_t refresh = 0;
    std::uint32_t retry = 0;
    std::uint32_t expire = 0;
    std::uint32_t minimum = 0;  // RFC 2308 negative caching TTL
};

struct ResourceRecord {
    std::string name;
    std::uint16_t type = 0;
    std::uint16_t cls = 0;
    std::uint32_t ttl = 0;
    std::string data;                 // Text representation
    std::uint16_t mx_preference = 0;  // meaningful when type == MX
    SoaData soa;                      // meaningful when type == SOA
    Bytes raw_rdata;                  // raw record payload
};

struct Response {
    Header header;
    Question question;
    std::vector<ResourceRecord> answers;      // Answer section
    std::vector<ResourceRecord> authorities;  // Authority section (NS, SOA)
    std::vector<ResourceRecord> additionals;  // Additional section (glue A/AAAA, OPT)
    bool truncated = false;
    std::uint8_t rcode = 0;
};

// -------------------------------------------------------- wire-format API ---

Bytes encode_name(const std::string& normalized_name);

// Generates a DNS query packet. By default recursion_desired=true and use_edns=false
// for backwards compatibility with existing tests; iterative resolution sets
// recursion_desired=false and use_edns=true.
Bytes encode_query(const std::string& domain, RecordType type, std::uint16_t id,
                   bool recursion_desired = true, bool use_edns = false,
                   std::uint16_t edns_buf_size = 1232);

Header parse_header(const Bytes& packet);

// Decodes a (possibly compressed) name starting at `offset`. On return `offset`
// points just past the name as it appears at the original position.
// Returns "" for the root name. Throws DnsError on any malformed input.
std::string decode_name(const Bytes& packet, std::size_t& offset);

// Parses a complete packet into a Response structure.
Response parse_packet(const Bytes& packet);

// Validates and parses response against expected transaction ID and query question.
// Throws DnsError when malformed or when expected_id/expected_question mismatch.
Response parse_response(const Bytes& packet, std::uint16_t expected_id,
                        const Question& expected_question);

std::string rcode_message(std::uint8_t rcode);

// ----------------------------------------------------------------- stats ---

struct Stats {
    std::uint64_t total = 0;
    std::uint64_t successful = 0;
    std::uint64_t failed = 0;
    std::uint64_t cache_hits = 0;
    std::uint64_t cache_misses = 0;
    double total_latency_ms = 0.0;

    double average_latency_ms() const {
        return total == 0 ? 0.0 : total_latency_ms / static_cast<double>(total);
    }
};

}  // namespace resolvex
