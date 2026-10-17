// dns.cpp - DNS wire format: building queries and parsing responses.
// Pure functions over byte buffers; no sockets here. Every read is bounds-checked.
#include "dns.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace resolvex {
namespace {

constexpr std::size_t kHeaderSize = 12;
constexpr std::size_t kMaxLabelLength = 63;
constexpr std::size_t kMaxNameWireLength = 255;

std::string hex16(std::uint16_t v) {
    char buf[8];
    std::snprintf(buf, sizeof buf, "0x%04x", static_cast<unsigned>(v));
    return buf;
}

void require(const Bytes& p, std::size_t offset, std::size_t length, const char* what) {
    if (offset > p.size() || length > p.size() - offset) {
        throw DnsError(std::string("truncated packet while reading ") + what);
    }
}

std::uint16_t read_u16(const Bytes& p, std::size_t off) {
    require(p, off, 2, "16-bit field");
    return static_cast<std::uint16_t>((p[off] << 8) | p[off + 1]);
}

std::uint32_t read_u32(const Bytes& p, std::size_t off) {
    require(p, off, 4, "32-bit field");
    return (static_cast<std::uint32_t>(p[off]) << 24) | (static_cast<std::uint32_t>(p[off + 1]) << 16) |
           (static_cast<std::uint32_t>(p[off + 2]) << 8) | static_cast<std::uint32_t>(p[off + 3]);
}

void put_u16(Bytes& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v >> 8));
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

// Names come from the network, so escape anything that could mangle a terminal.
void append_label_byte(std::string& out, std::uint8_t c) {
    if (c == '.' || c == '\\' || c <= 0x20 || c >= 0x7F) {
        char buf[8];
        std::snprintf(buf, sizeof buf, "\\%03u", static_cast<unsigned>(c));
        out += buf;
    } else {
        out += static_cast<char>(c);
    }
}

bool equals_ignore_case(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

Question parse_question(const Bytes& p, std::size_t& off) {
    Question q;
    q.name = decode_name(p, off);
    q.type = read_u16(p, off);
    q.cls = read_u16(p, off + 2);
    off += 4;
    return q;
}

// Decodes a name that must occupy exactly [off, rdata_end).
std::string decode_rdata_name(const Bytes& p, std::size_t off, std::size_t rdata_end, const char* what) {
    std::size_t pos = off;
    std::string name = decode_name(p, pos);
    if (pos != rdata_end) {
        throw DnsError(std::string(what) + " record data length does not match encoded name");
    }
    return name;
}

std::string format_address(int family, const Bytes& p, std::size_t off) {
    char buf[INET6_ADDRSTRLEN];
    if (inet_ntop(family, &p[off], buf, sizeof buf) == nullptr) {
        throw DnsError("could not format address");
    }
    return buf;
}

ResourceRecord parse_record(const Bytes& p, std::size_t& off) {
    ResourceRecord rr;
    rr.name = decode_name(p, off);
    require(p, off, 10, "record header");
    rr.type = read_u16(p, off);
    rr.cls = read_u16(p, off + 2);
    rr.ttl = read_u32(p, off + 4);
    if (rr.ttl & 0x80000000u) rr.ttl = 0;  // RFC 2181 s8: high bit set => treat as 0
    const std::uint16_t rdlength = read_u16(p, off + 8);
    off += 10;
    require(p, off, rdlength, "record data");
    const std::size_t rdata_end = off + rdlength;

    switch (rr.type) {
        case static_cast<std::uint16_t>(RecordType::A):
            if (rdlength != 4) throw DnsError("A record must have 4 bytes of data, got " + std::to_string(rdlength));
            rr.data = format_address(AF_INET, p, off);
            break;
        case static_cast<std::uint16_t>(RecordType::AAAA):
            if (rdlength != 16) throw DnsError("AAAA record must have 16 bytes of data, got " + std::to_string(rdlength));
            rr.data = format_address(AF_INET6, p, off);
            break;
        case static_cast<std::uint16_t>(RecordType::NS):
            rr.data = decode_rdata_name(p, off, rdata_end, "NS");
            break;
        case static_cast<std::uint16_t>(RecordType::CNAME):
            rr.data = decode_rdata_name(p, off, rdata_end, "CNAME");
            break;
        case static_cast<std::uint16_t>(RecordType::MX):
            if (rdlength < 3) throw DnsError("MX record too short");
            rr.mx_preference = read_u16(p, off);
            rr.data = decode_rdata_name(p, off + 2, rdata_end, "MX");
            break;
        default:
            rr.data = "<" + std::to_string(rdlength) + " bytes of unsupported type " + std::to_string(rr.type) + ">";
            break;
    }
    off = rdata_end;
    return rr;
}

}  // namespace

// ------------------------------------------------------- names and types ---

std::string record_type_name(std::uint16_t type) {
    switch (type) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 15: return "MX";
        case 28: return "AAAA";
        default: return "TYPE" + std::to_string(type);
    }
}

bool parse_record_type(const std::string& text, RecordType& out) {
    std::string up = text;
    std::transform(up.begin(), up.end(), up.begin(), [](unsigned char c) { return std::toupper(c); });
    if (up == "A") out = RecordType::A;
    else if (up == "AAAA") out = RecordType::AAAA;
    else if (up == "CNAME") out = RecordType::CNAME;
    else if (up == "MX") out = RecordType::MX;
    else if (up == "NS") out = RecordType::NS;
    else return false;
    return true;
}

std::string normalize_domain(const std::string& domain) {
    std::string name = domain;
    if (!name.empty() && name.back() == '.') name.pop_back();
    if (name.empty()) throw std::invalid_argument("domain name is empty");
    if (name.size() > 253) throw std::invalid_argument("domain name is longer than 253 characters");

    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return std::tolower(c); });

    std::size_t label_start = 0;
    while (label_start <= name.size()) {
        std::size_t dot = name.find('.', label_start);
        if (dot == std::string::npos) dot = name.size();
        const std::string label = name.substr(label_start, dot - label_start);
        if (label.empty()) throw std::invalid_argument("domain name contains an empty label: '" + domain + "'");
        if (label.size() > kMaxLabelLength) throw std::invalid_argument("label longer than 63 characters in '" + domain + "'");
        if (label.front() == '-' || label.back() == '-') throw std::invalid_argument("label may not start or end with '-': '" + label + "'");
        for (unsigned char c : label) {
            if (!(std::isalnum(c) || c == '-' || c == '_')) {
                throw std::invalid_argument(std::string("invalid character '") + static_cast<char>(c) + "' in domain '" + domain + "'");
            }
        }
        label_start = dot + 1;
    }
    return name;
}

// ---------------------------------------------------------------- encode ---

Bytes encode_name(const std::string& name) {
    Bytes out;
    std::size_t start = 0;
    while (start < name.size()) {
        std::size_t dot = name.find('.', start);
        if (dot == std::string::npos) dot = name.size();
        const std::size_t len = dot - start;
        if (len == 0 || len > kMaxLabelLength) throw std::invalid_argument("invalid label length in name");
        out.push_back(static_cast<std::uint8_t>(len));
        out.insert(out.end(), name.begin() + static_cast<std::ptrdiff_t>(start), name.begin() + static_cast<std::ptrdiff_t>(dot));
        start = dot + 1;
    }
    out.push_back(0);
    if (out.size() > kMaxNameWireLength) throw std::invalid_argument("encoded name too long");
    return out;
}

Bytes encode_query(const std::string& domain, RecordType type, std::uint16_t id) {
    const std::string name = normalize_domain(domain);
    Bytes packet;
    put_u16(packet, id);
    put_u16(packet, 0x0100);  // standard query, recursion desired
    put_u16(packet, 1);       // QDCOUNT
    put_u16(packet, 0);       // ANCOUNT
    put_u16(packet, 0);       // NSCOUNT
    put_u16(packet, 0);       // ARCOUNT
    const Bytes qname = encode_name(name);
    packet.insert(packet.end(), qname.begin(), qname.end());
    put_u16(packet, static_cast<std::uint16_t>(type));
    put_u16(packet, kClassIN);
    return packet;
}

// ----------------------------------------------------------------- parse ---

Header parse_header(const Bytes& p) {
    require(p, 0, kHeaderSize, "header");
    Header h;
    h.id = read_u16(p, 0);
    h.flags = read_u16(p, 2);
    h.qdcount = read_u16(p, 4);
    h.ancount = read_u16(p, 6);
    h.nscount = read_u16(p, 8);
    h.arcount = read_u16(p, 10);
    return h;
}

std::string decode_name(const Bytes& p, std::size_t& offset) {
    std::size_t pos = offset;
    std::size_t resume = 0;  // where the caller continues (after the first pointer)
    bool jumped = false;
    std::size_t wire_length = 1;  // the terminating zero byte
    std::string name;

    for (;;) {
        require(p, pos, 1, "name length byte");
        const std::uint8_t len = p[pos];

        if (len == 0) {
            ++pos;
            break;
        }
        if ((len & 0xC0) == 0xC0) {  // compression pointer
            require(p, pos, 2, "compression pointer");
            const std::size_t target = (static_cast<std::size_t>(len & 0x3F) << 8) | p[pos + 1];
            if (!jumped) {
                resume = pos + 2;
                jumped = true;
            }
            // Valid compression only points backwards. Requiring this makes
            // infinite pointer loops impossible.
            if (target >= pos) throw DnsError("invalid compression pointer (not pointing backwards)");
            pos = target;
            continue;
        }
        if ((len & 0xC0) != 0) throw DnsError("unsupported label type (reserved bits set)");

        require(p, pos + 1, len, "label");
        wire_length += 1u + len;
        if (wire_length > kMaxNameWireLength) throw DnsError("domain name exceeds 255 bytes");
        if (!name.empty()) name += '.';
        for (std::size_t i = 0; i < len; ++i) append_label_byte(name, p[pos + 1 + i]);
        pos += 1u + len;
    }

    offset = jumped ? resume : pos;
    return name;
}

std::string rcode_message(std::uint8_t rcode) {
    switch (rcode) {
        case 0: return "NOERROR";
        case 1: return "FORMERR: the server could not interpret the query";
        case 2: return "SERVFAIL: the server failed to complete the request (often a problem upstream of it)";
        case 3: return "NXDOMAIN: the domain name does not exist";
        case 4: return "NOTIMP: the server does not support this kind of query";
        case 5: return "REFUSED: the server refused to answer (policy or not authorised for this client)";
        default: return "unexpected DNS response code " + std::to_string(rcode);
    }
}

Response parse_response(const Bytes& p, std::uint16_t expected_id, const Question& expected) {
    Response r;
    r.header = parse_header(p);

    if (r.header.id != expected_id) {
        throw DnsError("transaction ID mismatch: expected " + hex16(expected_id) + ", got " + hex16(r.header.id));
    }
    if (!r.header.is_response()) throw DnsError("packet is a query, not a response (QR bit not set)");
    if (r.header.opcode() != 0) throw DnsError("unexpected opcode " + std::to_string(r.header.opcode()));
    if (r.header.qdcount != 1) {
        throw DnsError("expected exactly 1 question in response, got " + std::to_string(r.header.qdcount));
    }

    std::size_t off = kHeaderSize;
    r.question = parse_question(p, off);
    if (!equals_ignore_case(r.question.name, expected.name) || r.question.type != expected.type ||
        r.question.cls != expected.cls) {
        throw DnsError("response question does not match the query that was sent");
    }

    r.truncated = r.header.truncated();
    r.rcode = r.header.rcode();
    // Truncated packets are incomplete; error responses carry no answers we need.
    if (r.truncated || r.rcode != 0) return r;

    r.answers.reserve(std::min<std::size_t>(r.header.ancount, 64));
    for (std::uint16_t i = 0; i < r.header.ancount; ++i) r.answers.push_back(parse_record(p, off));
    // Validate (but discard) authority and additional sections so a corrupt
    // packet is rejected as a whole.
    const std::size_t extra = static_cast<std::size_t>(r.header.nscount) + r.header.arcount;
    for (std::size_t i = 0; i < extra; ++i) parse_record(p, off);
    return r;
}

}  // namespace resolvex
