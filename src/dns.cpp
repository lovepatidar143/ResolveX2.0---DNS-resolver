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
constexpr std::size_t kMaxJumps = 64;

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

void put_u32(Bytes& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
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
    const std::size_t rdata_start = off;
    const std::size_t rdata_end = off + rdlength;

    rr.raw_rdata.assign(p.begin() + static_cast<std::ptrdiff_t>(rdata_start),
                        p.begin() + static_cast<std::ptrdiff_t>(rdata_end));

    switch (rr.type) {
        case static_cast<std::uint16_t>(RecordType::A):
            if (rdlength != 4) throw DnsError("A record must have 4 bytes of data, got " + std::to_string(rdlength));
            rr.data = format_address(AF_INET, p, off);
            off = rdata_end;
            break;
        case static_cast<std::uint16_t>(RecordType::AAAA):
            if (rdlength != 16) throw DnsError("AAAA record must have 16 bytes of data, got " + std::to_string(rdlength));
            rr.data = format_address(AF_INET6, p, off);
            off = rdata_end;
            break;
        case static_cast<std::uint16_t>(RecordType::NS):
            rr.data = decode_rdata_name(p, off, rdata_end, "NS");
            off = rdata_end;
            break;
        case static_cast<std::uint16_t>(RecordType::CNAME):
            rr.data = decode_rdata_name(p, off, rdata_end, "CNAME");
            off = rdata_end;
            break;
        case static_cast<std::uint16_t>(RecordType::PTR):
            rr.data = decode_rdata_name(p, off, rdata_end, "PTR");
            off = rdata_end;
            break;
        case static_cast<std::uint16_t>(RecordType::MX):
            if (rdlength < 3) throw DnsError("MX record too short");
            rr.mx_preference = read_u16(p, off);
            rr.data = decode_rdata_name(p, off + 2, rdata_end, "MX");
            off = rdata_end;
            break;
        case static_cast<std::uint16_t>(RecordType::SOA): {
            std::size_t cur = off;
            rr.soa.mname = decode_name(p, cur);
            rr.soa.rname = decode_name(p, cur);
            require(p, cur, 20, "SOA numeric fields");
            rr.soa.serial = read_u32(p, cur); cur += 4;
            rr.soa.refresh = read_u32(p, cur); cur += 4;
            rr.soa.retry = read_u32(p, cur); cur += 4;
            rr.soa.expire = read_u32(p, cur); cur += 4;
            rr.soa.minimum = read_u32(p, cur); cur += 4;
            if (cur != rdata_end) throw DnsError("SOA record data length mismatch");
            rr.data = rr.soa.mname + " " + rr.soa.rname + " " + std::to_string(rr.soa.serial) +
                      " " + std::to_string(rr.soa.refresh) + " " + std::to_string(rr.soa.retry) +
                      " " + std::to_string(rr.soa.expire) + " " + std::to_string(rr.soa.minimum);
            off = rdata_end;
            break;
        }
        case static_cast<std::uint16_t>(RecordType::TXT): {
            std::size_t cur = off;
            std::string full_txt;
            while (cur < rdata_end) {
                const std::uint8_t slen = p[cur++];
                require(p, cur, slen, "TXT segment");
                if (!full_txt.empty()) full_txt += " ";
                full_txt += "\"";
                for (std::size_t i = 0; i < slen; ++i) append_label_byte(full_txt, p[cur + i]);
                full_txt += "\"";
                cur += slen;
            }
            rr.data = full_txt;
            off = rdata_end;
            break;
        }
        case static_cast<std::uint16_t>(RecordType::OPT):
            // RFC 6891: rr.cls is requestor UDP payload size
            rr.data = "EDNS payload=" + std::to_string(rr.cls);
            off = rdata_end;
            break;
        default:
            rr.data = "<" + std::to_string(rdlength) + " bytes of unsupported type " + std::to_string(rr.type) + ">";
            off = rdata_end;
            break;
    }
    return rr;
}

}  // namespace

// ------------------------------------------------------- names and types ---

std::string record_type_name(std::uint16_t type) {
    switch (type) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 41: return "OPT";
        default: return "TYPE" + std::to_string(type);
    }
}

bool parse_record_type(const std::string& text, RecordType& out) {
    std::string up = text;
    std::transform(up.begin(), up.end(), up.begin(), [](unsigned char c) { return std::toupper(c); });
    if (up == "A") out = RecordType::A;
    else if (up == "AAAA") out = RecordType::AAAA;
    else if (up == "CNAME") out = RecordType::CNAME;
    else if (up == "SOA") out = RecordType::SOA;
    else if (up == "PTR") out = RecordType::PTR;
    else if (up == "MX") out = RecordType::MX;
    else if (up == "TXT") out = RecordType::TXT;
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
    if (name.empty() || name == ".") {
        out.push_back(0);
        return out;
    }
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

Bytes encode_query(const std::string& domain, RecordType type, std::uint16_t id,
                   bool recursion_desired, bool use_edns, std::uint16_t edns_buf_size) {
    const std::string name = normalize_domain(domain);
    Bytes packet;
    put_u16(packet, id);

    // Flags: opcode=0 (QUERY), RD bit set conditionally
    const std::uint16_t flags = recursion_desired ? 0x0100 : 0x0000;
    put_u16(packet, flags);
    put_u16(packet, 1);                                 // QDCOUNT
    put_u16(packet, 0);                                 // ANCOUNT
    put_u16(packet, 0);                                 // NSCOUNT
    put_u16(packet, use_edns ? 1 : 0);                 // ARCOUNT (1 if EDNS OPT RR attached)

    const Bytes qname = encode_name(name);
    packet.insert(packet.end(), qname.begin(), qname.end());
    put_u16(packet, static_cast<std::uint16_t>(type));
    put_u16(packet, kClassIN);

    if (use_edns) {
        // RFC 6891 OPT pseudo-RR
        packet.push_back(0);                             // Root domain name
        put_u16(packet, static_cast<std::uint16_t>(RecordType::OPT));  // Type 41
        put_u16(packet, edns_buf_size);                  // UDP payload size in CLASS
        put_u32(packet, 0);                             // Extended RCODE, Version 0, Flags (DO=0)
        put_u16(packet, 0);                             // RDLENGTH = 0
    }

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
    std::size_t resume = 0;  // where caller continues after first jump
    bool jumped = false;
    std::size_t wire_length = 1;  // terminating zero byte
    std::string name;
    std::size_t jumps = 0;

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
            if (++jumps > kMaxJumps) throw DnsError("too many compression pointer jumps");
            if (target >= p.size()) throw DnsError("compression pointer out of packet bounds");
            // RFC 1035: compression pointers must point backwards to already-encoded names
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

Response parse_packet(const Bytes& p) {
    Response r;
    r.header = parse_header(p);
    r.truncated = r.header.truncated();
    r.rcode = r.header.rcode();

    std::size_t off = kHeaderSize;
    if (r.header.qdcount >= 1) {
        r.question = parse_question(p, off);
    }

    if (r.truncated) {
        return r;
    }

    r.answers.reserve(std::min<std::size_t>(r.header.ancount, 64));
    for (std::uint16_t i = 0; i < r.header.ancount; ++i) {
        r.answers.push_back(parse_record(p, off));
    }

    r.authorities.reserve(std::min<std::size_t>(r.header.nscount, 64));
    for (std::uint16_t i = 0; i < r.header.nscount; ++i) {
        r.authorities.push_back(parse_record(p, off));
    }

    r.additionals.reserve(std::min<std::size_t>(r.header.arcount, 64));
    for (std::uint16_t i = 0; i < r.header.arcount; ++i) {
        r.additionals.push_back(parse_record(p, off));
    }

    return r;
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
    if (r.truncated) return r;

    r.answers.reserve(std::min<std::size_t>(r.header.ancount, 64));
    for (std::uint16_t i = 0; i < r.header.ancount; ++i) {
        r.answers.push_back(parse_record(p, off));
    }

    r.authorities.reserve(std::min<std::size_t>(r.header.nscount, 64));
    for (std::uint16_t i = 0; i < r.header.nscount; ++i) {
        r.authorities.push_back(parse_record(p, off));
    }

    r.additionals.reserve(std::min<std::size_t>(r.header.arcount, 64));
    for (std::uint16_t i = 0; i < r.header.arcount; ++i) {
        r.additionals.push_back(parse_record(p, off));
    }

    return r;
}

}  // namespace resolvex
