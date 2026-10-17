// main.cpp - command-line interface, output formatting, and offline tests.
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <thread>

#include "dns.hpp"

using namespace resolvex;

namespace {

// ================================================================== CLI ====

enum class Command { Query, Stats, Test, Help };

struct CliArgs {
    Command command = Command::Query;
    std::string domain;
    RecordType type = RecordType::A;
    QueryOptions options;
    int repeat = 1;
    int delay_ms = 0;
};

void print_usage(std::ostream& out) {
    out << "ResolveX - a small DNS resolver (UDP, IPv4 upstream, no TCP fallback)\n\n"
           "Usage:\n"
           "  resolvex <domain> [options]\n"
           "  resolvex stats\n"
           "  resolvex test\n"
           "  resolvex --help\n\n"
           "Options:\n"
           "  -t, --type <A|AAAA|MX|NS|CNAME>  record type to query (default: A)\n"
           "  -s, --server <ipv4>              upstream DNS server (default: 1.1.1.1)\n"
           "      --port <1-65535>             upstream port (default: 53)\n"
           "      --timeout <ms>               receive timeout, 1-60000 (default: 3000)\n"
           "      --repeat <n>                 run the query n times in one process, 1-1000\n"
           "                                   (shows cache behaviour and session stats)\n"
           "      --delay <ms>                 pause between repeats, 0-60000 (default: 0)\n"
           "  -h, --help                       show this help\n\n"
           "Commands:\n"
           "  stats   print statistics for THIS process (in-memory; see README)\n"
           "  test    run the offline unit tests (no network needed)\n\n"
           "Examples:\n"
           "  resolvex google.com\n"
           "  resolvex google.com --type MX --server 8.8.8.8\n"
           "  resolvex example.com --repeat 3\n";
}

// Docs and word processors often turn "--type" into an en/em dash; accept that.
std::string normalize_dashes(const std::string& arg) {
    static const std::string en = "\xE2\x80\x93", em = "\xE2\x80\x94";
    if (arg.compare(0, en.size(), en) == 0) return "--" + arg.substr(en.size());
    if (arg.compare(0, em.size(), em) == 0) return "--" + arg.substr(em.size());
    return arg;
}

int parse_int_option(const std::string& name, const std::string& text, int lo, int hi) {
    std::size_t used = 0;
    int value = 0;
    try {
        value = std::stoi(text, &used);
    } catch (const std::exception&) {
        used = 0;
    }
    if (used == 0 || used != text.size()) throw std::invalid_argument(name + " expects a number, got '" + text + "'");
    if (value < lo || value > hi) {
        throw std::invalid_argument(name + " must be between " + std::to_string(lo) + " and " + std::to_string(hi));
    }
    return value;
}

CliArgs parse_args(int argc, char** argv) {
    CliArgs args;
    bool have_positional = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = normalize_dashes(argv[i]);
        std::string inline_value;
        bool has_inline = false;
        if (arg.rfind("--", 0) == 0) {
            const std::size_t eq = arg.find('=');
            if (eq != std::string::npos) {
                inline_value = arg.substr(eq + 1);
                arg = arg.substr(0, eq);
                has_inline = true;
            }
        }

        auto value_for = [&](const std::string& opt) -> std::string {
            if (has_inline) return inline_value;
            if (i + 1 >= argc) throw std::invalid_argument("option " + opt + " requires a value");
            return argv[++i];
        };

        if (arg == "-h" || arg == "--help") {
            args.command = Command::Help;
            return args;
        } else if (arg == "--test") {
            args.command = Command::Test;
            have_positional = true;
        } else if (arg == "-t" || arg == "--type") {
            const std::string v = value_for(arg);
            if (!parse_record_type(v, args.type)) {
                throw std::invalid_argument("unsupported record type '" + v + "' (supported: A, AAAA, CNAME, MX, NS)");
            }
        } else if (arg == "-s" || arg == "--server") {
            args.options.server = value_for(arg);
            if (!is_valid_ipv4(args.options.server)) {
                throw std::invalid_argument("'" + args.options.server + "' is not a valid IPv4 address (hostnames are not accepted for --server)");
            }
        } else if (arg == "--port") {
            args.options.port = static_cast<std::uint16_t>(parse_int_option("--port", value_for(arg), 1, 65535));
        } else if (arg == "--timeout") {
            args.options.timeout_ms = parse_int_option("--timeout", value_for(arg), 1, 60000);
        } else if (arg == "--delay") {
            args.delay_ms = parse_int_option("--delay", value_for(arg), 0, 60000);
        } else if (arg == "--repeat") {
            args.repeat = parse_int_option("--repeat", value_for(arg), 1, 1000);
        } else if (arg.size() > 1 && arg[0] == '-') {
            throw std::invalid_argument("unknown option '" + arg + "' (try --help)");
        } else {
            if (have_positional) throw std::invalid_argument("unexpected extra argument '" + arg + "'");
            have_positional = true;
            if (arg == "stats") args.command = Command::Stats;
            else if (arg == "test") args.command = Command::Test;
            else args.domain = arg;
        }
    }

    if (args.command == Command::Query && args.domain.empty()) {
        throw std::invalid_argument("missing domain name (try --help)");
    }
    return args;
}

// ============================================================== output ====

std::string display_name(const std::string& name) { return name.empty() ? "." : name + "."; }

void print_result(const QueryResult& r) {
    const char* status = r.status == QueryStatus::Ok ? "OK" : (r.status == QueryStatus::NoData ? "OK (no data)" : "ERROR");

    std::cout << "\nDomain:   " << r.domain << "\n"
              << "Type:     " << record_type_name(static_cast<std::uint16_t>(r.type)) << "\n"
              << "Server:   " << r.server << "\n"
              << "Status:   " << status << " - " << r.message << "\n"
              << "Cache:    " << (r.cache_hit ? "CACHE HIT" : "CACHE MISS") << "\n"
              << "Latency:  " << std::fixed << std::setprecision(2) << r.latency_ms << " ms\n";

    if (r.answers.empty()) return;
    std::cout << "Records (" << r.answers.size() << "):" << (r.cache_hit ? "  [TTL = remaining cache lifetime]" : "") << "\n";
    for (const ResourceRecord& rr : r.answers) {
        std::string data = rr.data;
        if (rr.type == static_cast<std::uint16_t>(RecordType::MX)) data = "pref " + std::to_string(rr.mx_preference) + "  " + rr.data;
        std::cout << "  " << std::left << std::setw(28) << display_name(rr.name) << std::setw(7)
                  << record_type_name(rr.type) << "TTL " << std::setw(7) << rr.ttl << data << "\n";
    }
}

void print_stats(const Stats& s) {
    std::cout << "\nResolveX statistics (this process only)\n"
              << "  Total queries:        " << s.total << "\n"
              << "  Successful:           " << s.successful << "\n"
              << "  Failed:               " << s.failed << "\n"
              << "  Cache hits:           " << s.cache_hits << "\n"
              << "  Cache misses:         " << s.cache_misses << "\n"
              << "  Average latency:      " << std::fixed << std::setprecision(2) << s.average_latency_ms() << " ms\n";
}

// ============================================================== tests =====

int g_passed = 0;
int g_failed = 0;

void check(bool ok, const char* expr, int line) {
    if (ok) {
        ++g_passed;
        std::cout << "  [PASS] " << expr << "\n";
    } else {
        ++g_failed;
        std::cout << "  [FAIL] " << expr << "  (main.cpp:" << line << ")\n";
    }
}
#define CHECK(expr) check(static_cast<bool>(expr), #expr, __LINE__)

template <typename F>
bool throws_dns_error(F fn) {
    try {
        fn();
    } catch (const DnsError&) {
        return true;
    } catch (...) {
    }
    return false;
}

// Builds synthetic packets byte by byte.
class ByteWriter {
public:
    Bytes data;
    ByteWriter& u8(unsigned v) { data.push_back(static_cast<std::uint8_t>(v)); return *this; }
    ByteWriter& u16(unsigned v) { return u8(v >> 8).u8(v & 0xFF); }
    ByteWriter& u32(std::uint32_t v) { return u16(v >> 16).u16(v & 0xFFFF); }
    ByteWriter& name(const std::string& n) { return raw(encode_name(n)); }
    ByteWriter& raw(const Bytes& b) { data.insert(data.end(), b.begin(), b.end()); return *this; }
};

constexpr std::uint16_t kTestId = 0x1234;

// Header + question for example.com. The question name starts at offset 12, so
// 0xC00C is a compression pointer to "example.com".
ByteWriter response_head(std::uint16_t flags, std::uint16_t qtype, unsigned an, const std::string& qname = "example.com") {
    ByteWriter w;
    w.u16(kTestId).u16(flags).u16(1).u16(an).u16(0).u16(0).name(qname).u16(qtype).u16(kClassIN);
    return w;
}

void add_record(ByteWriter& w, std::uint16_t type, std::uint32_t ttl, const Bytes& rdata) {
    w.u16(0xC00C).u16(type).u16(kClassIN).u32(ttl).u16(static_cast<unsigned>(rdata.size())).raw(rdata);
}

Response parse_as(const Bytes& packet, RecordType type, std::uint16_t id = kTestId) {
    return parse_response(packet, id, Question{"example.com", static_cast<std::uint16_t>(type), kClassIN});
}

constexpr std::uint16_t kOkFlags = 0x8180;  // response, RD, RA, NOERROR

void test_query_encoding() {
    std::cout << "Query encoding\n";
    const Bytes expected = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
                            0,    0x00, 0x01, 0x00, 0x01};
    CHECK(encode_query("example.com", RecordType::A, 0x1234) == expected);
    CHECK(encode_query("Example.COM.", RecordType::A, 0x1234) == expected);  // normalized
    const Bytes mx = encode_query("example.com", RecordType::MX, 1);
    CHECK(mx[mx.size() - 4] == 0x00 && mx[mx.size() - 3] == 15);
    CHECK(normalize_domain("Example.COM.") == "example.com");
    bool rejected = true;
    for (const char* bad : {"", "a..b", "bad name.com", "-a.com", ".", "a b"}) {
        try { normalize_domain(bad); rejected = false; } catch (const std::invalid_argument&) {}
    }
    CHECK(rejected);  // empty, empty label, space, leading hyphen, root
    bool long_label_rejected = false;
    try { normalize_domain(std::string(64, 'a') + ".com"); } catch (const std::invalid_argument&) { long_label_rejected = true; }
    CHECK(long_label_rejected);
}

void test_header_parsing() {
    std::cout << "Header parsing\n";
    const Bytes pkt = ByteWriter().u16(0xABCD).u16(0x8183).u16(1).u16(2).u16(3).u16(4).data;
    const Header h = parse_header(pkt);
    CHECK(h.id == 0xABCD);
    CHECK(h.is_response());
    CHECK(h.rcode() == 3);
    CHECK(!h.truncated());
    CHECK(h.opcode() == 0);
    CHECK(h.qdcount == 1 && h.ancount == 2 && h.nscount == 3 && h.arcount == 4);
    CHECK(parse_header(ByteWriter().u16(1).u16(0x8380).u16(0).u16(0).u16(0).u16(0).data).truncated());
    CHECK(throws_dns_error([] { parse_header(Bytes(11, 0)); }));
}

void test_name_decoding() {
    std::cout << "Compressed names\n";
    ByteWriter w;
    w.name("www.example.com");        // offset 0, 17 bytes
    const std::size_t second = w.data.size();
    w.u8(4).raw({'m', 'a', 'i', 'l'}).u16(0xC000);  // "mail" + pointer to offset 0
    const std::size_t third = w.data.size();
    w.u16(0xC000 | static_cast<unsigned>(second));  // pointer to a name that itself ends in a pointer
    std::size_t off = 0;
    CHECK(decode_name(w.data, off) == "www.example.com" && off == 17);
    off = second;
    CHECK(decode_name(w.data, off) == "mail.www.example.com" && off == second + 7);
    off = third;
    CHECK(decode_name(w.data, off) == "mail.www.example.com" && off == third + 2);
    off = 0;
    CHECK(decode_name(ByteWriter().u8(0).data, off).empty() && off == 1);  // root

    const Bytes self = {0xC0, 0x00};
    off = 0;
    CHECK(throws_dns_error([&] { decode_name(self, off); }));  // pointer to itself
    const Bytes fwd = {0xC0, 0x05, 0, 0, 0, 1, 'a', 0};
    off = 0;
    CHECK(throws_dns_error([&] { decode_name(fwd, off); }));  // forward pointer
    const Bytes overrun = {5, 'a', 'b'};
    off = 0;
    CHECK(throws_dns_error([&] { decode_name(overrun, off); }));  // label runs past end
    const Bytes reserved = {0x40, 'a', 0};
    off = 0;
    CHECK(throws_dns_error([&] { decode_name(reserved, off); }));  // reserved label type
    const Bytes no_end = {1, 'a'};
    off = 0;
    CHECK(throws_dns_error([&] { decode_name(no_end, off); }));  // missing terminator
}

void test_record_parsing() {
    std::cout << "Record parsing\n";
    {
        ByteWriter w = response_head(kOkFlags, 1, 1);
        add_record(w, 1, 300, {93, 184, 216, 34});
        const Response r = parse_as(w.data, RecordType::A);
        CHECK(r.rcode == 0 && !r.truncated && r.answers.size() == 1);
        CHECK(r.answers[0].name == "example.com" && r.answers[0].data == "93.184.216.34" && r.answers[0].ttl == 300);
    }
    {
        Bytes v6 = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
        ByteWriter w = response_head(kOkFlags, 28, 1);
        add_record(w, 28, 60, v6);
        const Response r = parse_as(w.data, RecordType::AAAA);
        CHECK(r.answers.size() == 1 && r.answers[0].data == "2001:db8::1" && r.answers[0].ttl == 60);
    }
    {
        ByteWriter w = response_head(kOkFlags, 15, 2);
        add_record(w, 15, 3600, ByteWriter().u16(10).u8(4).raw({'m', 'a', 'i', 'l'}).u16(0xC00C).data);
        add_record(w, 15, 3600, ByteWriter().u16(20).name("backup.example.net").data);
        const Response r = parse_as(w.data, RecordType::MX);
        CHECK(r.answers.size() == 2);
        CHECK(r.answers[0].mx_preference == 10 && r.answers[0].data == "mail.example.com");
        CHECK(r.answers[1].mx_preference == 20 && r.answers[1].data == "backup.example.net");
    }
    {
        ByteWriter w = response_head(kOkFlags, 5, 2);
        add_record(w, 5, 120, ByteWriter().u8(3).raw({'w', 'w', 'w'}).u16(0xC00C).data);
        add_record(w, 1, 30, {1, 2, 3, 4});  // CNAME chain followed by an A record
        const Response r = parse_as(w.data, RecordType::CNAME);
        CHECK(r.answers.size() == 2 && r.answers[0].data == "www.example.com" && r.answers[1].data == "1.2.3.4");
    }
    {
        ByteWriter w = response_head(kOkFlags, 2, 1);
        add_record(w, 2, 86400, ByteWriter().u8(3).raw({'n', 's', '1'}).u16(0xC00C).data);
        CHECK(parse_as(w.data, RecordType::NS).answers[0].data == "ns1.example.com");
    }
    {
        ByteWriter w = response_head(kOkFlags, 1, 1);
        add_record(w, 1, 0x80000001u, {1, 1, 1, 1});
        CHECK(parse_as(w.data, RecordType::A).answers[0].ttl == 0);  // RFC 2181 high-bit TTL
    }
}

void test_rejection_and_errors() {
    std::cout << "Malformed packets and error handling\n";
    CHECK(throws_dns_error([] { parse_as(Bytes{}, RecordType::A); }));
    CHECK(throws_dns_error([] { parse_as(Bytes(5, 0), RecordType::A); }));

    {
        ByteWriter w = response_head(kOkFlags, 1, 1);
        add_record(w, 1, 300, {1, 2, 3, 4});
        Bytes pkt = w.data;
        CHECK(throws_dns_error([&] { parse_as(Bytes(pkt.begin(), pkt.end() - 3), RecordType::A); }));  // cut mid-record
        CHECK(throws_dns_error([&] { parse_as(Bytes(pkt.begin(), pkt.begin() + 20), RecordType::A); }));  // cut mid-question
    }
    {
        ByteWriter w = response_head(kOkFlags, 1, 1);
        w.u16(0xC00C).u16(1).u16(1).u32(5).u16(200).raw({1, 2, 3, 4});  // rdlength 200, only 4 bytes
        CHECK(throws_dns_error([&] { parse_as(w.data, RecordType::A); }));
    }
    {
        ByteWriter w = response_head(kOkFlags, 1, 1);
        add_record(w, 1, 5, {1, 2, 3});  // A record with 3 bytes
        CHECK(throws_dns_error([&] { parse_as(w.data, RecordType::A); }));
    }
    {
        ByteWriter w = response_head(kOkFlags, 1, 5);  // claims 5 answers, has 1
        add_record(w, 1, 5, {1, 2, 3, 4});
        CHECK(throws_dns_error([&] { parse_as(w.data, RecordType::A); }));
    }
    {
        ByteWriter w = response_head(kOkFlags, 1, 1);
        w.u16(0xC000 | static_cast<unsigned>(w.data.size())).u16(1).u16(1).u32(5).u16(4).raw({1, 2, 3, 4});  // self pointer
        CHECK(throws_dns_error([&] { parse_as(w.data, RecordType::A); }));
    }
    {
        ByteWriter w = response_head(0x0100, 1, 0);  // QR bit clear: this is a query
        CHECK(throws_dns_error([&] { parse_as(w.data, RecordType::A); }));
    }
    {
        ByteWriter w = response_head(kOkFlags, 1, 0, "other.org");  // echoed question differs
        CHECK(throws_dns_error([&] { parse_as(w.data, RecordType::A); }));
    }
    {
        ByteWriter w = response_head(kOkFlags, 1, 1);
        add_record(w, 1, 300, {1, 2, 3, 4});
        CHECK(throws_dns_error([&] { parse_as(w.data, RecordType::A, 0x4321); }));  // transaction-ID mismatch
        CHECK(!throws_dns_error([&] { parse_as(w.data, RecordType::A, kTestId); }));
        bool message_ok = false;
        try { parse_as(w.data, RecordType::A, 0x4321); } catch (const DnsError& e) {
            message_ok = std::string(e.what()).find("transaction ID mismatch") != std::string::npos;
        }
        CHECK(message_ok);
    }
    {
        const Response t = parse_as(response_head(0x8380, 1, 0).data, RecordType::A);  // TC flag
        CHECK(t.truncated && t.answers.empty());
    }
    {
        const Response nx = parse_as(response_head(0x8183, 1, 0).data, RecordType::A);
        CHECK(nx.rcode == 3 && rcode_message(nx.rcode).find("NXDOMAIN") == 0);
    }
    CHECK(rcode_message(2).find("SERVFAIL") == 0);
    CHECK(rcode_message(5).find("REFUSED") == 0);
    CHECK(rcode_message(9).find("unexpected") != std::string::npos);
}

std::vector<ResourceRecord> sample_answers(std::uint32_t ttl_a, std::uint32_t ttl_b) {
    ResourceRecord a;
    a.name = "example.com"; a.type = 1; a.cls = 1; a.ttl = ttl_a; a.data = "1.2.3.4";
    ResourceRecord b = a;
    b.ttl = ttl_b; b.data = "5.6.7.8";
    return {a, b};
}

void test_cache() {
    std::cout << "Cache\n";
    auto now = std::make_shared<Clock::time_point>(Clock::now());
    DnsCache cache(2, [now] { return *now; });
    const CacheKey k1{"example.com", 1, 1, "1.1.1.1:53"};
    std::vector<ResourceRecord> out;

    CHECK(!cache.lookup(k1, out));                                  // miss on empty cache
    CHECK(cache.store(k1, sample_answers(300, 60)));
    CHECK(cache.lookup(k1, out) && out.size() == 2);                // hit
    CHECK(out[0].ttl == 300 && out[1].ttl == 60);

    *now += std::chrono::seconds(10);
    CHECK(cache.lookup(k1, out) && out[0].ttl == 290 && out[1].ttl == 50);  // remaining TTL, not original

    CHECK(!cache.lookup(CacheKey{"example.com", 28, 1, "1.1.1.1:53"}, out));  // other type
    CHECK(!cache.lookup(CacheKey{"example.com", 1, 1, "8.8.8.8:53"}, out));   // other upstream
    CHECK(!cache.lookup(CacheKey{"example.org", 1, 1, "1.1.1.1:53"}, out));   // other name

    *now += std::chrono::seconds(49);
    CHECK(cache.lookup(k1, out) && out[1].ttl == 1);                // 1s left
    *now += std::chrono::seconds(1);
    CHECK(!cache.lookup(k1, out));                                  // expired at min TTL (60s)
    CHECK(cache.size() == 0);                                       // expired entry removed

    CHECK(!cache.store(k1, sample_answers(0, 300)));                // TTL 0 not cached
    CHECK(!cache.store(k1, {}));                                    // nothing to cache
    CHECK(cache.size() == 0);

    // Bounded size: capacity 2, evict soonest-to-expire first.
    const CacheKey ka{"a.com", 1, 1, "s"}, kb{"b.com", 1, 1, "s"}, kc{"c.com", 1, 1, "s"};
    CHECK(cache.store(ka, sample_answers(100, 100)));
    CHECK(cache.store(kb, sample_answers(500, 500)));
    CHECK(cache.store(kc, sample_answers(300, 300)));
    CHECK(cache.size() == 2);
    CHECK(!cache.lookup(ka, out) && cache.lookup(kb, out) && cache.lookup(kc, out));

    // A full cache with an expired entry drops that one instead of a live one.
    *now += std::chrono::seconds(301);
    const CacheKey kd{"d.com", 1, 1, "s"};
    CHECK(cache.store(kd, sample_answers(50, 50)));
    CHECK(cache.lookup(kb, out) && cache.lookup(kd, out) && cache.size() == 2);
}

void test_resolver_cache_path() {
    std::cout << "Resolver cache hit path (no network)\n";
    DnsCache cache(8);
    Stats stats;
    Resolver resolver(cache, stats);
    QueryOptions opts;
    cache.store(CacheKey{"example.com", 1, kClassIN, server_label(opts)}, sample_answers(300, 300));

    const QueryResult r = resolver.resolve("Example.COM", RecordType::A, opts);
    CHECK(r.cache_hit && r.status == QueryStatus::Ok && r.answers.size() == 2);
    CHECK(stats.total == 1 && stats.cache_hits == 1 && stats.cache_misses == 0 && stats.successful == 1);

    bool bad_server = false;
    try { QueryOptions bad; bad.server = "not-an-ip"; resolver.resolve("example.com", RecordType::A, bad); }
    catch (const std::invalid_argument&) { bad_server = true; }
    CHECK(bad_server);
    CHECK(stats.total == 1);  // invalid input is not counted as a query
}

int run_tests() {
    test_query_encoding();
    test_header_parsing();
    test_name_decoding();
    test_record_parsing();
    test_rejection_and_errors();
    test_cache();
    test_resolver_cache_path();
    std::cout << "\n" << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed == 0 ? 0 : 1;
}

// ================================================================ main ====

int run_query(const CliArgs& args) {
    DnsCache cache;
    Stats stats;
    Resolver resolver(cache, stats);

    int exit_code = 0;
    for (int i = 0; i < args.repeat; ++i) {
        if (i > 0 && args.delay_ms > 0) std::this_thread::sleep_for(std::chrono::milliseconds(args.delay_ms));
        const QueryResult result = resolver.resolve(args.domain, args.type, args.options);
        print_result(result);
        if (result.status == QueryStatus::Error) exit_code = 1;
    }
    if (args.repeat > 1) print_stats(stats);
    return exit_code;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            print_usage(std::cerr);
            return 2;
        }
        const CliArgs args = parse_args(argc, argv);
        switch (args.command) {
            case Command::Help:
                print_usage(std::cout);
                return 0;
            case Command::Test:
                return run_tests();
            case Command::Stats: {
                const Stats fresh;  // each process starts with empty, in-memory statistics
                print_stats(fresh);
                std::cout << "\nNote: statistics live in memory and are not saved between runs, so a fresh\n"
                             "process always reports zeros. Use `resolvex <domain> --repeat N` to see them accumulate.\n";
                return 0;
            }
            case Command::Query:
                return run_query(args);
        }
    } catch (const std::invalid_argument& e) {
        std::cerr << "resolvex: " << e.what() << "\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "resolvex: unexpected error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
