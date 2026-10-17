// main.cpp - CLI, packet inspector, benchmark harness, and comprehensive offline test suite.
#include <arpa/inet.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <sstream>
#include <thread>
#include <unistd.h>

#include "cache.hpp"
#include "dns.hpp"
#include "resolver.hpp"
#include "root_hints.hpp"
#include "trace.hpp"
#include "transport.hpp"

using namespace resolvex;

namespace {

// ================================================================== CLI ====

enum class Command { Resolve, Cache, CacheClear, Inspect, Benchmark, Stats, Test, Help };

struct CliArgs {
    Command command = Command::Resolve;
    std::string domain;
    RecordType type = RecordType::A;
    QueryOptions options;
    ResolverConfig resolver_config;
    std::string root_hints_path;
    int repeat = 1;
    int delay_ms = 0;
    int benchmark_runs = 10;
    bool trace = false;
    bool quiet = false;
    bool hex_dump = false;
    bool json_output = false;
};

void print_usage(std::ostream& out) {
    out << "ResolveX 2.0 — Iterative DNS Resolution Engine\n\n"
           "Usage:\n"
           "  resolvex resolve <domain> [type] [options]    perform iterative DNS resolution\n"
           "  resolvex <domain> [type] [options]            shortcut for resolve\n"
           "  resolvex cache                                display active cached DNS records\n"
           "  resolvex cache clear                          purge the persistent DNS cache\n"
           "  resolvex inspect <domain> [type] [options]    inspect raw decoded DNS packet sections\n"
           "  resolvex benchmark <domain> [type] [options]  run cold/warm latency & hit-rate benchmark\n"
           "  resolvex stats                                print in-memory session statistics\n"
           "  resolvex test                                 run offline deterministic test suite\n"
           "  resolvex --help                               show this help message\n\n"
           "Options:\n"
           "  -t, --type <A|AAAA|MX|NS|CNAME|SOA|TXT>       DNS record type (default: A)\n"
           "      --trace, -v                               display step-by-step iterative referral trace\n"
           "      --no-cache                                bypass in-memory and persistent cache\n"
           "  -q, --quiet                                   quiet mode (scripting output only)\n"
           "  -s, --server <ip>                             query specific server directly instead of iterative walk\n"
           "      --port <1-65535>                          port (default: 53)\n"
           "      --timeout <ms>                            query timeout in ms (default: 3000)\n"
           "      --root-hints <path>                       path to custom root.hints file\n"
           "      --repeat <n>                              repeat query n times in one process (1-1000)\n"
           "      --delay <ms>                              delay between repeats in ms (default: 0)\n"
           "      --runs <n>                                number of runs for benchmark (default: 10)\n"
           "      --hex                                     print raw packet hex dump in inspector\n"
           "      --json                                    output results in JSON format\n"
           "  -h, --help                                    display this help\n\n"
           "Examples:\n"
           "  resolvex resolve example.com A --trace\n"
           "  resolvex wikipedia.org AAAA --trace\n"
           "  resolvex google.com MX\n"
           "  resolvex inspect example.com A --hex\n"
           "  resolvex benchmark example.com A --runs 20 --json\n"
           "  resolvex cache\n";
}

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
    std::vector<std::string> positionals;

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
        } else if (arg == "--trace" || arg == "-v") {
            args.trace = true;
        } else if (arg == "--no-cache") {
            args.resolver_config.no_cache = true;
        } else if (arg == "-q" || arg == "--quiet") {
            args.quiet = true;
        } else if (arg == "--hex") {
            args.hex_dump = true;
        } else if (arg == "--json") {
            args.json_output = true;
        } else if (arg == "-t" || arg == "--type") {
            const std::string v = value_for(arg);
            if (!parse_record_type(v, args.type)) {
                throw std::invalid_argument("unsupported record type '" + v + "'");
            }
        } else if (arg == "-s" || arg == "--server") {
            args.options.server = value_for(arg);
            if (!is_valid_ip(args.options.server)) {
                throw std::invalid_argument("'" + args.options.server + "' is not a valid IP address");
            }
        } else if (arg == "--port") {
            args.options.port = static_cast<std::uint16_t>(parse_int_option("--port", value_for(arg), 1, 65535));
        } else if (arg == "--timeout") {
            args.options.timeout_ms = parse_int_option("--timeout", value_for(arg), 1, 60000);
            args.resolver_config.timeout_ms = args.options.timeout_ms;
        } else if (arg == "--root-hints") {
            args.root_hints_path = value_for(arg);
        } else if (arg == "--delay") {
            args.delay_ms = parse_int_option("--delay", value_for(arg), 0, 60000);
        } else if (arg == "--repeat") {
            args.repeat = parse_int_option("--repeat", value_for(arg), 1, 1000);
        } else if (arg == "--runs") {
            args.benchmark_runs = parse_int_option("--runs", value_for(arg), 1, 1000);
        } else if (arg.size() > 1 && arg[0] == '-') {
            throw std::invalid_argument("unknown option '" + arg + "' (try --help)");
        } else {
            positionals.push_back(arg);
        }
    }

    if (positionals.empty()) {
        if (args.command == Command::Test || args.command == Command::Help) return args;
        throw std::invalid_argument("missing domain name or command (try --help)");
    }

    const std::string& cmd_or_domain = positionals[0];
    if (cmd_or_domain == "stats") {
        args.command = Command::Stats;
    } else if (cmd_or_domain == "test") {
        args.command = Command::Test;
    } else if (cmd_or_domain == "cache") {
        if (positionals.size() >= 2 && positionals[1] == "clear") {
            args.command = Command::CacheClear;
        } else {
            args.command = Command::Cache;
        }
    } else if (cmd_or_domain == "inspect") {
        args.command = Command::Inspect;
        if (positionals.size() < 2) throw std::invalid_argument("inspect requires a domain name");
        args.domain = positionals[1];
        if (positionals.size() >= 3) parse_record_type(positionals[2], args.type);
    } else if (cmd_or_domain == "benchmark") {
        args.command = Command::Benchmark;
        if (positionals.size() < 2) throw std::invalid_argument("benchmark requires a domain name");
        args.domain = positionals[1];
        if (positionals.size() >= 3) parse_record_type(positionals[2], args.type);
    } else if (cmd_or_domain == "resolve") {
        args.command = Command::Resolve;
        if (positionals.size() < 2) throw std::invalid_argument("resolve requires a domain name");
        args.domain = positionals[1];
        if (positionals.size() >= 3) parse_record_type(positionals[2], args.type);
    } else {
        // Direct domain query shortcut: `resolvex example.com [type]`
        args.command = Command::Resolve;
        args.domain = cmd_or_domain;
        if (positionals.size() >= 2) parse_record_type(positionals[1], args.type);
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
    std::cout << "\nResolveX statistics (this session)\n"
              << "  Total queries:        " << s.total << "\n"
              << "  Successful:           " << s.successful << "\n"
              << "  Failed:               " << s.failed << "\n"
              << "  Cache hits:           " << s.cache_hits << "\n"
              << "  Cache misses:         " << s.cache_misses << "\n"
              << "  Average latency:      " << std::fixed << std::setprecision(2) << s.average_latency_ms() << " ms\n";
}

void print_hex_dump(const Bytes& p) {
    std::cout << "\nRaw packet dump (" << p.size() << " bytes):\n";
    for (std::size_t i = 0; i < p.size(); i += 16) {
        std::printf("  %04zx  ", i);
        for (std::size_t j = 0; j < 16; ++j) {
            if (i + j < p.size()) std::printf("%02x ", p[i + j]);
            else std::printf("   ");
            if (j == 7) std::printf(" ");
        }
        std::printf(" |");
        for (std::size_t j = 0; j < 16 && i + j < p.size(); ++j) {
            unsigned char c = p[i + j];
            std::printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        std::printf("|\n");
    }
}

void inspect_packet_view(const Response& r, const Bytes& raw, bool hex) {
    std::cout << "========================== DNS PACKET INSPECTOR ==========================\n"
              << "HEADER:\n"
              << "  Transaction ID: 0x" << std::hex << std::setw(4) << std::setfill('0') << r.header.id << std::dec << "\n"
              << "  Flags:          0x" << std::hex << std::setw(4) << std::setfill('0') << r.header.flags << std::dec << " ("
              << (r.header.is_response() ? "QR/Response " : "QR/Query ")
              << (r.header.authoritative() ? "AA " : "")
              << (r.header.truncated() ? "TC " : "")
              << (r.header.recursion_desired() ? "RD " : "")
              << (r.header.recursion_available() ? "RA " : "")
              << ")\n" << std::setfill(' ')
              << "  Opcode:         " << static_cast<int>(r.header.opcode()) << " (QUERY)\n"
              << "  RCODE:          " << static_cast<int>(r.header.rcode()) << " (" << rcode_message(r.header.rcode()) << ")\n"
              << "  Question Count: " << r.header.qdcount << "\n"
              << "  Answer Count:   " << r.header.ancount << "\n"
              << "  Authority Count:" << r.header.nscount << "\n"
              << "  Additional Count:" << r.header.arcount << "\n\n";

    std::cout << "QUESTION SECTION:\n"
              << "  " << display_name(r.question.name) << " IN " << record_type_name(r.question.type) << "\n\n";

    auto print_section = [](const char* title, const std::vector<ResourceRecord>& records) {
        std::cout << title << " (" << records.size() << "):\n";
        if (records.empty()) {
            std::cout << "  <none>\n";
            return;
        }
        for (const auto& rr : records) {
            std::cout << "  " << std::left << std::setw(30) << display_name(rr.name)
                      << " " << std::setw(7) << record_type_name(rr.type)
                      << " TTL " << std::setw(7) << rr.ttl
                      << " " << rr.data << "\n";
        }
        std::cout << "\n";
    };

    print_section("ANSWER SECTION", r.answers);
    print_section("AUTHORITY SECTION", r.authorities);
    print_section("ADDITIONAL SECTION", r.additionals);

    if (hex && !raw.empty()) {
        print_hex_dump(raw);
    }
    std::cout << "==========================================================================\n";
}

// ============================================================== commands ==

int run_resolve(const CliArgs& args) {
    RootHints hints;
    if (!args.root_hints_path.empty()) {
        if (!hints.load_from_file(args.root_hints_path)) {
            std::cerr << "resolvex: error loading root hints file: " << args.root_hints_path << "\n";
            return 2;
        }
    } else {
        const std::string default_hints = RootHints::find_default_hints_file();
        if (!default_hints.empty()) hints.load_from_file(default_hints);
    }

    DnsCache cache;
    const std::string cache_file = DnsCache::default_cache_path();
    if (!args.resolver_config.no_cache) {
        cache.load_from_file(cache_file);
    }

    Stats stats;
    PosixTransport transport;
    IterativeResolver resolver(transport, hints, cache, stats, args.resolver_config);

    int exit_code = 0;
    TraceCollector trace;

    for (int i = 0; i < args.repeat; ++i) {
        if (i > 0 && args.delay_ms > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(args.delay_ms));
        }

        QueryResult result;
        if (!args.options.server.empty()) {
            result = resolver.query_direct(args.domain, args.type,
                                          Endpoint{args.options.server, args.options.port},
                                          /*recursion_desired=*/true,
                                          args.trace ? &trace : nullptr);
        } else {
            result = resolver.resolve(args.domain, args.type, args.trace ? &trace : nullptr);
        }

        if (args.trace) {
            if (args.json_output) trace.print_json(std::cout);
            else trace.print_trace(std::cout);
        }

        if (!args.quiet) {
            print_result(result);
        }

        if (result.status == QueryStatus::Error) {
            exit_code = 1;
        }
    }

    if (args.repeat > 1 && !args.quiet) {
        print_stats(stats);
    }

    if (!args.resolver_config.no_cache) {
        cache.save_to_file(cache_file);
    }

    return exit_code;
}

int run_cache_display() {
    DnsCache cache;
    const std::string cache_file = DnsCache::default_cache_path();
    cache.load_from_file(cache_file);

    const auto entries = cache.get_all_entries();
    std::cout << "ResolveX Cache (" << entries.size() << " active entries, storage: " << cache_file << "):\n";
    if (entries.empty()) {
        std::cout << "  Cache is currently empty.\n";
        return 0;
    }

    for (const auto& item : entries) {
        std::cout << "\nDomain: " << item.key.name << " (" << record_type_name(item.key.type)
                  << ")  Min remaining TTL: " << item.remaining_ttl << "s\n";
        for (const auto& rr : item.answers) {
            std::cout << "  " << std::left << std::setw(28) << display_name(rr.name)
                      << std::setw(7) << record_type_name(rr.type)
                      << "TTL " << std::setw(7) << rr.ttl << rr.data << "\n";
        }
    }
    return 0;
}

int run_cache_clear() {
    const std::string cache_file = DnsCache::default_cache_path();
    ::unlink(cache_file.c_str());
    std::cout << "ResolveX cache cleared (" << cache_file << " removed).\n";
    return 0;
}

int run_inspect(const CliArgs& args) {
    RootHints hints;
    const std::string default_hints = RootHints::find_default_hints_file();
    if (!default_hints.empty()) hints.load_from_file(default_hints);

    PosixTransport transport;
    Endpoint target_server{"198.41.0.4", 53};  // A.ROOT-SERVERS.NET default
    if (!args.options.server.empty()) {
        target_server = Endpoint{args.options.server, args.options.port};
    } else {
        const auto cand = hints.get_candidate_ips();
        if (!cand.empty()) target_server.ip = cand.front();
    }

    const std::uint16_t id = 0x1234;
    const Bytes query = encode_query(args.domain, args.type, id,
                                     /*recursion_desired=*/false, /*use_edns=*/true, 1232);

    try {
        const ExchangeResult ex = transport.exchange(target_server, query, args.options.timeout_ms, id, true);
        const Response resp = parse_packet(ex.reply);
        std::cout << "Response from " << target_server.to_string() << " in "
                  << std::fixed << std::setprecision(2) << ex.latency_ms << " ms ("
                  << (ex.via_tcp ? "TCP" : "UDP") << "):\n\n";
        inspect_packet_view(resp, ex.reply, args.hex_dump);
    } catch (const std::exception& e) {
        std::cerr << "resolvex inspect error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int run_benchmark(const CliArgs& args) {
    RootHints hints;
    const std::string default_hints = RootHints::find_default_hints_file();
    if (!default_hints.empty()) hints.load_from_file(default_hints);

    DnsCache cache;
    Stats stats;
    PosixTransport transport;
    IterativeResolver resolver(transport, hints, cache, stats, args.resolver_config);

    std::vector<double> latencies;
    latencies.reserve(args.benchmark_runs);
    std::size_t hits = 0;
    std::size_t failures = 0;

    if (!args.json_output) {
        std::cout << "Benchmarking iterative resolution for " << args.domain << " ("
                  << record_type_name(static_cast<std::uint16_t>(args.type)) << ") with "
                  << args.benchmark_runs << " runs...\n";
    }

    // Run 1: Cold cache
    cache.clear();
    const auto t0 = std::chrono::steady_clock::now();
    QueryResult cold_res = resolver.resolve(args.domain, args.type);
    const double cold_time = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    latencies.push_back(cold_time);
    if (cold_res.status == QueryStatus::Error) failures++;

    // Subsequent runs: Warm cache
    for (int i = 1; i < args.benchmark_runs; ++i) {
        const auto t_start = std::chrono::steady_clock::now();
        QueryResult r = resolver.resolve(args.domain, args.type);
        const double t_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t_start).count();
        latencies.push_back(t_ms);
        if (r.cache_hit) hits++;
        if (r.status == QueryStatus::Error) failures++;
    }

    std::vector<double> sorted = latencies;
    std::sort(sorted.begin(), sorted.end());

    auto percentile = [&](double p) -> double {
        if (sorted.empty()) return 0.0;
        const double rank = (p / 100.0) * (sorted.size() - 1);
        const std::size_t low = static_cast<std::size_t>(std::floor(rank));
        const std::size_t high = static_cast<std::size_t>(std::ceil(rank));
        const double weight = rank - low;
        return sorted[low] * (1.0 - weight) + sorted[high] * weight;
    };

    const double min_l = sorted.front();
    const double max_l = sorted.back();
    const double median_l = percentile(50.0);
    const double p95_l = percentile(95.0);
    const double p99_l = percentile(99.0);
    const double sum = std::accumulate(sorted.begin(), sorted.end(), 0.0);
    const double mean_l = sum / sorted.size();
    const double hit_rate = (sorted.size() > 1) ? (static_cast<double>(hits) / (sorted.size() - 1)) * 100.0 : 0.0;

    if (args.json_output) {
        std::cout << "{\n"
                  << "  \"domain\": \"" << args.domain << "\",\n"
                  << "  \"type\": \"" << record_type_name(static_cast<std::uint16_t>(args.type)) << "\",\n"
                  << "  \"runs\": " << args.benchmark_runs << ",\n"
                  << "  \"cold_resolution_ms\": " << std::fixed << std::setprecision(2) << cold_time << ",\n"
                  << "  \"min_latency_ms\": " << min_l << ",\n"
                  << "  \"max_latency_ms\": " << max_l << ",\n"
                  << "  \"mean_latency_ms\": " << mean_l << ",\n"
                  << "  \"median_latency_ms\": " << median_l << ",\n"
                  << "  \"p95_latency_ms\": " << p95_l << ",\n"
                  << "  \"p99_latency_ms\": " << p99_l << ",\n"
                  << "  \"cache_hit_rate_percent\": " << hit_rate << ",\n"
                  << "  \"total_queries\": " << stats.total << ",\n"
                  << "  \"failures\": " << failures << "\n"
                  << "}\n";
    } else {
        std::cout << "\nBenchmark Results:\n"
                  << "  Runs:                " << args.benchmark_runs << "\n"
                  << "  Cold Latency:        " << std::fixed << std::setprecision(2) << cold_time << " ms\n"
                  << "  Warm Cache Hit Rate: " << hit_rate << " %\n"
                  << "  Min Latency:         " << min_l << " ms\n"
                  << "  Median Latency:      " << median_l << " ms\n"
                  << "  P95 Latency:         " << p95_l << " ms\n"
                  << "  P99 Latency:         " << p99_l << " ms\n"
                  << "  Max Latency:         " << max_l << " ms\n"
                  << "  Average Latency:     " << mean_l << " ms\n"
                  << "  Total Queries:       " << stats.total << "\n"
                  << "  Failures:            " << failures << "\n";
    }
    return 0;
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

constexpr std::uint16_t kOkFlags = 0x8180;

void test_query_encoding() {
    std::cout << "Query encoding\n";
    const Bytes expected = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
                            0,    0x00, 0x01, 0x00, 0x01};
    CHECK(encode_query("example.com", RecordType::A, 0x1234) == expected);
    CHECK(encode_query("Example.COM.", RecordType::A, 0x1234) == expected);
    const Bytes mx = encode_query("example.com", RecordType::MX, 1);
    CHECK(mx[mx.size() - 4] == 0x00 && mx[mx.size() - 3] == 15);
    CHECK(normalize_domain("Example.COM.") == "example.com");

    // RD=0 for iterative queries
    const Bytes iter_query = encode_query("example.com", RecordType::A, 0x1234, false, false);
    CHECK((iter_query[2] & 0x01) == 0);

    // EDNS0 OPT RR attached in AR section
    const Bytes edns_query = encode_query("example.com", RecordType::A, 0x1234, false, true, 1232);
    CHECK(edns_query[11] == 1);  // ARCOUNT = 1

    bool rejected = true;
    for (const char* bad : {"", "a..b", "bad name.com", "-a.com", ".", "a b"}) {
        try { normalize_domain(bad); rejected = false; } catch (const std::invalid_argument&) {}
    }
    CHECK(rejected);
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
    w.name("www.example.com");
    const std::size_t second = w.data.size();
    w.u8(4).raw({'m', 'a', 'i', 'l'}).u16(0xC000);
    const std::size_t third = w.data.size();
    w.u16(0xC000 | static_cast<unsigned>(second));
    std::size_t off = 0;
    CHECK(decode_name(w.data, off) == "www.example.com" && off == 17);
    off = second;
    CHECK(decode_name(w.data, off) == "mail.www.example.com" && off == second + 7);
    off = third;
    CHECK(decode_name(w.data, off) == "mail.www.example.com" && off == third + 2);
    off = 0;
    CHECK(decode_name(ByteWriter().u8(0).data, off).empty() && off == 1);

    const Bytes self = {0xC0, 0x00};
    off = 0;
    CHECK(throws_dns_error([&] { decode_name(self, off); }));
    const Bytes fwd = {0xC0, 0x05, 0, 0, 0, 1, 'a', 0};
    off = 0;
    CHECK(throws_dns_error([&] { decode_name(fwd, off); }));
    const Bytes overrun = {5, 'a', 'b'};
    off = 0;
    CHECK(throws_dns_error([&] { decode_name(overrun, off); }));
    const Bytes reserved = {0x40, 'a', 0};
    off = 0;
    CHECK(throws_dns_error([&] { decode_name(reserved, off); }));
    const Bytes no_end = {1, 'a'};
    off = 0;
    CHECK(throws_dns_error([&] { decode_name(no_end, off); }));
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
        add_record(w, 1, 30, {1, 2, 3, 4});
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
        CHECK(parse_as(w.data, RecordType::A).answers[0].ttl == 0);
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
        CHECK(throws_dns_error([&] { parse_as(Bytes(pkt.begin(), pkt.end() - 3), RecordType::A); }));
        CHECK(throws_dns_error([&] { parse_as(Bytes(pkt.begin(), pkt.begin() + 20), RecordType::A); }));
    }
    {
        ByteWriter w = response_head(kOkFlags, 1, 1);
        w.u16(0xC00C).u16(1).u16(1).u32(5).u16(200).raw({1, 2, 3, 4});
        CHECK(throws_dns_error([&] { parse_as(w.data, RecordType::A); }));
    }
    {
        ByteWriter w = response_head(kOkFlags, 1, 1);
        add_record(w, 1, 5, {1, 2, 3});
        CHECK(throws_dns_error([&] { parse_as(w.data, RecordType::A); }));
    }
    {
        ByteWriter w = response_head(kOkFlags, 1, 5);
        add_record(w, 1, 5, {1, 2, 3, 4});
        CHECK(throws_dns_error([&] { parse_as(w.data, RecordType::A); }));
    }
    {
        ByteWriter w = response_head(kOkFlags, 1, 1);
        w.u16(0xC000 | static_cast<unsigned>(w.data.size())).u16(1).u16(1).u32(5).u16(4).raw({1, 2, 3, 4});
        CHECK(throws_dns_error([&] { parse_as(w.data, RecordType::A); }));
    }
    {
        ByteWriter w = response_head(0x0100, 1, 0);
        CHECK(throws_dns_error([&] { parse_as(w.data, RecordType::A); }));
    }
    {
        ByteWriter w = response_head(kOkFlags, 1, 0, "other.org");
        CHECK(throws_dns_error([&] { parse_as(w.data, RecordType::A); }));
    }
    {
        ByteWriter w = response_head(kOkFlags, 1, 1);
        add_record(w, 1, 300, {1, 2, 3, 4});
        CHECK(throws_dns_error([&] { parse_as(w.data, RecordType::A, 0x4321); }));
        CHECK(!throws_dns_error([&] { parse_as(w.data, RecordType::A, kTestId); }));
        bool message_ok = false;
        try { parse_as(w.data, RecordType::A, 0x4321); } catch (const DnsError& e) {
            message_ok = std::string(e.what()).find("transaction ID mismatch") != std::string::npos;
        }
        CHECK(message_ok);
    }
    {
        const Response t = parse_as(response_head(0x8380, 1, 0).data, RecordType::A);
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

    CHECK(!cache.lookup(k1, out));
    CHECK(cache.store(k1, sample_answers(300, 60)));
    CHECK(cache.lookup(k1, out) && out.size() == 2);
    CHECK(out[0].ttl == 300 && out[1].ttl == 60);

    *now += std::chrono::seconds(10);
    CHECK(cache.lookup(k1, out) && out[0].ttl == 290 && out[1].ttl == 50);

    CHECK(!cache.lookup(CacheKey{"example.com", 28, 1, "1.1.1.1:53"}, out));
    CHECK(!cache.lookup(CacheKey{"example.com", 1, 1, "8.8.8.8:53"}, out));
    CHECK(!cache.lookup(CacheKey{"example.org", 1, 1, "1.1.1.1:53"}, out));

    *now += std::chrono::seconds(49);
    CHECK(cache.lookup(k1, out) && out[1].ttl == 1);
    *now += std::chrono::seconds(1);
    CHECK(!cache.lookup(k1, out));
    CHECK(cache.size() == 0);

    CHECK(!cache.store(k1, sample_answers(0, 300)));
    CHECK(!cache.store(k1, {}));
    CHECK(cache.size() == 0);

    const CacheKey ka{"a.com", 1, 1, "s"}, kb{"b.com", 1, 1, "s"}, kc{"c.com", 1, 1, "s"};
    CHECK(cache.store(ka, sample_answers(100, 100)));
    CHECK(cache.store(kb, sample_answers(500, 500)));
    CHECK(cache.store(kc, sample_answers(300, 300)));
    CHECK(cache.size() == 2);
    CHECK(!cache.lookup(ka, out) && cache.lookup(kb, out) && cache.lookup(kc, out));

    *now += std::chrono::seconds(301);
    const CacheKey kd{"d.com", 1, 1, "s"};
    CHECK(cache.store(kd, sample_answers(50, 50)));
    CHECK(cache.lookup(kb, out) && cache.lookup(kd, out) && cache.size() == 2);
}

void test_resolver_cache_path() {
    std::cout << "Resolver cache hit path (no network)\n";
    DnsCache cache(8);
    Stats stats;
    QueryOptions opts;
    opts.server = "1.1.1.1";
    cache.store(CacheKey{"example.com", 1, kClassIN, server_label(opts)}, sample_answers(300, 300));
    Resolver resolver(cache, stats);

    const QueryResult r = resolver.resolve("Example.COM", RecordType::A, opts);
    CHECK(r.cache_hit && r.status == QueryStatus::Ok && r.answers.size() == 2);
    CHECK(stats.total == 1 && stats.cache_hits == 1 && stats.cache_misses == 0 && stats.successful == 1);

    bool bad_server = false;
    try { QueryOptions bad; bad.server = "not-an-ip"; resolver.resolve("example.com", RecordType::A, bad); }
    catch (const std::invalid_argument&) { bad_server = true; }
    CHECK(bad_server);
    CHECK(stats.total == 1);
}

// -------------------------------------------------- New Iterative Tests ---

void test_root_hints() {
    std::cout << "Root hints loading and candidate selection\n";
    RootHints hints;
    CHECK(hints.server_count() == 13);
    CHECK(hints.total_ip_count() >= 26);  // At least 13 IPv4 and 13 IPv6

    const std::string custom_data =
        "; Sample test root hints\n"
        ". 3600000 NS TEST.ROOT-SERVERS.NET.\n"
        "TEST.ROOT-SERVERS.NET. 3600000 A 10.0.0.1\n"
        "TEST.ROOT-SERVERS.NET. 3600000 AAAA 2001:db8::1\n";
    CHECK(hints.load_from_string(custom_data));
    CHECK(hints.server_count() == 1);
    CHECK(hints.servers()[0].ipv4.size() == 1 && hints.servers()[0].ipv4[0] == "10.0.0.1");
    CHECK(hints.servers()[0].ipv6.size() == 1 && hints.servers()[0].ipv6[0] == "2001:db8::1");

    auto cand = hints.get_candidate_ips(true);
    CHECK(cand.size() == 2 && cand[0] == "10.0.0.1");
}

void test_soa_parsing() {
    std::cout << "SOA record parsing\n";
    ByteWriter w = response_head(kOkFlags, 6, 1);
    ByteWriter soa_rdata;
    soa_rdata.name("ns1.example.com").name("hostmaster.example.com")
             .u32(2026101701).u32(7200).u32(3600).u32(1209600).u32(300);
    add_record(w, 6, 3600, soa_rdata.data);

    Response r = parse_as(w.data, RecordType::SOA);
    CHECK(r.answers.size() == 1);
    CHECK(r.answers[0].type == 6);
    CHECK(r.answers[0].soa.mname == "ns1.example.com");
    CHECK(r.answers[0].soa.rname == "hostmaster.example.com");
    CHECK(r.answers[0].soa.serial == 2026101701);
    CHECK(r.answers[0].soa.minimum == 300);
}

void test_mock_iterative_resolution() {
    std::cout << "Mock iterative resolution (multi-stage referral and answers)\n";
    MockTransport mock;
    RootHints hints;
    const std::string root_data =
        ". NS A.ROOT-SERVERS.NET.\nA.ROOT-SERVERS.NET. A 198.41.0.4\n";
    hints.load_from_string(root_data);

    // 1. Root response: referral to .com (NS a.gtld-servers.net, glue 192.5.6.30)
    ByteWriter root_resp;
    root_resp.u16(kTestId).u16(0x8000).u16(1).u16(0).u16(1).u16(1)
             .name("example.com").u16(1).u16(kClassIN);
    // Authority: com. NS a.gtld-servers.net
    root_resp.name("com").u16(2).u16(kClassIN).u32(86400)
             .u16(20).name("a.gtld-servers.net");
    // Additional: a.gtld-servers.net A 192.5.6.30
    root_resp.name("a.gtld-servers.net").u16(1).u16(kClassIN).u32(86400)
             .u16(4).raw({192, 5, 6, 30});
    mock.register_response("198.41.0.4", "example.com", RecordType::A, root_resp.data);

    // 2. TLD response: referral to example.com (NS ns1.example.com, glue 93.184.216.34)
    ByteWriter tld_resp;
    tld_resp.u16(kTestId).u16(0x8000).u16(1).u16(0).u16(1).u16(1)
            .name("example.com").u16(1).u16(kClassIN);
    tld_resp.name("example.com").u16(2).u16(kClassIN).u32(86400)
            .u16(17).name("ns1.example.com");
    tld_resp.name("ns1.example.com").u16(1).u16(kClassIN).u32(86400)
            .u16(4).raw({93, 184, 216, 34});
    mock.register_response("192.5.6.30", "example.com", RecordType::A, tld_resp.data);

    // 3. Auth response: Authoritative Answer for example.com A -> 93.184.216.34
    ByteWriter auth_resp;
    auth_resp.u16(kTestId).u16(0x8400).u16(1).u16(1).u16(0).u16(0)
             .name("example.com").u16(1).u16(kClassIN);
    auth_resp.name("example.com").u16(1).u16(kClassIN).u32(300)
             .u16(4).raw({93, 184, 216, 34});
    mock.register_response("93.184.216.34", "example.com", RecordType::A, auth_resp.data);

    DnsCache cache;
    Stats stats;
    IterativeResolver resolver(mock, hints, cache, stats);
    TraceCollector trace;

    QueryResult res = resolver.resolve("example.com", RecordType::A, &trace);
    CHECK(res.status == QueryStatus::Ok);
    CHECK(res.answers.size() == 1);
    CHECK(res.answers[0].data == "93.184.216.34");
    CHECK(trace.query_count() == 3);  // Root, TLD, Auth
    CHECK(trace.steps()[0].stage_name == "ROOT");
    CHECK(trace.steps()[1].stage_name == "TLD");
    CHECK(trace.steps()[2].stage_name == "AUTHORITATIVE");
}

void test_mock_cname_and_loops() {
    std::cout << "Mock CNAME following and loop detection\n";
    MockTransport mock;
    RootHints hints;
    hints.load_from_string(". NS A.ROOT-SERVERS.NET.\nA.ROOT-SERVERS.NET. A 10.1.1.1\n");

    // Single server answers CNAME www.example.com -> target.example.com
    ByteWriter cname_resp;
    cname_resp.u16(kTestId).u16(0x8400).u16(1).u16(1).u16(0).u16(0)
              .name("www.example.com").u16(1).u16(kClassIN);
    cname_resp.name("www.example.com").u16(5).u16(kClassIN).u32(300)
              .u16(20).name("target.example.com");
    mock.register_response("10.1.1.1", "www.example.com", RecordType::A, cname_resp.data);

    // Target answers A 10.2.2.2
    ByteWriter target_resp;
    target_resp.u16(kTestId).u16(0x8400).u16(1).u16(1).u16(0).u16(0)
               .name("target.example.com").u16(1).u16(kClassIN);
    target_resp.name("target.example.com").u16(1).u16(kClassIN).u32(300)
               .u16(4).raw({10, 2, 2, 2});
    mock.register_response("10.1.1.1", "target.example.com", RecordType::A, target_resp.data);

    DnsCache cache;
    Stats stats;
    IterativeResolver resolver(mock, hints, cache, stats);
    QueryResult res = resolver.resolve("www.example.com", RecordType::A);
    CHECK(res.status == QueryStatus::Ok);
    CHECK(res.answers.size() == 2);
    CHECK(res.answers[0].type == 5 && res.answers[0].data == "target.example.com");
    CHECK(res.answers[1].type == 1 && res.answers[1].data == "10.2.2.2");

    // CNAME loop test: loop1 -> loop2 -> loop1
    ByteWriter loop1_resp;
    loop1_resp.u16(kTestId).u16(0x8400).u16(1).u16(1).u16(0).u16(0)
              .name("loop1.com").u16(1).u16(kClassIN);
    loop1_resp.name("loop1.com").u16(5).u16(kClassIN).u32(300)
              .u16(11).name("loop2.com");
    mock.register_response("10.1.1.1", "loop1.com", RecordType::A, loop1_resp.data);

    ByteWriter loop2_resp;
    loop2_resp.u16(kTestId).u16(0x8400).u16(1).u16(1).u16(0).u16(0)
              .name("loop2.com").u16(1).u16(kClassIN);
    loop2_resp.name("loop2.com").u16(5).u16(kClassIN).u32(300)
              .u16(11).name("loop1.com");
    mock.register_response("10.1.1.1", "loop2.com", RecordType::A, loop2_resp.data);

    QueryResult loop_res = resolver.resolve("loop1.com", RecordType::A);
    CHECK(loop_res.status == QueryStatus::Error);
    CHECK(loop_res.message.find("CNAME loop") != std::string::npos);
}

void test_mock_tcp_fallback() {
    std::cout << "Mock TCP fallback on truncated response\n";
    MockTransport mock;
    RootHints hints;
    hints.load_from_string(". NS A.ROOT-SERVERS.NET.\nA.ROOT-SERVERS.NET. A 10.5.5.5\n");

    // UDP response has TC bit set (flags 0x8380)
    ByteWriter udp_trunc;
    udp_trunc.u16(kTestId).u16(0x8380).u16(1).u16(0).u16(0).u16(0)
             .name("trunc.example.com").u16(1).u16(kClassIN);

    // TCP response has full answer (flags 0x8180)
    ByteWriter tcp_ok;
    tcp_ok.u16(kTestId).u16(0x8180).u16(1).u16(1).u16(0).u16(0)
          .name("trunc.example.com").u16(1).u16(kClassIN);
    tcp_ok.name("trunc.example.com").u16(1).u16(kClassIN).u32(100)
          .u16(4).raw({192, 0, 2, 1});

    mock.register_response("10.5.5.5", "trunc.example.com", RecordType::A, udp_trunc.data, tcp_ok.data);

    DnsCache cache;
    Stats stats;
    IterativeResolver resolver(mock, hints, cache, stats);
    QueryResult res = resolver.resolve("trunc.example.com", RecordType::A);
    CHECK(res.status == QueryStatus::Ok);
    CHECK(res.answers.size() == 1);
    CHECK(res.answers[0].data == "192.0.2.1");
}

int run_tests() {
    test_query_encoding();
    test_header_parsing();
    test_name_decoding();
    test_record_parsing();
    test_rejection_and_errors();
    test_cache();
    test_resolver_cache_path();
    test_root_hints();
    test_soa_parsing();
    test_mock_iterative_resolution();
    test_mock_cname_and_loops();
    test_mock_tcp_fallback();

    std::cout << "\n========================================\n"
              << "TEST SUMMARY: " << g_passed << " passed, " << g_failed << " failed\n"
              << "========================================\n";
    return g_failed == 0 ? 0 : 1;
}

}  // namespace

// ================================================================ main ====

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
            case Command::Cache:
                return run_cache_display();
            case Command::CacheClear:
                return run_cache_clear();
            case Command::Inspect:
                return run_inspect(args);
            case Command::Benchmark:
                return run_benchmark(args);
            case Command::Stats: {
                const Stats fresh;
                print_stats(fresh);
                std::cout << "\nNote: statistics live in memory and are not saved between runs, so a fresh\n"
                             "process reports zeros. Use `--repeat N` or `benchmark` to observe accumulated metrics.\n";
                return 0;
            }
            case Command::Resolve:
                return run_resolve(args);
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
