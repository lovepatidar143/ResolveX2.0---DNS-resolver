#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "cache.hpp"
#include "dns.hpp"
#include "root_hints.hpp"
#include "trace.hpp"
#include "transport.hpp"

namespace resolvex {

// -------------------------------------------------------- Resolver types ---

struct QueryOptions {
    std::string server = "";  // If empty, perform iterative resolution; if specified, query directly
    std::uint16_t port = 53;
    int timeout_ms = 3000;
};

enum class QueryStatus {
    Ok,      // NOERROR with at least one answer
    NoData,  // NOERROR but no records of the requested type (NODATA)
    Error,   // timeout, malformed packet, truncated, NXDOMAIN, or server error
};

struct QueryResult {
    std::string domain;
    RecordType type = RecordType::A;
    std::string server;   // IP:port of the answering server or "Iterative"
    QueryStatus status = QueryStatus::Error;
    std::string message;  // human readable status/error detail
    std::uint8_t rcode = 0;
    bool cache_hit = false;
    double latency_ms = 0.0;
    std::vector<ResourceRecord> answers;
};

struct ResolverConfig {
    int timeout_ms = 3000;
    int max_retries_per_server = 1;
    int max_referral_depth = 16;
    int max_queries = 40;
    int max_cname_depth = 10;
    int max_subresolution_depth = 3;
    bool use_edns = true;
    bool prefer_ipv4 = true;
    bool use_tcp_fallback = true;
    bool no_cache = false;
};

// ---------------------------------------------------- IterativeResolver ---

class IterativeResolver {
public:
    IterativeResolver(ITransport& transport, const RootHints& root_hints,
                      DnsCache& cache, Stats& stats, ResolverConfig config = {});

    // Main entry point for iterative DNS resolution.
    // Traverses root -> TLD -> authoritative nameservers, handles CNAME chasing,
    // missing glue sub-resolution, retries, and bounded failure.
    QueryResult resolve(const std::string& domain, RecordType type,
                        TraceCollector* trace = nullptr);

    // Queries a specific upstream DNS server directly (RD=1 by default).
    QueryResult query_direct(const std::string& domain, RecordType type,
                             const Endpoint& server, bool recursion_desired = true,
                             TraceCollector* trace = nullptr);

    const ResolverConfig& config() const { return config_; }
    void set_config(const ResolverConfig& cfg) { config_ = cfg; }

private:
    struct ResolutionContext {
        std::string target_domain;
        RecordType target_type = RecordType::A;
        int total_queries = 0;
        int cname_depth = 0;
        int subresolution_depth = 0;
        std::vector<std::string> visited_cnames;
        std::vector<std::string> resolving_nameservers;  // Circular subquery detection
    };

    struct Delegation {
        std::string zone;
        std::vector<std::string> nameservers;
        std::vector<Endpoint> servers;
    };

    QueryResult resolve_internal(const std::string& current_name, RecordType current_type,
                                 ResolutionContext& ctx, TraceCollector* trace);

    Delegation parse_referral(const Response& resp);

    std::vector<Endpoint> resolve_missing_glue(const std::vector<std::string>& ns_names,
                                              ResolutionContext& ctx, TraceCollector* trace);

    bool is_in_bailiwick(const std::string& ns_name, const std::string& zone) const;

    ITransport& transport_;
    const RootHints& root_hints_;
    DnsCache& cache_;
    Stats& stats_;
    ResolverConfig config_;
};

// Backwards-compatible Resolver interface
class Resolver {
public:
    Resolver(DnsCache& cache, Stats& stats, ITransport* transport = nullptr,
             const RootHints* root_hints = nullptr);

    QueryResult resolve(const std::string& domain, RecordType type, const QueryOptions& options,
                        TraceCollector* trace = nullptr);

private:
    DnsCache& cache_;
    Stats& stats_;
    std::unique_ptr<ITransport> owned_transport_;
    ITransport& transport_;
    std::unique_ptr<RootHints> owned_root_hints_;
    const RootHints& root_hints_;
    std::unique_ptr<IterativeResolver> engine_;
};

bool is_valid_ipv4(const std::string& text);
bool is_valid_ip(const std::string& text);
std::string server_label(const QueryOptions& options);

}  // namespace resolvex
