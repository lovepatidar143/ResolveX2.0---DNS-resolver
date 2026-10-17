// resolver.cpp - Iterative DNS resolver engine and query orchestration.
#include "resolver.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <chrono>
#include <random>
#include <set>
#include <stdexcept>

namespace resolvex {
namespace {

std::uint16_t random_transaction_id() {
    std::random_device rd;
    return static_cast<std::uint16_t>(rd() & 0xFFFF);
}

bool equals_icase(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

std::size_t label_count(const std::string& name) {
    if (name.empty()) return 0;
    std::size_t count = 1;
    for (char c : name) {
        if (c == '.') ++count;
    }
    return count;
}

Stage classify_stage(const std::string& zone, int referral_depth) {
    if (referral_depth == 0 || zone.empty() || zone == ".") return Stage::Root;
    const std::size_t labels = label_count(zone);
    if (labels <= 1) return Stage::Tld;
    return Stage::Authoritative;
}

std::string stage_to_string(Stage st) {
    switch (st) {
        case Stage::Root: return "ROOT";
        case Stage::Tld: return "TLD";
        case Stage::Authoritative: return "AUTHORITATIVE";
        case Stage::Subquery: return "SUBQUERY";
        case Stage::TcpFallback: return "TCP FALLBACK";
    }
    return "QUERY";
}

}  // namespace

bool is_valid_ipv4(const std::string& text) {
    in_addr addr;
    return inet_pton(AF_INET, text.c_str(), &addr) == 1;
}

bool is_valid_ipv6(const std::string& text) {
    in6_addr addr;
    return inet_pton(AF_INET6, text.c_str(), &addr) == 1;
}

bool is_valid_ip(const std::string& text) {
    return is_valid_ipv4(text) || is_valid_ipv6(text);
}

std::string server_label(const QueryOptions& options) {
    if (options.server.empty()) return "Iterative";
    return options.server + ":" + std::to_string(options.port);
}

// ---------------------------------------------------- IterativeResolver ---

IterativeResolver::IterativeResolver(ITransport& transport, const RootHints& root_hints,
                                     DnsCache& cache, Stats& stats, ResolverConfig config)
    : transport_(transport), root_hints_(root_hints), cache_(cache), stats_(stats), config_(config) {}

bool IterativeResolver::is_in_bailiwick(const std::string& ns_name, const std::string& zone) const {
    const std::string norm_ns = normalize_domain(ns_name);
    const std::string norm_zone = normalize_domain(zone);
    if (norm_ns == norm_zone) return true;
    if (norm_ns.size() > norm_zone.size() + 1 &&
        norm_ns.compare(norm_ns.size() - norm_zone.size(), norm_zone.size(), norm_zone) == 0 &&
        norm_ns[norm_ns.size() - norm_zone.size() - 1] == '.') {
        return true;
    }
    return false;
}

IterativeResolver::Delegation IterativeResolver::parse_referral(const Response& resp) {
    Delegation del;
    for (const auto& rr : resp.authorities) {
        if (rr.type == static_cast<std::uint16_t>(RecordType::NS)) {
            if (del.zone.empty()) del.zone = rr.name;
            const std::string ns = normalize_domain(rr.data);
            if (std::find(del.nameservers.begin(), del.nameservers.end(), ns) == del.nameservers.end()) {
                del.nameservers.push_back(ns);
            }
        }
    }

    // Extract usable glue records from additionals
    std::vector<Endpoint> v4_eps;
    std::vector<Endpoint> v6_eps;
    for (const auto& rr : resp.additionals) {
        if (rr.type == static_cast<std::uint16_t>(RecordType::A)) {
            const std::string glue_owner = normalize_domain(rr.name);
            for (const auto& ns : del.nameservers) {
                if (equals_icase(glue_owner, ns)) {
                    Endpoint ep{rr.data, 53};
                    if (std::find_if(v4_eps.begin(), v4_eps.end(),
                                     [&](const Endpoint& e) { return e.ip == ep.ip; }) == v4_eps.end()) {
                        v4_eps.push_back(ep);
                    }
                    break;
                }
            }
        } else if (rr.type == static_cast<std::uint16_t>(RecordType::AAAA)) {
            const std::string glue_owner = normalize_domain(rr.name);
            for (const auto& ns : del.nameservers) {
                if (equals_icase(glue_owner, ns)) {
                    Endpoint ep{rr.data, 53};
                    if (std::find_if(v6_eps.begin(), v6_eps.end(),
                                     [&](const Endpoint& e) { return e.ip == ep.ip; }) == v6_eps.end()) {
                        v6_eps.push_back(ep);
                    }
                    break;
                }
            }
        }
    }

    if (config_.prefer_ipv4) {
        del.servers.insert(del.servers.end(), v4_eps.begin(), v4_eps.end());
        del.servers.insert(del.servers.end(), v6_eps.begin(), v6_eps.end());
    } else {
        del.servers.insert(del.servers.end(), v6_eps.begin(), v6_eps.end());
        del.servers.insert(del.servers.end(), v4_eps.begin(), v4_eps.end());
    }
    return del;
}

std::vector<Endpoint> IterativeResolver::resolve_missing_glue(const std::vector<std::string>& ns_names,
                                                            ResolutionContext& ctx,
                                                            TraceCollector* trace) {
    std::vector<Endpoint> resolved;
    if (ctx.subresolution_depth >= config_.max_subresolution_depth) {
        return resolved;
    }

    ctx.subresolution_depth++;

    for (const auto& ns : ns_names) {
        const std::string norm_ns = normalize_domain(ns);

        // Circular subquery detection
        if (std::find(ctx.resolving_nameservers.begin(), ctx.resolving_nameservers.end(), norm_ns) !=
            ctx.resolving_nameservers.end()) {
            continue;
        }

        ctx.resolving_nameservers.push_back(norm_ns);

        if (trace) {
            TraceStep step;
            step.stage = Stage::Subquery;
            step.stage_name = "SUBQUERY (resolving missing glue)";
            step.query_name = norm_ns;
            step.query_type = RecordType::A;
            step.detail = "No glue records in referral; resolving nameserver IP directly";
            trace->record_step(step);
        }

        QueryResult sub_res = resolve_internal(norm_ns, RecordType::A, ctx, trace);
        ctx.resolving_nameservers.pop_back();

        if (sub_res.status == QueryStatus::Ok) {
            for (const auto& rr : sub_res.answers) {
                if (rr.type == static_cast<std::uint16_t>(RecordType::A)) {
                    resolved.push_back(Endpoint{rr.data, 53});
                }
            }
        }

        if (!resolved.empty()) break;  // One working nameserver address is sufficient
    }

    ctx.subresolution_depth--;
    return resolved;
}

QueryResult IterativeResolver::resolve(const std::string& domain, RecordType type, TraceCollector* trace) {
    const auto start_time = std::chrono::steady_clock::now();
    const std::string norm_domain = normalize_domain(domain);

    if (trace) {
        trace->start_query(norm_domain, type);
    }

    ResolutionContext ctx;
    ctx.target_domain = norm_domain;
    ctx.target_type = type;

    QueryResult result = resolve_internal(norm_domain, type, ctx, trace);

    const double elapsed_ms = std::chrono::duration<double, std::milli>(
                                  std::chrono::steady_clock::now() - start_time).count();
    result.latency_ms = elapsed_ms;

    ++stats_.total;
    if (result.cache_hit) {
        ++stats_.cache_hits;
    } else {
        ++stats_.cache_misses;
    }

    if (result.status == QueryStatus::Error) {
        ++stats_.failed;
    } else {
        ++stats_.successful;
    }
    stats_.total_latency_ms += elapsed_ms;

    if (trace) {
        trace->finish(result.status == QueryStatus::Ok || result.status == QueryStatus::NoData,
                      result.message, elapsed_ms);
    }

    return result;
}

QueryResult IterativeResolver::resolve_internal(const std::string& current_name, RecordType current_type,
                                                ResolutionContext& ctx, TraceCollector* trace) {
    const std::string norm_name = normalize_domain(current_name);

    // 1. Cache lookup
    if (!config_.no_cache) {
        const CacheKey key{norm_name, static_cast<std::uint16_t>(current_type), kClassIN, ""};
        std::vector<ResourceRecord> cached_answers;
        if (cache_.lookup(key, cached_answers)) {
            QueryResult r;
            r.domain = norm_name;
            r.type = current_type;
            r.server = "Cache";
            r.status = QueryStatus::Ok;
            r.message = "NOERROR (served from cache)";
            r.cache_hit = true;
            r.answers = std::move(cached_answers);
            if (trace) trace->record_cache_hit(norm_name, current_type, 0.05);
            return r;
        }
    }

    // 2. Initialize candidate servers from root hints
    std::vector<Endpoint> candidates;
    for (const auto& ip : root_hints_.get_candidate_ips(config_.prefer_ipv4)) {
        candidates.push_back(Endpoint{ip, 53});
    }

    if (candidates.empty()) {
        QueryResult r;
        r.domain = norm_name;
        r.type = current_type;
        r.status = QueryStatus::Error;
        r.message = "No root nameserver addresses available in root hints";
        return r;
    }

    int referral_depth = 0;
    std::string current_zone = ".";
    std::set<std::string> visited_delegation_zones;

    while (referral_depth < config_.max_referral_depth) {
        if (ctx.total_queries >= config_.max_queries) {
            QueryResult r;
            r.domain = norm_name;
            r.type = current_type;
            r.status = QueryStatus::Error;
            r.message = "Query budget exceeded (" + std::to_string(config_.max_queries) + " queries)";
            return r;
        }

        const Stage current_stage = classify_stage(current_zone, referral_depth);
        bool query_succeeded = false;
        Response response;
        Endpoint answered_server;
        double query_latency = 0.0;
        bool was_tcp = false;

        // Try candidates for this delegation stage
        for (const auto& server : candidates) {
            ctx.total_queries++;
            const std::uint16_t id = random_transaction_id();
            const Bytes query_bytes = encode_query(norm_name, current_type, id,
                                                   /*recursion_desired=*/false,
                                                   config_.use_edns, 1232);
            const Question expected_q{norm_name, static_cast<std::uint16_t>(current_type), kClassIN};

            TraceStep step;
            step.stage = current_stage;
            step.stage_name = stage_to_string(current_stage);
            step.server = server;
            step.query_name = norm_name;
            step.query_type = current_type;

            try {
                const ExchangeResult ex = transport_.exchange(server, query_bytes, config_.timeout_ms,
                                                             id, config_.use_tcp_fallback);
                query_latency = ex.latency_ms;
                was_tcp = ex.via_tcp;
                step.transport_protocol = ex.via_tcp ? "TCP" : "UDP";
                step.latency_ms = ex.latency_ms;

                response = parse_response(ex.reply, id, expected_q);
                step.rcode = response.rcode;

                if (response.truncated) {
                    step.response_classification = "Truncated";
                    step.detail = "Packet truncated and TCP fallback was not successful";
                    if (trace) trace->record_step(step);
                    continue;
                }

                answered_server = server;
                query_succeeded = true;
                break;
            } catch (const TimeoutError& e) {
                step.response_classification = "Timeout";
                step.detail = e.what();
                step.retry = true;
                if (trace) trace->record_step(step);
            } catch (const NetworkError& e) {
                step.response_classification = "NetworkError";
                step.detail = e.what();
                step.retry = true;
                if (trace) trace->record_step(step);
            } catch (const DnsError& e) {
                step.response_classification = "DnsError";
                step.detail = e.what();
                step.retry = true;
                if (trace) trace->record_step(step);
            }
        }

        if (!query_succeeded) {
            QueryResult r;
            r.domain = norm_name;
            r.type = current_type;
            r.status = QueryStatus::Error;
            r.message = "All nameservers for zone '" + current_zone + "' failed to respond";
            return r;
        }

        // 3. Process the response

        // Handle error response codes (NXDOMAIN, SERVFAIL, REFUSED, etc.)
        if (response.rcode == 3) {  // NXDOMAIN
            if (trace) {
                TraceStep step;
                step.stage = current_stage;
                step.stage_name = stage_to_string(current_stage);
                step.server = answered_server;
                step.query_name = norm_name;
                step.query_type = current_type;
                step.transport_protocol = was_tcp ? "TCP" : "UDP";
                step.response_classification = "NXDOMAIN";
                step.rcode = 3;
                step.latency_ms = query_latency;
                trace->record_step(step);
            }
            QueryResult r;
            r.domain = norm_name;
            r.type = current_type;
            r.server = answered_server.to_string();
            r.status = QueryStatus::Error;
            r.rcode = 3;
            r.message = rcode_message(3);
            return r;
        }

        if (response.rcode != 0) {
            if (trace) {
                TraceStep step;
                step.stage = current_stage;
                step.stage_name = stage_to_string(current_stage);
                step.server = answered_server;
                step.query_name = norm_name;
                step.query_type = current_type;
                step.transport_protocol = was_tcp ? "TCP" : "UDP";
                step.response_classification = "RCODE " + std::to_string(response.rcode);
                step.rcode = response.rcode;
                step.latency_ms = query_latency;
                trace->record_step(step);
            }
            QueryResult r;
            r.domain = norm_name;
            r.type = current_type;
            r.server = answered_server.to_string();
            r.status = QueryStatus::Error;
            r.rcode = response.rcode;
            r.message = rcode_message(response.rcode);
            return r;
        }

        // Check Answer section for direct matching records
        std::vector<ResourceRecord> direct_answers;
        std::string cname_target;
        ResourceRecord cname_record;
        bool has_cname = false;

        for (const auto& rr : response.answers) {
            if (rr.type == static_cast<std::uint16_t>(current_type) && equals_icase(rr.name, norm_name)) {
                direct_answers.push_back(rr);
            } else if (rr.type == static_cast<std::uint16_t>(RecordType::CNAME) && equals_icase(rr.name, norm_name)) {
                has_cname = true;
                cname_target = normalize_domain(rr.data);
                cname_record = rr;
            }
        }

        // Direct answer match
        if (!direct_answers.empty()) {
            if (trace) {
                TraceStep step;
                step.stage = Stage::Authoritative;
                step.stage_name = "AUTHORITATIVE";
                step.server = answered_server;
                step.query_name = norm_name;
                step.query_type = current_type;
                step.transport_protocol = was_tcp ? "TCP" : "UDP";
                step.response_classification = "Answer";
                step.rcode = 0;
                step.latency_ms = query_latency;
                trace->record_step(step);
            }

            if (!config_.no_cache) {
                cache_.store(CacheKey{norm_name, static_cast<std::uint16_t>(current_type), kClassIN, ""},
                             direct_answers);
            }

            QueryResult r;
            r.domain = norm_name;
            r.type = current_type;
            r.server = answered_server.to_string();
            r.status = QueryStatus::Ok;
            r.message = "NOERROR";
            r.answers = std::move(direct_answers);
            return r;
        }

        // CNAME response
        if (has_cname) {
            if (current_type == RecordType::CNAME) {
                // Requested record was CNAME itself
                std::vector<ResourceRecord> c_ans{cname_record};
                if (!config_.no_cache) {
                    cache_.store(CacheKey{norm_name, static_cast<std::uint16_t>(RecordType::CNAME), kClassIN, ""},
                                 c_ans);
                }
                QueryResult r;
                r.domain = norm_name;
                r.type = RecordType::CNAME;
                r.server = answered_server.to_string();
                r.status = QueryStatus::Ok;
                r.message = "NOERROR";
                r.answers = std::move(c_ans);
                return r;
            }

            // Check CNAME loop and depth
            if (ctx.cname_depth >= config_.max_cname_depth) {
                QueryResult r;
                r.domain = norm_name;
                r.type = current_type;
                r.status = QueryStatus::Error;
                r.message = "CNAME chain depth limit exceeded (" + std::to_string(config_.max_cname_depth) + ")";
                return r;
            }

            if (std::find(ctx.visited_cnames.begin(), ctx.visited_cnames.end(), cname_target) !=
                ctx.visited_cnames.end()) {
                QueryResult r;
                r.domain = norm_name;
                r.type = current_type;
                r.status = QueryStatus::Error;
                r.message = "CNAME loop detected: " + cname_target;
                return r;
            }

            ctx.visited_cnames.push_back(cname_target);
            ctx.cname_depth++;

            if (trace) {
                TraceStep step;
                step.stage = current_stage;
                step.stage_name = stage_to_string(current_stage);
                step.server = answered_server;
                step.query_name = norm_name;
                step.query_type = current_type;
                step.transport_protocol = was_tcp ? "TCP" : "UDP";
                step.response_classification = "CNAME -> " + cname_target;
                step.rcode = 0;
                step.latency_ms = query_latency;
                trace->record_step(step);
            }

            // Check if response answers already contained the target record
            std::vector<ResourceRecord> chain_records{cname_record};
            bool target_found_in_pkt = false;
            for (const auto& rr : response.answers) {
                if (rr.type == static_cast<std::uint16_t>(current_type) && equals_icase(rr.name, cname_target)) {
                    chain_records.push_back(rr);
                    target_found_in_pkt = true;
                }
            }

            if (target_found_in_pkt) {
                if (!config_.no_cache) {
                    cache_.store(CacheKey{norm_name, static_cast<std::uint16_t>(current_type), kClassIN, ""},
                                 chain_records);
                }
                QueryResult r;
                r.domain = norm_name;
                r.type = current_type;
                r.server = answered_server.to_string();
                r.status = QueryStatus::Ok;
                r.message = "NOERROR (CNAME followed in response)";
                r.answers = std::move(chain_records);
                return r;
            }

            // Resolve target domain recursively
            QueryResult target_res = resolve_internal(cname_target, current_type, ctx, trace);
            if (target_res.status == QueryStatus::Ok) {
                chain_records.insert(chain_records.end(), target_res.answers.begin(), target_res.answers.end());
                if (!config_.no_cache) {
                    cache_.store(CacheKey{norm_name, static_cast<std::uint16_t>(current_type), kClassIN, ""},
                                 chain_records);
                }
                target_res.answers = std::move(chain_records);
            }
            return target_res;
        }

        // Referral processing (Authority section with NS records)
        Delegation del = parse_referral(response);
        if (!del.nameservers.empty()) {
            if (visited_delegation_zones.find(del.zone) != visited_delegation_zones.end()) {
                QueryResult r;
                r.domain = norm_name;
                r.type = current_type;
                r.status = QueryStatus::Error;
                r.message = "Referral loop detected on zone: " + del.zone;
                return r;
            }
            visited_delegation_zones.insert(del.zone);
            current_zone = del.zone;

            // If no glue records provided, resolve missing glue
            if (del.servers.empty()) {
                del.servers = resolve_missing_glue(del.nameservers, ctx, trace);
            }

            if (del.servers.empty()) {
                QueryResult r;
                r.domain = norm_name;
                r.type = current_type;
                r.status = QueryStatus::Error;
                r.message = "Failed to obtain nameserver IP addresses for zone '" + del.zone + "' (missing glue)";
                return r;
            }

            if (trace) {
                TraceStep step;
                step.stage = current_stage;
                step.stage_name = stage_to_string(current_stage);
                step.server = answered_server;
                step.query_name = norm_name;
                step.query_type = current_type;
                step.transport_protocol = was_tcp ? "TCP" : "UDP";
                step.response_classification = "Referral";
                step.delegated_zone = del.zone;
                step.nameservers = del.nameservers;
                for (const auto& s : del.servers) step.glue_ips.push_back(s.ip);
                step.rcode = 0;
                step.latency_ms = query_latency;
                trace->record_step(step);
            }

            candidates = std::move(del.servers);
            referral_depth++;
            continue;
        }

        // NODATA check (NOERROR, no answers, authority has SOA or no NS)
        bool has_soa = false;
        for (const auto& rr : response.authorities) {
            if (rr.type == static_cast<std::uint16_t>(RecordType::SOA)) {
                has_soa = true;
                break;
            }
        }

        if (response.answers.empty()) {
            if (trace) {
                TraceStep step;
                step.stage = current_stage;
                step.stage_name = stage_to_string(current_stage);
                step.server = answered_server;
                step.query_name = norm_name;
                step.query_type = current_type;
                step.transport_protocol = was_tcp ? "TCP" : "UDP";
                step.response_classification = has_soa ? "NODATA (SOA)" : "NODATA (Empty)";
                step.rcode = 0;
                step.latency_ms = query_latency;
                trace->record_step(step);
            }
            QueryResult r;
            r.domain = norm_name;
            r.type = current_type;
            r.server = answered_server.to_string();
            r.status = QueryStatus::NoData;
            r.message = "NOERROR, but the server returned no " +
                        record_type_name(static_cast<std::uint16_t>(current_type)) + " records";
            return r;
        }

        referral_depth++;
    }

    QueryResult r;
    r.domain = norm_name;
    r.type = current_type;
    r.status = QueryStatus::Error;
    r.message = "Maximum referral depth exceeded (" + std::to_string(config_.max_referral_depth) + ")";
    return r;
}

QueryResult IterativeResolver::query_direct(const std::string& domain, RecordType type,
                                            const Endpoint& server, bool recursion_desired,
                                            TraceCollector* trace) {
    const auto start_time = std::chrono::steady_clock::now();
    const std::string norm_domain = normalize_domain(domain);

    if (trace) trace->start_query(norm_domain, type);

    const std::uint16_t id = random_transaction_id();
    const Bytes query_bytes = encode_query(norm_domain, type, id, recursion_desired,
                                           config_.use_edns, 1232);
    const Question expected_q{norm_domain, static_cast<std::uint16_t>(type), kClassIN};

    TraceStep step;
    step.stage = Stage::Authoritative;
    step.stage_name = "DIRECT";
    step.server = server;
    step.query_name = norm_domain;
    step.query_type = type;

    QueryResult res;
    res.domain = norm_domain;
    res.type = type;
    res.server = server.to_string();

    const CacheKey key{norm_domain, static_cast<std::uint16_t>(type), kClassIN, server_label(QueryOptions{server.ip, server.port, 0})};
    if (!config_.no_cache) {
        if (cache_.lookup(key, res.answers)) {
            res.cache_hit = true;
            res.status = QueryStatus::Ok;
            res.message = "NOERROR (served from cache)";
            res.latency_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start_time).count();
            if (trace) trace->record_cache_hit(norm_domain, type, res.latency_ms);
            ++stats_.total;
            ++stats_.cache_hits;
            ++stats_.successful;
            stats_.total_latency_ms += res.latency_ms;
            return res;
        }
    }

    ++stats_.cache_misses;

    try {
        const ExchangeResult ex = transport_.exchange(server, query_bytes, config_.timeout_ms, id,
                                                     config_.use_tcp_fallback);
        res.latency_ms = ex.latency_ms;
        step.latency_ms = ex.latency_ms;
        step.transport_protocol = ex.via_tcp ? "TCP" : "UDP";

        const Response r = parse_response(ex.reply, id, expected_q);
        res.rcode = r.rcode;
        step.rcode = r.rcode;

        if (r.truncated) {
            res.status = QueryStatus::Error;
            res.message = "response truncated (TC flag set); results would be incomplete";
            step.response_classification = "Truncated";
        } else if (r.rcode != 0) {
            res.status = QueryStatus::Error;
            res.message = rcode_message(r.rcode);
            step.response_classification = "Error " + std::to_string(r.rcode);
        } else if (r.answers.empty()) {
            res.status = QueryStatus::NoData;
            res.message = "NOERROR, but the server returned no " +
                          record_type_name(static_cast<std::uint16_t>(type)) + " records";
            step.response_classification = "NODATA";
        } else {
            res.status = QueryStatus::Ok;
            res.message = "NOERROR";
            res.answers = r.answers;
            step.response_classification = "Answer";
            if (!config_.no_cache) {
                cache_.store(CacheKey{norm_domain, static_cast<std::uint16_t>(type), kClassIN, server_label(QueryOptions{server.ip, server.port, 0})},
                             r.answers);
            }
        }
    } catch (const NetworkError& e) {
        res.status = QueryStatus::Error;
        res.message = e.what();
        step.response_classification = "NetworkError";
        step.detail = e.what();
    } catch (const DnsError& e) {
        res.status = QueryStatus::Error;
        res.message = std::string("malformed response rejected: ") + e.what();
        step.response_classification = "DnsError";
        step.detail = e.what();
    }

    res.latency_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start_time).count();

    if (trace) {
        trace->record_step(step);
        trace->finish(res.status == QueryStatus::Ok || res.status == QueryStatus::NoData,
                      res.message, res.latency_ms);
    }

    ++stats_.total;
    if (res.status == QueryStatus::Error) ++stats_.failed; else ++stats_.successful;
    stats_.total_latency_ms += res.latency_ms;

    return res;
}

// -------------------------------------------------- Resolver wrapper ---

Resolver::Resolver(DnsCache& cache, Stats& stats, ITransport* transport,
                   const RootHints* root_hints)
    : cache_(cache), stats_(stats),
      owned_transport_(transport ? nullptr : std::make_unique<PosixTransport>()),
      transport_(transport ? *transport : *owned_transport_),
      owned_root_hints_(root_hints ? nullptr : std::make_unique<RootHints>()),
      root_hints_(root_hints ? *root_hints : *owned_root_hints_) {
    if (owned_root_hints_) {
        const std::string default_hints = RootHints::find_default_hints_file();
        if (!default_hints.empty()) {
            owned_root_hints_->load_from_file(default_hints);
        }
    }
    engine_ = std::make_unique<IterativeResolver>(transport_, root_hints_, cache_, stats_);
}

QueryResult Resolver::resolve(const std::string& domain, RecordType type,
                              const QueryOptions& options, TraceCollector* trace) {
    if (!options.server.empty()) {
        if (!is_valid_ip(options.server)) {
            throw std::invalid_argument("'" + options.server + "' is not a valid IP address");
        }
        return engine_->query_direct(domain, type, Endpoint{options.server, options.port},
                                     /*recursion_desired=*/true, trace);
    }

    return engine_->resolve(domain, type, trace);
}

}  // namespace resolvex
