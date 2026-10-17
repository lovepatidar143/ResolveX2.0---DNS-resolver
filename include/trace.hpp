#pragma once

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "dns.hpp"
#include "transport.hpp"

namespace resolvex {

enum class Stage {
    Root,
    Tld,
    Authoritative,
    Subquery,
    TcpFallback
};

struct TraceStep {
    std::size_t step_number = 1;
    Stage stage = Stage::Root;
    std::string stage_name;  // "ROOT", "TLD", "AUTHORITATIVE", "SUBQUERY", "TCP FALLBACK"
    Endpoint server;
    std::string query_name;
    RecordType query_type = RecordType::A;
    std::string transport_protocol = "UDP";  // "UDP" or "TCP"
    std::string response_classification;     // "Referral", "Answer", "CNAME", "NXDOMAIN", "NODATA", "Timeout", "Error"
    std::uint8_t rcode = 0;
    std::string delegated_zone;
    std::vector<std::string> nameservers;
    std::vector<std::string> glue_ips;
    double latency_ms = 0.0;
    bool retry = false;
    std::string detail;
};

class TraceCollector {
public:
    TraceCollector() = default;

    void start_query(const std::string& domain, RecordType type);

    void record_step(TraceStep step);

    void record_cache_hit(const std::string& domain, RecordType type, double latency_ms);

    void finish(bool success, const std::string& summary_message, double total_elapsed_ms);

    void print_trace(std::ostream& out) const;
    void print_json(std::ostream& out) const;

    const std::vector<TraceStep>& steps() const { return steps_; }
    std::size_t query_count() const { return steps_.size(); }
    double total_time_ms() const { return total_time_ms_; }
    bool is_cache_hit() const { return cache_hit_; }
    bool is_success() const { return success_; }

private:
    std::string query_domain_;
    RecordType query_type_ = RecordType::A;
    std::vector<TraceStep> steps_;
    bool cache_hit_ = false;
    bool success_ = false;
    std::string summary_;
    double total_time_ms_ = 0.0;
};

}  // namespace resolvex
