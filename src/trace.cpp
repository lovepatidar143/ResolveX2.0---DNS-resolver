#include "trace.hpp"

#include <iomanip>
#include <sstream>

namespace resolvex {

void TraceCollector::start_query(const std::string& domain, RecordType type) {
    query_domain_ = domain;
    query_type_ = type;
    steps_.clear();
    cache_hit_ = false;
    success_ = false;
    summary_.clear();
    total_time_ms_ = 0.0;
}

void TraceCollector::record_step(TraceStep step) {
    step.step_number = steps_.size() + 1;
    steps_.push_back(std::move(step));
}

void TraceCollector::record_cache_hit(const std::string& domain, RecordType type, double latency_ms) {
    query_domain_ = domain;
    query_type_ = type;
    cache_hit_ = true;
    total_time_ms_ = latency_ms;
}

void TraceCollector::finish(bool success, const std::string& summary_message, double total_elapsed_ms) {
    success_ = success;
    summary_ = summary_message;
    total_time_ms_ = total_elapsed_ms;
}

void TraceCollector::print_trace(std::ostream& out) const {
    out << "ResolveX 2.0 — Iterative DNS Resolver\n"
        << "Query: " << query_domain_ << "\n"
        << "Type:  " << record_type_name(static_cast<std::uint16_t>(query_type_)) << "\n"
        << "Mode:  Iterative\n";

    if (cache_hit_) {
        out << "[Cache] HIT\n"
            << "    Served directly from in-memory TTL cache (" << std::fixed << std::setprecision(2)
            << total_time_ms_ << " ms)\n";
        return;
    }

    for (const auto& s : steps_) {
        out << "[" << s.step_number << "] " << s.stage_name << "\n"
            << "    Server:    " << s.server.to_string() << " (" << s.transport_protocol << ")\n"
            << "    Query:     " << s.query_name << " " << record_type_name(static_cast<std::uint16_t>(s.query_type)) << "\n"
            << "    Response:  " << s.response_classification << " (RCODE: " << rcode_message(s.rcode) << ")\n";

        if (!s.delegated_zone.empty()) {
            out << "    Delegation: " << s.delegated_zone << "\n";
        }
        if (!s.nameservers.empty()) {
            out << "    Nameservers: ";
            for (std::size_t i = 0; i < s.nameservers.size(); ++i) {
                out << (i == 0 ? "" : ", ") << s.nameservers[i];
                if (i >= 3 && s.nameservers.size() > 4) {
                    out << " (+" << (s.nameservers.size() - i - 1) << " more)";
                    break;
                }
            }
            out << "\n";
        }
        if (!s.glue_ips.empty()) {
            out << "    Glue IPs:    ";
            for (std::size_t i = 0; i < s.glue_ips.size(); ++i) {
                out << (i == 0 ? "" : ", ") << s.glue_ips[i];
                if (i >= 3 && s.glue_ips.size() > 4) {
                    out << " (+" << (s.glue_ips.size() - i - 1) << " more)";
                    break;
                }
            }
            out << "\n";
        }
        if (s.retry) {
            out << "    Status:    RETRY (previous server failed or timed out)\n";
        }
        if (!s.detail.empty()) {
            out << "    Detail:    " << s.detail << "\n";
        }
        out << "    Latency:   " << std::fixed << std::setprecision(2) << s.latency_ms << " ms\n";
    }

    out << "TRACE SUMMARY\n"
        << "    Queries sent: " << steps_.size() << "\n"
        << "    Elapsed time: " << std::fixed << std::setprecision(2) << total_time_ms_ << " ms\n";
}

void TraceCollector::print_json(std::ostream& out) const {
    out << "{\n"
        << "  \"query\": \"" << query_domain_ << "\",\n"
        << "  \"type\": \"" << record_type_name(static_cast<std::uint16_t>(query_type_)) << "\",\n"
        << "  \"cache_hit\": " << (cache_hit_ ? "true" : "false") << ",\n"
        << "  \"success\": " << (success_ ? "true" : "false") << ",\n"
        << "  \"queries_sent\": " << steps_.size() << ",\n"
        << "  \"total_time_ms\": " << std::fixed << std::setprecision(2) << total_time_ms_ << ",\n"
        << "  \"steps\": [\n";

    for (std::size_t i = 0; i < steps_.size(); ++i) {
        const auto& s = steps_[i];
        out << "    {\n"
            << "      \"step\": " << s.step_number << ",\n"
            << "      \"stage\": \"" << s.stage_name << "\",\n"
            << "      \"server\": \"" << s.server.to_string() << "\",\n"
            << "      \"query_name\": \"" << s.query_name << "\",\n"
            << "      \"query_type\": \"" << record_type_name(static_cast<std::uint16_t>(s.query_type)) << "\",\n"
            << "      \"protocol\": \"" << s.transport_protocol << "\",\n"
            << "      \"classification\": \"" << s.response_classification << "\",\n"
            << "      \"rcode\": " << static_cast<int>(s.rcode) << ",\n"
            << "      \"delegated_zone\": \"" << s.delegated_zone << "\",\n"
            << "      \"latency_ms\": " << std::fixed << std::setprecision(2) << s.latency_ms << "\n"
            << "    }" << (i + 1 < steps_.size() ? "," : "") << "\n";
    }
    out << "  ]\n}\n";
}

}  // namespace resolvex
