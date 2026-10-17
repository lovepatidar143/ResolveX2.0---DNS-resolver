#include "root_hints.hpp"

#include <algorithm>
#include <fstream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <unistd.h>

namespace resolvex {

namespace {

std::string clean_name(std::string s) {
    if (!s.empty() && s.back() == '.') s.pop_back();
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

}  // namespace

RootHints::RootHints() {
    populate_defaults();
}

std::size_t RootHints::total_ip_count() const {
    std::size_t count = 0;
    for (const auto& s : servers_) {
        count += s.ipv4.size() + s.ipv6.size();
    }
    return count;
}

void RootHints::populate_defaults() {
    servers_ = {
        {"a.root-servers.net", {"198.41.0.4"}, {"2001:503:ba3e::2:30"}},
        {"b.root-servers.net", {"170.247.170.2"}, {"2801:1b8:10::b"}},
        {"c.root-servers.net", {"192.33.4.12"}, {"2001:500:2::c"}},
        {"d.root-servers.net", {"199.7.91.13"}, {"2001:500:2d::d"}},
        {"e.root-servers.net", {"192.203.230.10"}, {"2001:500:a8::e"}},
        {"f.root-servers.net", {"192.5.5.241"}, {"2001:500:2f::f"}},
        {"g.root-servers.net", {"192.112.36.4"}, {"2001:500:12::d0d"}},
        {"h.root-servers.net", {"198.97.190.53"}, {"2001:500:1::53"}},
        {"i.root-servers.net", {"192.36.148.17"}, {"2001:7fe::53"}},
        {"j.root-servers.net", {"192.58.128.30"}, {"2001:503:c27::2:30"}},
        {"k.root-servers.net", {"193.0.14.129"}, {"2001:7fd::1"}},
        {"l.root-servers.net", {"199.7.83.42"}, {"2001:500:9f::42"}},
        {"m.root-servers.net", {"202.12.27.33"}, {"2001:dc3::35"}}
    };
    source_path_ = "<built-in authoritative defaults>";
}

void RootHints::parse_lines(std::istream& stream) {
    std::string line;
    std::vector<RootServer> loaded_servers;

    auto find_or_add_server = [&](const std::string& name) -> RootServer& {
        const std::string norm = clean_name(name);
        for (auto& s : loaded_servers) {
            if (s.name == norm) return s;
        }
        loaded_servers.push_back({norm, {}, {}});
        return loaded_servers.back();
    };

    while (std::getline(stream, line)) {
        // Strip comments
        const auto comment_pos = line.find_first_of(";#");
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }

        std::istringstream iss(line);
        std::vector<std::string> tokens;
        std::string token;
        while (iss >> token) tokens.push_back(token);

        if (tokens.size() < 3) continue;

        // Check if token matches NS, A, or AAAA
        // Examples:
        // . 3600000 NS A.ROOT-SERVERS.NET.
        // A.ROOT-SERVERS.NET. 3600000 A 198.41.0.4
        // A.ROOT-SERVERS.NET. A 198.41.0.4
        std::string owner = tokens[0];
        std::string rtype;
        std::string rdata;

        for (std::size_t i = 1; i < tokens.size(); ++i) {
            std::string t = tokens[i];
            std::transform(t.begin(), t.end(), t.begin(), [](unsigned char c) { return std::toupper(c); });
            if (t == "A" || t == "AAAA" || t == "NS") {
                rtype = t;
                if (i + 1 < tokens.size()) {
                    rdata = tokens[i + 1];
                }
                break;
            }
        }

        if (rtype == "NS" && !rdata.empty()) {
            find_or_add_server(rdata);
        } else if (rtype == "A" && !rdata.empty()) {
            auto& s = find_or_add_server(owner);
            if (std::find(s.ipv4.begin(), s.ipv4.end(), rdata) == s.ipv4.end()) {
                s.ipv4.push_back(rdata);
            }
        } else if (rtype == "AAAA" && !rdata.empty()) {
            auto& s = find_or_add_server(owner);
            if (std::find(s.ipv6.begin(), s.ipv6.end(), rdata) == s.ipv6.end()) {
                s.ipv6.push_back(rdata);
            }
        }
    }

    if (!loaded_servers.empty()) {
        servers_ = std::move(loaded_servers);
    }
}

bool RootHints::load_from_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return false;
    }
    parse_lines(file);
    source_path_ = path;
    return !servers_.empty();
}

bool RootHints::load_from_string(const std::string& content) {
    std::istringstream iss(content);
    parse_lines(iss);
    source_path_ = "<string>";
    return !servers_.empty();
}

std::vector<std::string> RootHints::get_candidate_ips(bool prefer_ipv4) const {
    std::vector<std::string> v4;
    std::vector<std::string> v6;
    for (const auto& s : servers_) {
        for (const auto& ip : s.ipv4) v4.push_back(ip);
        for (const auto& ip : s.ipv6) v6.push_back(ip);
    }

    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(v4.begin(), v4.end(), g);
    std::shuffle(v6.begin(), v6.end(), g);

    std::vector<std::string> ips;
    if (prefer_ipv4) {
        ips.insert(ips.end(), v4.begin(), v4.end());
        ips.insert(ips.end(), v6.begin(), v6.end());
    } else {
        ips.insert(ips.end(), v6.begin(), v6.end());
        ips.insert(ips.end(), v4.begin(), v4.end());
    }
    return ips;
}

std::string RootHints::find_default_hints_file() {
    const char* candidates[] = {
        "config/root.hints",
        "../config/root.hints",
        "../../config/root.hints",
        "/etc/resolvex/root.hints"
    };
    for (const char* path : candidates) {
        if (::access(path, R_OK) == 0) {
            return path;
        }
    }
    return "";
}

}  // namespace resolvex
