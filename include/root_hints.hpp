#pragma once

#include <string>
#include <vector>

namespace resolvex {

struct RootServer {
    std::string name;
    std::vector<std::string> ipv4;
    std::vector<std::string> ipv6;
};

class RootHints {
public:
    RootHints();

    // Loads root hints from a file in standard BIND/named.root format.
    // Throws std::runtime_error on file read error or syntax error if required.
    bool load_from_file(const std::string& path);
    bool load_from_string(const std::string& content);

    // Returns candidate IP addresses (IPv4 and optionally IPv6), randomized
    // or shuffled to distribute load across root nameservers.
    std::vector<std::string> get_candidate_ips(bool prefer_ipv4 = true) const;

    // All loaded root servers
    const std::vector<RootServer>& servers() const { return servers_; }
    std::size_t server_count() const { return servers_.size(); }
    std::size_t total_ip_count() const;

    const std::string& source_path() const { return source_path_; }

    // Locate default root.hints path searching current directory, parent dirs, etc.
    static std::string find_default_hints_file();

private:
    void populate_defaults();
    void parse_lines(std::istream& stream);

    std::vector<RootServer> servers_;
    std::string source_path_;
};

}  // namespace resolvex
