#include "cache.hpp"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <tuple>
#include <unistd.h>

namespace resolvex {

bool CacheKey::operator<(const CacheKey& o) const {
    return std::tie(name, type, cls, server) < std::tie(o.name, o.type, o.cls, o.server);
}

bool CacheKey::operator==(const CacheKey& o) const {
    return std::tie(name, type, cls, server) == std::tie(o.name, o.type, o.cls, o.server);
}

DnsCache::DnsCache(std::size_t max_entries, ClockFn clock)
    : max_entries_(max_entries == 0 ? 1 : max_entries),
      clock_(clock ? std::move(clock) : ClockFn([] { return Clock::now(); })) {}

std::size_t DnsCache::size() const {
    return entries_.size();
}

void DnsCache::clear() {
    entries_.clear();
}

bool DnsCache::lookup(const CacheKey& key, std::vector<ResourceRecord>& answers) {
    const auto it = entries_.find(key);
    if (it == entries_.end()) return false;

    const Clock::time_point now = clock_();
    if (now >= it->second.expires_at) {  // never serve expired data
        entries_.erase(it);
        return false;
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.stored_at).count();
    answers = it->second.answers;
    for (ResourceRecord& rr : answers) {
        const std::uint32_t used = static_cast<std::uint32_t>(std::min<long long>(elapsed, rr.ttl));
        rr.ttl -= used;  // show remaining TTL, not original
    }
    return true;
}

bool DnsCache::store(const CacheKey& key, const std::vector<ResourceRecord>& answers) {
    if (answers.empty()) return false;

    std::uint32_t min_ttl = answers.front().ttl;
    for (const ResourceRecord& rr : answers) min_ttl = std::min(min_ttl, rr.ttl);
    if (min_ttl == 0) return false;  // TTL 0 means "do not cache"

    const Clock::time_point now = clock_();
    if (entries_.find(key) == entries_.end()) make_room(now);

    Entry entry;
    entry.answers = answers;
    entry.stored_at = now;
    entry.expires_at = now + std::chrono::seconds(min_ttl);
    entries_[key] = std::move(entry);
    return true;
}

void DnsCache::purge_expired(Clock::time_point now) {
    for (auto it = entries_.begin(); it != entries_.end();) {
        it = (now >= it->second.expires_at) ? entries_.erase(it) : std::next(it);
    }
}

void DnsCache::make_room(Clock::time_point now) {
    if (entries_.size() < max_entries_) return;
    purge_expired(now);
    if (entries_.size() < max_entries_) return;

    // Still full: evict entry closest to expiring
    const auto victim = std::min_element(entries_.begin(), entries_.end(), [](const auto& a, const auto& b) {
        return a.second.expires_at < b.second.expires_at;
    });
    entries_.erase(victim);
}

std::vector<CachedEntryInfo> DnsCache::get_all_entries() {
    const Clock::time_point now = clock_();
    purge_expired(now);

    std::vector<CachedEntryInfo> list;
    list.reserve(entries_.size());

    for (const auto& pair : entries_) {
        CachedEntryInfo info;
        info.key = pair.first;
        info.answers = pair.second.answers;
        const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(pair.second.expires_at - now).count();
        info.remaining_ttl = remaining > 0 ? static_cast<std::uint32_t>(remaining) : 0;
        for (auto& rr : info.answers) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - pair.second.stored_at).count();
            const std::uint32_t used = static_cast<std::uint32_t>(std::min<long long>(elapsed, rr.ttl));
            rr.ttl -= used;
        }
        list.push_back(std::move(info));
    }
    return list;
}

std::string DnsCache::default_cache_path() {
    const char* env = std::getenv("RESOLVEX_CACHE");
    if (env && *env) return env;
    return ".resolvex.cache";
}

bool DnsCache::save_to_file(const std::string& path) {
    std::ofstream out(path, std::ios::trunc);
    if (!out.is_open()) return false;

    const Clock::time_point now = clock_();
    purge_expired(now);

    out << "# ResolveX Cache File v1\n";
    for (const auto& pair : entries_) {
        const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(pair.second.expires_at - now).count();
        if (remaining <= 0) continue;

        out << "ENTRY " << pair.first.name << " " << pair.first.type << " " << pair.first.cls << " "
            << (pair.first.server.empty() ? "-" : pair.first.server) << " " << remaining << " "
            << pair.second.answers.size() << "\n";

        for (const auto& rr : pair.second.answers) {
            out << "RR " << rr.name << " " << rr.type << " " << rr.cls << " " << rr.ttl << " "
                << rr.mx_preference << " " << rr.data << "\n";
        }
    }
    return true;
}

bool DnsCache::load_from_file(const std::string& path) {
    std::ifstream in(path);
    if (!in.is_open()) return false;

    std::string line;
    const Clock::time_point now = clock_();

    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::istringstream iss(line);
        std::string tag;
        iss >> tag;
        if (tag == "ENTRY") {
            CacheKey key;
            std::uint32_t remaining = 0;
            std::size_t count = 0;
            iss >> key.name >> key.type >> key.cls >> key.server >> remaining >> count;
            if (key.server == "-") key.server = "";

            if (remaining == 0) continue;

            std::vector<ResourceRecord> rrs;
            for (std::size_t i = 0; i < count; ++i) {
                if (!std::getline(in, line)) break;
                std::istringstream rr_iss(line);
                std::string rr_tag;
                rr_iss >> rr_tag;
                if (rr_tag != "RR") break;

                ResourceRecord rr;
                rr_iss >> rr.name >> rr.type >> rr.cls >> rr.ttl >> rr.mx_preference;
                std::getline(rr_iss >> std::ws, rr.data);
                rrs.push_back(std::move(rr));
            }

            if (rrs.size() == count) {
                Entry entry;
                entry.answers = std::move(rrs);
                entry.stored_at = now;
                entry.expires_at = now + std::chrono::seconds(remaining);
                entries_[key] = std::move(entry);
            }
        }
    }
    return true;
}

}  // namespace resolvex
