// cache.cpp - bounded in-memory TTL cache for validated positive DNS answers.
#include "dns.hpp"

#include <algorithm>
#include <tuple>

namespace resolvex {

bool CacheKey::operator<(const CacheKey& o) const {
    return std::tie(name, type, cls, server) < std::tie(o.name, o.type, o.cls, o.server);
}

DnsCache::DnsCache(std::size_t max_entries, ClockFn clock)
    : max_entries_(max_entries == 0 ? 1 : max_entries),
      clock_(clock ? std::move(clock) : ClockFn([] { return Clock::now(); })) {}

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
        rr.ttl -= used;  // show remaining TTL, not the original
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

    // Still full: evict the entry closest to expiring (it has the least value left).
    const auto victim = std::min_element(entries_.begin(), entries_.end(), [](const auto& a, const auto& b) {
        return a.second.expires_at < b.second.expires_at;
    });
    entries_.erase(victim);
}

}  // namespace resolvex
