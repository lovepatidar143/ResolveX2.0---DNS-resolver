#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "dns.hpp"

namespace resolvex {

using Clock = std::chrono::steady_clock;
using ClockFn = std::function<Clock::time_point()>;

struct CacheKey {
    std::string name;    // normalized domain
    std::uint16_t type = 1;  // query type
    std::uint16_t cls = kClassIN;   // query class
    std::string server = "";  // optional server label for backward compatibility

    bool operator<(const CacheKey& o) const;
    bool operator==(const CacheKey& o) const;
};

struct CachedEntryInfo {
    CacheKey key;
    std::vector<ResourceRecord> answers;
    std::uint32_t remaining_ttl = 0;
};

// Bounded TTL cache. Eviction: when full, drop expired entries first,
// then the entry that would expire soonest.
class DnsCache {
public:
    explicit DnsCache(std::size_t max_entries = 512, ClockFn clock = nullptr);

    // On hit, fills `answers` with records whose TTL is the *remaining* TTL.
    bool lookup(const CacheKey& key, std::vector<ResourceRecord>& answers);

    // Stores answers. Returns false if answers is empty or smallest TTL is zero.
    bool store(const CacheKey& key, const std::vector<ResourceRecord>& answers);

    // Clears all in-memory entries
    void clear();

    std::size_t size() const;
    std::size_t max_entries() const { return max_entries_; }

    // Returns a snapshot of all active (non-expired) cached entries
    std::vector<CachedEntryInfo> get_all_entries();

    // Persistence to disk for cross-invocation caching and `./resolvex cache` commands
    bool save_to_file(const std::string& path);
    bool load_from_file(const std::string& path);

    static std::string default_cache_path();

private:
    struct Entry {
        std::vector<ResourceRecord> answers;
        Clock::time_point stored_at;
        Clock::time_point expires_at;
    };

    void purge_expired(Clock::time_point now);
    void make_room(Clock::time_point now);

    std::size_t max_entries_;
    ClockFn clock_;
    std::map<CacheKey, Entry> entries_;
};

}  // namespace resolvex
