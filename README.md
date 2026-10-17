# ResolveX

A small command-line DNS resolver written in C++17. It builds DNS queries and parses
responses **by hand** (no DNS libraries, no `getaddrinfo()` for the queried name) and
talks to an upstream server over UDP using POSIX sockets. Portable to macOS and Linux.

```
ResolveX/
├── include/dns.hpp      single header: all types and interfaces
├── src/dns.cpp          DNS wire format: encode query, parse response (no sockets)
├── src/resolver.cpp     UDP transport + query orchestration (cache, stats)
├── src/cache.cpp        bounded in-memory TTL cache
├── src/main.cpp         CLI, output formatting, offline test suite
├── CMakeLists.txt
└── .gitignore
```

## Build

Requires a C++17 compiler and CMake >= 3.10.

```sh
mkdir build
cd build
cmake ..
cmake --build .
```

This produces `build/resolvex`. Build is warning-free with `-Wall -Wextra -Wpedantic`
(GCC 13 on Ubuntu 24.04 was the only compiler I could try; see "Verification status").

## Usage

Run from the `build` directory:

```sh
./resolvex google.com                        # A record via 1.1.1.1
./resolvex google.com --type AAAA            # A, AAAA, CNAME, MX, NS
./resolvex google.com --type MX --server 8.8.8.8
./resolvex stats
./resolvex --help
```

Other options: `--port N`, `--timeout MS` (default 3000), `--repeat N` and `--delay MS`
(run the same query N times in one process; useful for watching the cache).
`--type=MX` and `-t MX` also work. Typographic dashes (`–type`) are accepted too.
`--server` takes an IPv4 address only.

Exit codes: `0` success (including "no data"), `1` query failed, `2` usage error.

Example output (from a local test server, not a public one):

```
Domain:   ok.test
Type:     MX
Server:   127.0.0.1:5353
Status:   OK - NOERROR
Cache:    CACHE MISS
Latency:  0.83 ms
Records (2):
  ok.test.                    MX     TTL 3      pref 10  mail.ok.test
  ok.test.                    MX     TTL 3      pref 20  backup.net
```

## Tests

```sh
./resolvex test        # from build/
ctest                  # same suite via CTest
```

The suite is built into `main.cpp` (no extra files) and needs **no network**. It uses
synthetic packets for: query encoding, header parsing, compressed names (including
pointer loops and forward pointers), A/AAAA/MX/CNAME/NS parsing, malformed-packet
rejection, transaction-ID mismatch, truncation flag, RCODE messages, TTL expiry and
remaining-TTL (via an injectable fake clock), cache hit/miss, bounded eviction, and a
resolver cache-hit path that never touches the network.

## Design notes

* **Layers.** `dns.cpp` only converts bytes <-> structs. `resolver.cpp` only moves bytes
  (an RAII `UdpSocket`) and decides what a parsed result means. `cache.cpp` knows nothing
  about sockets.
* **Safety.** Every read goes through a bounds check (`require`). Compression pointers
  must point strictly backwards, which makes loops impossible. Name length (255) and
  label length (63) are enforced. Names from the network are escaped before printing.
  Malformed packets raise `DnsError`; nothing in the parser reads out of bounds.
* **Transaction IDs** are random (`std::random_device`). The receive loop discards any
  packet that is not from the queried IP *and* port, or whose ID differs, then keeps
  waiting until the deadline. The parser additionally re-checks the ID, the QR bit and
  that the echoed question matches what was asked.
* **Cache.** Key = (normalized name, type, class, `ip:port` of upstream). Only a
  NOERROR, non-truncated response with at least one answer and minimum TTL > 0 is stored.
  Entry lifetime is the smallest TTL in the answer set. Lookups return the *remaining*
  TTL. Expired entries are never served. Capacity is 256 entries; when full, expired
  entries are dropped first, then the entry closest to expiry. NXDOMAIN, SERVFAIL,
  timeouts, malformed and truncated responses are never cached (no negative caching).
* **Statistics.** Total / successful / failed / cache hits / cache misses / average
  latency (averaged over *all* queries, so cache hits pull the average down). A
  NOERROR-with-no-records answer counts as successful. **Statistics are in memory only
  and do not persist across process restarts**, so `./resolvex stats` in a new process
  always shows zeros. Use `--repeat N` to see them accumulate within one run.

## Limitations

* UDP only. **No TCP fallback**: a response with the TC flag is reported as an error.
* Not recursive: it sends one query with RD set to an upstream recursive resolver and
  does not follow referrals. CNAME chains are shown as returned by the server, not chased.
* Not a server; each invocation is a short-lived process, so the cache only helps
  within one run (`--repeat`).
* IPv4 upstream only. ASCII domain names only (no IDN/punycode conversion).
* No EDNS0, so responses are limited to the classic 512 bytes by most servers.
* Only A, AAAA, CNAME, MX, NS are queryable; other record types in a response are
  shown as an opaque "unsupported type" line.
* No DNSSEC validation, no retries, no negative caching.
* A closed upstream port shows up as a timeout (an unconnected UDP socket does not
  reliably report ICMP port-unreachable).

## Verification status

What was actually run, and where (details in the hand-off report):

* Built with GCC 13.3 / CMake on Linux with no warnings; the offline suite passes
  (75 checks) both normally and under AddressSanitizer + UBSan.
* The network path was exercised against a **local fake DNS server** on 127.0.0.1
  (all five record types, NXDOMAIN/SERVFAIL/REFUSED, truncation, wrong-ID and
  wrong-port packets, garbage, silence, cache hit/remaining-TTL/expiry).
* **Real public DNS was not verified**: the development sandbox intercepts all UDP/53
  traffic and answers NXDOMAIN to everything, so run `./resolvex google.com` yourself.
* **macOS was not tested** (no Mac available); the code uses only POSIX APIs
  (`poll`, `sendto`, `recvfrom`, `inet_pton`) and sets `sin_len` on Apple platforms.
