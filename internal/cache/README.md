# Cache Package

High-performance DNS cache with TTL, negative caching, stale serving, and NSEC aggressive caching.

## Overview

Thread-safe in-memory LRU cache designed for DNS workloads with support for RFC 8198 aggressive negative caching and RFC 8767 stale serving.

## Key Features

- **TTL-based expiration** with configurable min/max/default
- **Negative caching** (RFC 2308) for NXDOMAIN responses
- **Serve-stale** (RFC 8767) when upstream is unavailable
- **NSEC aggressive caching** (RFC 8198) for synthesized NXDOMAIN
- **Prefetching** popular domains nearing expiration
- **Cluster cache invalidation** via callback
- **Memory pressure response** via `CacheEvictor`

## Cache Entry Structure

```go
type entry struct {
    key       string
    msg       *Message        // Cached response
    size      int             // Memory size
    expiresAt time.Time       // TTL expiration
    staleAt   time.Time       // When to start serving stale
    prefetch  bool            // Eligible for prefetch
}
```

## Cache Key Design

```
qname|qtype|qclass|doBit
```

The DO (DNSSEC OK) bit is included in the key to fix VULN-060 — this prevents DNSSEC-aware clients from receiving non-DNSSEC responses.

## Configuration

```go
type Config struct {
    Size              int           // Max entries (default: 10000)
    MinTTL            time.Duration // Minimum TTL (default: 5min)
    MaxTTL            time.Duration // Maximum TTL (default: 24h)
    DefaultTTL        time.Duration // Default TTL (default: 1h)
    NegativeTTL       time.Duration // NXDOMAIN cache (default: 1min)
    Prefetch          bool          // Enable prefetch (default: true)
    PrefetchThreshold time.Duration // Prefetch trigger (default: 8h before expiry)
    ServeStale        bool          // Serve stale on failure (default: true)
    ServeStaleTTL     time.Duration // Max stale duration (default: 7 days)
}
```

## Core Methods

### Get

```go
func (c *Cache) Get(qname string, qtype uint16, qclass uint16, doBit uint8) (*Message, bool)
```

Returns cached response if fresh. Checks both positive and negative cache.

### Set

```go
func (c *Cache) Set(qname string, qtype uint16, qclass uint16, doBit uint8, msg *Message, minTTL time.Duration)
```

Stores response with calculated TTL (clamped to Min/Max TTL).

### Invalidate

```go
func (c *Cache) Invalidate(qname string, qtype uint16)
```

Removes specific entry. Called on zone updates or cluster cache sync.

## NSEC Aggressive Cache

RFC 8198 allows synthesizing NXDOMAIN from cached NSEC records:

1. Cache NSEC records from negative responses
2. When looking up non-existent names, check if NSEC covers the name
3. If so, synthesize NXDOMAIN immediately without upstream query

**Implementation**: `cache/nsec.go`

```go
type NSECCache struct {
    cache *Cache
    tree  *radix.Tree // Fast NSEC range lookups
}
```

## Stale Serving

RFC 8767 allows serving expired cache entries when upstream fails:

1. Entry expires → moves to "stale" state
2. Upstream fails → serve stale if within `ServeStaleTTL`
3. Background refresh on next request

**Implementation**: `cache/stale.go`

## Memory Management

### Monitor

```go
type Monitor struct {
    Threshold float64  // 0.0-1.0, evict at this memory usage
    Evictor   *CacheEvictor
}
```

### Evictor

When memory pressure detected, `CacheEvictor`:
1. Calculates how much memory to free
2. Evicts entries with lowest access time
3. Respects minimum TTL for hot entries

## Persistence

Cache can persist to JSON for warming on restart:

```go
type persistence struct {
    path     string
    interval time.Duration
    atomic   bool  // Atomic rename on write
}
```

## Statistics

```go
type Stats struct {
    Hits       uint64
    Misses     uint64
    Size       int
    Capacity   int
    Evictions  uint64
    StaleHits  uint64
}
```

Exposed via `cache.Stats()` and API endpoint `/api/v1/cache/stats`.

## Thread Safety

Uses Go's `sync.Map` for concurrent access:
- Read-heavy workload optimization
- Lock-free reads
- Write synchronization via `sync.Mutex` in stats