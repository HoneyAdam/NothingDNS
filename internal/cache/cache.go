package cache

import (
	"fmt"
	"hash/maphash"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// Entry represents a cached DNS response.
type Entry struct {
	// Query key
	Key string

	// Response message
	Message *protocol.Message

	// Response code (for negative caching)
	RCode uint8

	// TTL information
	TTL        uint32    // Original TTL from record
	ExpireTime time.Time // When this entry expires

	// Prefetch tracking
	CanPrefetch bool      // Whether this entry can be prefetched
	PrefetchDue time.Time // When prefetch should occur

	// Entry type
	IsNegative bool // True for NXDOMAIN/NODATA entries
	IsStale    bool // True when serving a stale entry (RFC 8767)

	// touched is set atomically by Get on first access so that the very
	// first cache hit always promotes the entry to MRU. Subsequent hits use
	// probabilistic promotion (see Cache.Get).
	touched uint32

	// prefetchFired is flipped to 1 by Get the first time it triggers an
	// async prefetch for this entry (RFC-style cache refresh). Keeps us
	// from firing the same prefetch multiple times per entry as hits
	// continue to arrive in the PrefetchDue → ExpireTime window.
	prefetchFired uint32

	// Intrusive LRU list pointers (front = most recent, back = least recent)
	prev *Entry
	next *Entry
}

// IsExpired returns true if the entry has expired.
func (e *Entry) IsExpired(now time.Time) bool {
	return now.After(e.ExpireTime)
}

// ShouldPrefetch returns true if prefetch is due for this entry.
func (e *Entry) ShouldPrefetch(now time.Time) bool {
	if !e.CanPrefetch || e.IsNegative {
		return false
	}
	return now.After(e.PrefetchDue)
}

// RemainingTTL returns the remaining TTL for this entry in seconds.
func (e *Entry) RemainingTTL(now time.Time) uint32 {
	if e.IsExpired(now) {
		return 0
	}
	remaining := e.ExpireTime.Sub(now)
	if remaining < 0 {
		return 0
	}
	return uint32(remaining.Seconds())
}

// Stats tracks cache statistics. Numeric counters are accessed atomically.
type Stats struct {
	Hits        uint64
	Misses      uint64
	Evictions   uint64
	Expirations uint64
	StaleServed uint64
	Size        int
	Capacity    int
}

// HitRate returns the cache hit rate as a percentage.
func (s *Stats) HitRate() float64 {
	total := s.Hits + s.Misses
	if total == 0 {
		return 0
	}
	return float64(s.Hits) / float64(total) * 100
}

// HitRatio returns the cache hit ratio (alias for HitRate).
func (s *Stats) HitRatio() float64 {
	return s.HitRate()
}

// numShards is the number of independent cache shards. A power of two so
// shard selection reduces to a bitmask. 16 is a sweet spot: enough to
// distribute contention across many cores without bloating per-shard
// metadata or under-utilising small caches.
const numShards = 16

const shardMask uint64 = numShards - 1

// lruPromoteMask gates probabilistic LRU promotion on cache hits. With mask
// 0x0F roughly 1-in-16 hits acquire the write lock to call moveToFront; the
// other 15 stay under RLock and return without serializing on the shard.
// The first hit on each entry always promotes (see Cache.Get) so freshly
// cached items still reach MRU exactly once before sampling kicks in.
const lruPromoteMask uint64 = 0x0F

// shardSeed randomises shard distribution per process; defends against
// adversarial keys engineered to all collide in one shard.
var shardSeed = maphash.MakeSeed()

// cacheShard holds a subset of the cache's entries protected by its own
// RWMutex. Sharding spreads contention across numShards independent locks
// so different keys do not serialise on a single global mutex.
type cacheShard struct {
	mu       sync.RWMutex
	entries  map[string]*Entry
	lruFront *Entry
	lruBack  *Entry
	capacity int

	// Per-shard stat counters; summed by Cache.Stats. Keeping them local to
	// the shard avoids cross-shard cache-line bouncing on every hit.
	hits        uint64
	misses      uint64
	evictions   uint64
	expirations uint64
	staleServed uint64
}

// Cache is a sharded, thread-safe DNS cache with LRU eviction per shard.
type Cache struct {
	shards [numShards]cacheShard

	// Configuration. Reads are lock-free (simple value types, mirroring the
	// pre-sharding design); UpdateConfig serialises writes via cfgMu.
	cfgMu             sync.Mutex
	capacity          int
	minTTL            time.Duration
	maxTTL            time.Duration
	defaultTTL        time.Duration
	negativeTTL       time.Duration
	prefetchEnabled   bool
	prefetchThreshold time.Duration
	serveStale        bool
	staleGrace        time.Duration

	// Callbacks
	callbackMu     sync.Mutex
	prefetchFunc   func(key string, qtype uint16)
	invalidateFunc func(key string)
}

// shardOf returns the shard responsible for the given key.
func (c *Cache) shardOf(key string) *cacheShard {
	return &c.shards[maphash.String(shardSeed, key)&shardMask]
}

// Config holds cache configuration.
type Config struct {
	Capacity          int
	MinTTL            time.Duration
	MaxTTL            time.Duration
	DefaultTTL        time.Duration
	NegativeTTL       time.Duration
	PrefetchEnabled   bool
	PrefetchThreshold time.Duration
	ServeStale        bool          // RFC 8767: serve stale entries when upstream fails
	StaleGrace        time.Duration // How long past expiry to keep stale entries
}

// DefaultConfig returns the default cache configuration.
func DefaultConfig() Config {
	return Config{
		Capacity:          10000,
		MinTTL:            5 * time.Second,
		MaxTTL:            24 * time.Hour,
		DefaultTTL:        5 * time.Minute,
		NegativeTTL:       60 * time.Second,
		PrefetchEnabled:   false,
		PrefetchThreshold: 60 * time.Second,
		ServeStale:        false,
		StaleGrace:        24 * time.Hour, // RFC 8767 recommends at least 1-3 days
	}
}

// New creates a new sharded DNS cache with the given configuration.
func New(config Config) *Cache {
	c := &Cache{
		capacity:          config.Capacity,
		minTTL:            config.MinTTL,
		maxTTL:            config.MaxTTL,
		defaultTTL:        config.DefaultTTL,
		negativeTTL:       config.NegativeTTL,
		prefetchEnabled:   config.PrefetchEnabled,
		prefetchThreshold: config.PrefetchThreshold,
		serveStale:        config.ServeStale,
		staleGrace:        config.StaleGrace,
	}

	perShard := perShardCapacity(config.Capacity)
	for i := range c.shards {
		c.shards[i].entries = make(map[string]*Entry, perShard)
		c.shards[i].capacity = perShard
	}
	return c
}

// perShardCapacity divides total capacity across shards, rounding up so the
// total never falls below the requested value. Always at least 1.
func perShardCapacity(total int) int {
	per := (total + numShards - 1) / numShards
	if per < 1 {
		per = 1
	}
	return per
}

// MakeKey creates a cache key from query name, type, and DNSSEC DO bit.
// VULN-060: DO bit included so DNSSEC and plain responses don't share cache entries.
//
// SECURITY: Domain names longer than maxKeyNameLen are hashed to prevent
// cache key DoS attacks where an attacker floods the cache with unique
// long domain names.
func MakeKey(name string, qtype uint16, doBit bool) string {
	const maxKeyNameLen = 128 // Maximum domain name length before hashing

	var b strings.Builder
	b.Grow(len(name) + 1 + 6 + 1 + 1)

	if len(name) > maxKeyNameLen {
		// Hash long domain names to prevent cache flooding
		h := crc32Hash(name)
		b.WriteString(strconv.FormatUint(h, 10))
	} else {
		// RFC 1035 §2.3.3: domain names are case-insensitive. Lower-case here
		// so that "Example.com" and "example.com" share a single cache entry
		// and an attacker cannot inflate the working-set with case-randomised
		// duplicates.
		for i := 0; i < len(name); i++ {
			c := name[i]
			if c >= 'A' && c <= 'Z' {
				c |= 0x20
			}
			b.WriteByte(c)
		}
	}

	// Use '|' as a field separator: DNS names cannot contain it on the wire
	// or in zone files, so it is unambiguous. This avoids the last-colon
	// confusion that broke ExtractQueryInfo when the DO-bit suffix was added.
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(uint64(qtype), 10))
	b.WriteByte('|')
	if doBit {
		b.WriteByte('1')
	} else {
		b.WriteByte('0')
	}
	return b.String()
}

// crc32Hash returns a CRC32 hash of the input string as uint64.
func crc32Hash(s string) uint64 {
	h := uint64(0)
	for i := 0; i < len(s); i++ {
		h = h*31 + uint64(s[i])
	}
	return h
}

// Get retrieves an entry from the cache.
// Returns nil if not found or expired.
// Uses RLock for the read-only fast path; promotion to MRU is probabilistic
// so the write lock is rarely taken on the hot path.
func (c *Cache) Get(key string) *Entry {
	s := c.shardOf(key)

	// Fast path: read-only lookup under shard RLock.
	s.mu.RLock()
	entry, exists := s.entries[key]
	if !exists {
		s.mu.RUnlock()
		atomic.AddUint64(&s.misses, 1)
		return nil
	}

	now := time.Now()
	if entry.IsExpired(now) {
		s.mu.RUnlock()
		// Slow path: remove expired entry under exclusive lock.
		s.mu.Lock()
		// Re-verify the same entry is still there (may have changed).
		if e, ok := s.entries[key]; ok && e == entry {
			if c.serveStale {
				staleDeadline := entry.ExpireTime.Add(c.staleGrace)
				if now.After(staleDeadline) {
					s.removeEntry(entry)
				}
			} else {
				s.removeEntry(entry)
			}
			atomic.AddUint64(&s.expirations, 1)
		}
		atomic.AddUint64(&s.misses, 1)
		s.mu.Unlock()
		return nil
	}

	// Entry is valid. Probabilistic LRU promotion: skip the write lock on
	// most hits to avoid serializing the hot path. The first Get of a fresh
	// entry always promotes (CAS gate) so newly cached items reach MRU
	// before sampling applies.
	s.mu.RUnlock()
	hits := atomic.AddUint64(&s.hits, 1)

	// Fire async prefetch once per entry when we cross PrefetchDue.
	// SetPrefetchFunc has been wired since forever but nothing was
	// actually invoking it, so the prefetch feature was dead. The check
	// has to happen *before* the LRU-promotion early-return below,
	// otherwise probabilistic promotion (`hits & lruPromoteMask`) would
	// drop us back to the caller without ever firing prefetch on a hot
	// entry. We extract qtype from the cached message's question section
	// so the callback can re-resolve without re-parsing the key encoding.
	//
	// Snapshot c.prefetchFunc under c.callbackMu — SetPrefetchFunc
	// writes the field under that mutex, and the Delete/Invalidate
	// paths in this file already use this exact lock-snapshot pattern
	// for c.invalidateFunc. Reading the field unlocked was a data race
	// (per Go's memory model) even though no real-world caller swaps
	// the prefetch hook after startup. Use ShouldPrefetch first as a
	// cheap unlocked filter so we only pay the lock on entries that
	// actually crossed PrefetchDue.
	if entry.ShouldPrefetch(now) {
		c.callbackMu.Lock()
		fn := c.prefetchFunc
		c.callbackMu.Unlock()
		if fn != nil && atomic.CompareAndSwapUint32(&entry.prefetchFired, 0, 1) {
			qtype := uint16(0)
			if entry.Message != nil && len(entry.Message.Questions) > 0 {
				qtype = entry.Message.Questions[0].QType
			}
			go fn(key, qtype)
		}
	}

	firstTouch := atomic.CompareAndSwapUint32(&entry.touched, 0, 1)
	if !firstTouch && hits&lruPromoteMask != 0 {
		return entry
	}

	s.mu.Lock()
	// Verify entry is still in the map (could have been evicted).
	if _, ok := s.entries[key]; ok {
		s.moveToFront(entry)
	}
	s.mu.Unlock()

	return entry
}

// GetStale retrieves a stale (expired but within grace period) cache entry.
// Per RFC 8767, stale entries should only be served when the upstream is
// unavailable. Returns nil if no stale entry exists or serve-stale is disabled.
// The returned entry has IsStale=true and TTL set to 30s (RFC 8767 §4).
func (c *Cache) GetStale(key string) *Entry {
	if !c.serveStale {
		return nil
	}

	s := c.shardOf(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.entries[key]
	if !exists {
		return nil
	}

	now := time.Now()
	if !entry.IsExpired(now) {
		// Not expired — normal Get should be used
		return nil
	}

	// Check if within stale grace period
	staleDeadline := entry.ExpireTime.Add(c.staleGrace)
	if now.After(staleDeadline) {
		// Past stale grace — remove it
		s.removeEntry(entry)
		return nil
	}

	// Serve the stale entry with a short TTL (RFC 8767 §4 recommends 30s)
	s.moveToFront(entry)
	atomic.AddUint64(&s.staleServed, 1)

	staleEntry := &Entry{
		Key:        entry.Key,
		Message:    entry.Message,
		RCode:      entry.RCode,
		TTL:        30, // RFC 8767: stale TTL
		ExpireTime: entry.ExpireTime,
		IsNegative: entry.IsNegative,
		IsStale:    true,
	}
	return staleEntry
}

// StaleServed returns the count of stale entries served.
func (c *Cache) StaleServed() uint64 {
	var total uint64
	for i := range c.shards {
		total += atomic.LoadUint64(&c.shards[i].staleServed)
	}
	return total
}

// Set adds or updates an entry in the cache.
func (c *Cache) Set(key string, msg *protocol.Message, ttl uint32) {
	s := c.shardOf(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	c.setInternal(s, key, msg, ttl, false)
}

// SetNegative adds a negative cache entry (NXDOMAIN or NODATA).
func (c *Cache) SetNegative(key string, rcode uint8) {
	// Apply min/max TTL constraints to negative TTL.
	// maxTTL == 0 means "no upper bound" — only clamp when a positive ceiling
	// has been configured (otherwise zero-clamp expires the entry immediately).
	ttl := c.negativeTTL
	if ttl < c.minTTL {
		ttl = c.minTTL
	}
	if c.maxTTL > 0 && ttl > c.maxTTL {
		ttl = c.maxTTL
	}

	expireTime := time.Now().Add(ttl)

	entry := &Entry{
		Key:        key,
		RCode:      rcode,
		ExpireTime: expireTime,
		IsNegative: true,
	}

	s := c.shardOf(key)
	s.mu.Lock()
	s.addEntry(key, entry)
	s.mu.Unlock()
}

// setInternal adds or updates an entry with the given TTL. Must be called
// with the shard's mutex held.
func (c *Cache) setInternal(s *cacheShard, key string, msg *protocol.Message, ttl uint32, isPrefetch bool) {
	// Apply min/max TTL constraints.
	// maxTTL == 0 means "no upper bound" — only clamp when a positive ceiling
	// has been configured (otherwise zero-clamp expires the entry immediately).
	duration := time.Duration(ttl) * time.Second
	if duration < c.minTTL {
		duration = c.minTTL
	}
	if c.maxTTL > 0 && duration > c.maxTTL {
		duration = c.maxTTL
	}

	now := time.Now()
	expireTime := now.Add(duration)

	// Calculate prefetch time if enabled
	var prefetchDue time.Time
	canPrefetch := c.prefetchEnabled && !isPrefetch
	if canPrefetch {
		prefetchOffset := c.prefetchThreshold
		if duration > prefetchOffset {
			prefetchDue = expireTime.Add(-prefetchOffset)
		} else {
			canPrefetch = false
		}
	}

	entry := &Entry{
		Key:         key,
		Message:     msg,
		TTL:         ttl,
		ExpireTime:  expireTime,
		CanPrefetch: canPrefetch,
		PrefetchDue: prefetchDue,
		IsNegative:  false,
	}

	s.addEntry(key, entry)
}

// addEntry adds an entry to the shard, handling eviction if needed.
// Must be called with s.mu held for writing.
func (s *cacheShard) addEntry(key string, entry *Entry) {
	// Check if key already exists. If it does we're replacing the
	// value at this key, so the net entry count is unchanged — drop
	// the old map entry too BEFORE the eviction loop, otherwise the
	// loop sees len == capacity and evicts an unrelated victim every
	// time a hot entry refreshes (a steady stream of upstream-served
	// refreshes for the same name would silently churn through the
	// rest of the shard).
	if oldEntry, exists := s.entries[key]; exists {
		s.intrusiveRemove(oldEntry)
		delete(s.entries, key)
	}

	// Evict oldest entries if at capacity
	for len(s.entries) >= s.capacity {
		if !s.evictOldest() {
			break
		}
	}

	// Add to map and LRU list
	s.pushFront(entry)
	s.entries[key] = entry
}

// removeEntry removes an entry from the shard.
// Must be called with s.mu held for writing.
func (s *cacheShard) removeEntry(entry *Entry) {
	s.intrusiveRemove(entry)
	delete(s.entries, entry.Key)
}

// evictOldest removes the least recently used entry. Returns true if an
// entry was evicted, false if the LRU list was empty.
// Must be called with s.mu held for writing.
func (s *cacheShard) evictOldest() bool {
	if s.lruBack == nil {
		return false
	}
	entry := s.lruBack
	s.removeEntry(entry)
	atomic.AddUint64(&s.evictions, 1)
	return true
}

// pushFront inserts entry at the front of the LRU list (most recently used).
func (s *cacheShard) pushFront(entry *Entry) {
	entry.prev = nil
	entry.next = s.lruFront
	if s.lruFront != nil {
		s.lruFront.prev = entry
	}
	s.lruFront = entry
	if s.lruBack == nil {
		s.lruBack = entry
	}
}

// moveToFront moves an existing entry to the front of the LRU list.
func (s *cacheShard) moveToFront(entry *Entry) {
	if entry == s.lruFront {
		return // already at front
	}
	s.intrusiveRemove(entry)
	s.pushFront(entry)
}

// intrusiveRemove removes an entry from the intrusive LRU list.
func (s *cacheShard) intrusiveRemove(entry *Entry) {
	if entry.prev != nil {
		entry.prev.next = entry.next
	} else {
		s.lruFront = entry.next
	}
	if entry.next != nil {
		entry.next.prev = entry.prev
	} else {
		s.lruBack = entry.prev
	}
	entry.prev = nil
	entry.next = nil
}

// EvictPercent removes approximately percent of entries from each shard,
// starting with the least recently used entries.
func (c *Cache) EvictPercent(percent int) {
	if percent <= 0 || percent > 100 {
		return
	}

	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		count := len(s.entries) * percent / 100
		if count == 0 && len(s.entries) > 0 {
			count = 1 // Always evict at least one if shard has entries
		}
		for j := 0; j < count; j++ {
			if !s.evictOldest() {
				break
			}
		}
		s.mu.Unlock()
	}
}

// SetInvalidateFunc sets the callback function for cache invalidation.
func (c *Cache) SetInvalidateFunc(fn func(key string)) {
	c.callbackMu.Lock()
	c.invalidateFunc = fn
	c.callbackMu.Unlock()
}

// Delete removes an entry from the cache.
func (c *Cache) Delete(key string) {
	s := c.shardOf(key)
	s.mu.Lock()
	notify := false
	if entry, exists := s.entries[key]; exists {
		s.removeEntry(entry)
		notify = true
	}
	s.mu.Unlock()

	if notify {
		c.callbackMu.Lock()
		fn := c.invalidateFunc
		c.callbackMu.Unlock()
		if fn != nil {
			fn(key)
		}
	}
}

// Clear removes all entries from the cache.
func (c *Cache) Clear() {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		// Unlink all entries for GC
		for e := s.lruFront; e != nil; {
			next := e.next
			e.prev = nil
			e.next = nil
			e = next
		}
		s.entries = make(map[string]*Entry, s.capacity)
		s.lruFront = nil
		s.lruBack = nil
		s.mu.Unlock()
	}
}

// Flush is an alias for Clear.
func (c *Cache) Flush() {
	c.Clear()
}

// DeleteLocal removes an entry without triggering invalidation callback.
// Used when receiving invalidation from cluster to avoid broadcast loops.
func (c *Cache) DeleteLocal(key string) {
	s := c.shardOf(key)
	s.mu.Lock()
	if entry, exists := s.entries[key]; exists {
		s.removeEntry(entry)
	}
	s.mu.Unlock()
}

// Invalidate removes an entry and broadcasts invalidation to cluster.
func (c *Cache) Invalidate(key string) {
	c.Delete(key)
}

// InvalidatePattern removes entries matching a pattern and broadcasts invalidations.
// Pattern uses prefix matching (e.g., "example.com" matches "www.example.com:A")
func (c *Cache) InvalidatePattern(pattern string) []string {
	var invalidated []string

	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		for key := range s.entries {
			// Extract domain from key (format: "domain:type")
			domain, _ := ExtractQueryInfo(key)
			if strings.Contains(domain, pattern) || strings.HasSuffix(domain, pattern) {
				if entry, exists := s.entries[key]; exists {
					s.removeEntry(entry)
					invalidated = append(invalidated, key)
				}
			}
		}
		s.mu.Unlock()
	}

	if len(invalidated) > 0 {
		c.callbackMu.Lock()
		fn := c.invalidateFunc
		c.callbackMu.Unlock()
		if fn != nil {
			for _, key := range invalidated {
				fn(key)
			}
		}
	}
	return invalidated
}

// Stats returns a copy of the current cache statistics, summed across shards.
func (c *Cache) Stats() Stats {
	var hits, misses, evictions, expirations, staleServed uint64
	var size int
	for i := range c.shards {
		s := &c.shards[i]
		hits += atomic.LoadUint64(&s.hits)
		misses += atomic.LoadUint64(&s.misses)
		evictions += atomic.LoadUint64(&s.evictions)
		expirations += atomic.LoadUint64(&s.expirations)
		staleServed += atomic.LoadUint64(&s.staleServed)
		s.mu.RLock()
		size += len(s.entries)
		s.mu.RUnlock()
	}

	return Stats{
		Hits:        hits,
		Misses:      misses,
		Evictions:   evictions,
		Expirations: expirations,
		StaleServed: staleServed,
		Size:        size,
		Capacity:    c.capacity,
	}
}

// Size returns the current number of entries in the cache.
func (c *Cache) Size() int {
	var size int
	for i := range c.shards {
		c.shards[i].mu.RLock()
		size += len(c.shards[i].entries)
		c.shards[i].mu.RUnlock()
	}
	return size
}

// GetPrefetchable returns entries that are due for prefetching.
func (c *Cache) GetPrefetchable() []string {
	now := time.Now()
	var keys []string

	for i := range c.shards {
		s := &c.shards[i]
		s.mu.RLock()
		for _, entry := range s.entries {
			if entry.ShouldPrefetch(now) {
				keys = append(keys, entry.Key)
			}
		}
		s.mu.RUnlock()
	}

	return keys
}

// SetPrefetchFunc sets the callback function for prefetching.
func (c *Cache) SetPrefetchFunc(fn func(key string, qtype uint16)) {
	c.callbackMu.Lock()
	c.prefetchFunc = fn
	c.callbackMu.Unlock()
}

// UpdateConfig updates the runtime cache configuration.
// This allows changing cache behavior without restarting the server.
// GetConfig returns a snapshot of the cache's current runtime
// configuration. Used by callers that want to honor "patch
// semantics" — read current, modify, UpdateConfig — without
// reset-to-zero pitfalls on omitted fields. Locking matches the
// surrounding "reads are lock-free" pattern: take cfgMu just long
// enough to read each field, accepting that an in-flight
// UpdateConfig may interleave (the worst case is a snapshot
// mixing two configs, which is no worse than the existing
// lock-free read paths that already see the same possibility).
func (c *Cache) GetConfig() Config {
	c.cfgMu.Lock()
	defer c.cfgMu.Unlock()
	return Config{
		Capacity:          c.capacity,
		MinTTL:            c.minTTL,
		MaxTTL:            c.maxTTL,
		DefaultTTL:        c.defaultTTL,
		NegativeTTL:       c.negativeTTL,
		PrefetchEnabled:   c.prefetchEnabled,
		PrefetchThreshold: c.prefetchThreshold,
		ServeStale:        c.serveStale,
		StaleGrace:        c.staleGrace,
	}
}

func (c *Cache) UpdateConfig(cfg Config) {
	c.cfgMu.Lock()
	c.capacity = cfg.Capacity
	c.minTTL = cfg.MinTTL
	c.maxTTL = cfg.MaxTTL
	c.defaultTTL = cfg.DefaultTTL
	c.negativeTTL = cfg.NegativeTTL
	c.prefetchEnabled = cfg.PrefetchEnabled
	c.prefetchThreshold = cfg.PrefetchThreshold
	c.serveStale = cfg.ServeStale
	c.staleGrace = cfg.StaleGrace
	c.cfgMu.Unlock()

	perShard := perShardCapacity(cfg.Capacity)
	for i := range c.shards {
		c.shards[i].mu.Lock()
		c.shards[i].capacity = perShard
		c.shards[i].mu.Unlock()
	}
}

// OnPrefetchComplete marks a prefetch as complete and resets the prefetch flag.
func (c *Cache) OnPrefetchComplete(key string, msg *protocol.Message, ttl uint32) {
	s := c.shardOf(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update with new TTL but mark as prefetch to avoid infinite prefetch loop
	c.setInternal(s, key, msg, ttl, true)
}

// ExtractQueryInfo extracts the query name and type from a cache key.
// Returns empty values if the key format is unexpected.
func ExtractQueryInfo(key string) (string, uint16) {
	// Cache keys produced by MakeKey use the form "name|qtype|dobit" with '|'
	// separators. Split on the first two '|' characters: the first delimits
	// the name from the qtype, the second separates qtype from the DO bit
	// (which is discarded here — callers wanting it should parse the key
	// directly). Legacy ':' keys are no longer supported.
	first := strings.IndexByte(key, '|')
	if first < 0 {
		return "", 0
	}
	rest := key[first+1:]
	second := strings.IndexByte(rest, '|')
	var typeStr string
	if second < 0 {
		typeStr = rest
	} else {
		typeStr = rest[:second]
	}
	var qtype uint16
	if _, err := fmt.Sscanf(typeStr, "%d", &qtype); err != nil {
		return "", 0
	}
	return key[:first], qtype
}

// CacheEntryJSON is a JSON-serializable cache entry for persistence.
type CacheEntryJSON struct {
	Key        string    `json:"key"`
	WireBytes  []byte    `json:"wire"`
	TTL        uint32    `json:"ttl"`
	RCode      uint8     `json:"rcode"`
	IsNegative bool      `json:"negative"`
	ExpireTime time.Time `json:"expire_time"`
}

// Save returns a serializable snapshot of all non-negative cache entries.
// Negative entries are excluded because they have very short TTLs and
// add little value on restart. Only entries that have not yet expired are included.
func (c *Cache) Save() []CacheEntryJSON {
	now := time.Now()
	var entries []CacheEntryJSON

	for i := range c.shards {
		s := &c.shards[i]
		s.mu.RLock()
		for _, entry := range s.entries {
			// Skip expired entries
			if entry.IsExpired(now) {
				continue
			}
			// Skip negative entries (short TTL, low value on restart)
			if entry.IsNegative {
				continue
			}
			// Skip entries without a message (shouldn't happen)
			if entry.Message == nil {
				continue
			}

			// Pack message to wire format
			buf := make([]byte, entry.Message.WireLength())
			n, err := entry.Message.Pack(buf)
			if err != nil {
				continue // Skip entries that can't be packed
			}

			entries = append(entries, CacheEntryJSON{
				Key:        entry.Key,
				WireBytes:  buf[:n],
				TTL:        entry.TTL,
				RCode:      entry.RCode,
				IsNegative: entry.IsNegative,
				ExpireTime: entry.ExpireTime,
			})
		}
		s.mu.RUnlock()
	}

	return entries
}

// Load restores cache entries from a previously saved snapshot.
// Only non-expired entries are restored. Entries that have already
// expired are skipped. The cache is not cleared before loading.
func (c *Cache) Load(entries []CacheEntryJSON) (restored int) {
	now := time.Now()
	for _, e := range entries {
		// Skip expired entries
		if e.ExpireTime.Before(now) {
			continue
		}

		// Unpack the wire-format message
		msg, err := protocol.UnpackMessage(e.WireBytes)
		if err != nil {
			continue
		}

		// Calculate remaining TTL
		remainingTTL := uint32(e.ExpireTime.Sub(now).Seconds())
		if remainingTTL == 0 {
			continue
		}

		// Use setInternal to add without triggering callbacks
		s := c.shardOf(e.Key)
		s.mu.Lock()
		c.setInternal(s, e.Key, msg, remainingTTL, false)
		s.mu.Unlock()
		restored++
	}

	return restored
}
