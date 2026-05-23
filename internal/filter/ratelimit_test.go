package filter

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
)

func TestRateLimiter_BasicAllow(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 5, Burst: 20})
	defer rl.Stop()

	ip := net.ParseIP("10.0.0.1")
	if !rl.Allow(ip) {
		t.Error("first request should be allowed")
	}
}

func TestRateLimiter_BurstExhaustion(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 3})
	defer rl.Stop()

	ip := net.ParseIP("10.0.0.1")

	// Should allow burst size requests
	for i := 0; i < 3; i++ {
		if !rl.Allow(ip) {
			t.Fatalf("request %d should be allowed within burst", i+1)
		}
	}

	// Next request should be denied
	if rl.Allow(ip) {
		t.Error("request beyond burst should be denied")
	}
}

func TestRateLimiter_TokenRefill(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 1000, Burst: 2})
	defer rl.Stop()

	ip := net.ParseIP("10.0.0.1")

	// Exhaust the burst
	rl.Allow(ip)
	rl.Allow(ip)

	// Denied immediately
	if rl.Allow(ip) {
		t.Error("should be denied after burst exhaustion")
	}

	// Manually advance the bucket's lastTime to simulate time passing
	rl.mu.Lock()
	b := rl.buckets[ip.String()]
	b.lastTime = time.Now().Add(-10 * time.Millisecond) // 10ms ago, should refill ~10 tokens at 1000/s
	rl.mu.Unlock()

	// Should be allowed again after refill
	if !rl.Allow(ip) {
		t.Error("should be allowed after token refill")
	}
}

func TestRateLimiter_DifferentClients(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 1})
	defer rl.Stop()

	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")

	if !rl.Allow(ip1) {
		t.Error("ip1 first request should be allowed")
	}
	if !rl.Allow(ip2) {
		t.Error("ip2 first request should be allowed (separate bucket)")
	}

	// Both should be denied now (burst=1)
	if rl.Allow(ip1) {
		t.Error("ip1 should be denied after burst")
	}
	if rl.Allow(ip2) {
		t.Error("ip2 should be denied after burst")
	}
}

func TestRateLimiter_Defaults(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{}) // empty config
	defer rl.Stop()

	if rl.rate != 5 {
		t.Errorf("expected default rate 5, got %f", rl.rate)
	}
	if rl.burst != 20 {
		t.Errorf("expected default burst 20, got %d", rl.burst)
	}
}

func TestRateLimiter_IPv6(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 2})
	defer rl.Stop()

	ip := net.ParseIP("::1")
	if !rl.Allow(ip) {
		t.Error("IPv6 first request should be allowed")
	}
	if !rl.Allow(ip) {
		t.Error("IPv6 second request should be allowed")
	}
	if rl.Allow(ip) {
		t.Error("IPv6 request beyond burst should be denied")
	}
}

func TestRateLimiter_PruneStale(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 10})
	defer rl.Stop()

	ip := net.ParseIP("10.0.0.1")
	rl.Allow(ip)

	// Manually make the bucket stale
	rl.mu.Lock()
	rl.buckets[ip.String()].lastTime = time.Now().Add(-10 * time.Minute)
	rl.mu.Unlock()

	rl.pruneStale()

	rl.mu.Lock()
	count := len(rl.buckets)
	rl.mu.Unlock()

	if count != 0 {
		t.Errorf("expected 0 buckets after prune, got %d", count)
	}
}

func TestRateLimiter_PruneKeepsActive(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 10})
	defer rl.Stop()

	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")

	rl.Allow(ip1)
	rl.Allow(ip2)

	// Make ip1 stale
	rl.mu.Lock()
	rl.buckets[ip1.String()].lastTime = time.Now().Add(-10 * time.Minute)
	rl.mu.Unlock()

	rl.pruneStale()

	rl.mu.Lock()
	count := len(rl.buckets)
	_, hasActive := rl.buckets[ip2.String()]
	rl.mu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 bucket after prune, got %d", count)
	}
	if !hasActive {
		t.Error("active bucket should still exist")
	}
}

func TestRateLimiter_CapNotExceedBurst(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 10000, Burst: 3})
	defer rl.Stop()

	ip := net.ParseIP("10.0.0.1")

	// Use 1 token
	rl.Allow(ip)

	// Simulate a lot of time passing - tokens should cap at burst
	rl.mu.Lock()
	rl.buckets[ip.String()].lastTime = time.Now().Add(-1 * time.Hour)
	rl.mu.Unlock()

	// Should only get burst-size requests
	allowed := 0
	for i := 0; i < 10; i++ {
		if rl.Allow(ip) {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("expected 3 allowed (burst cap), got %d", allowed)
	}
}

func TestRateLimiter_MaxBuckets(t *testing.T) {
	// Test with small maxBuckets to verify eviction
	rl := NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 10, MaxBuckets: 100})
	defer rl.Stop()

	// Create 150 unique clients to trigger eviction
	for i := 0; i < 150; i++ {
		ip := net.ParseIP(fmt.Sprintf("10.0.0.%d", i%256))
		if i >= 256 {
			ip = net.ParseIP(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
		}
		rl.Allow(ip)
	}

	rl.mu.Lock()
	count := len(rl.buckets)
	rl.mu.Unlock()

	// Should not exceed maxBuckets (with some tolerance for race conditions)
	if count > 110 {
		t.Errorf("expected bucket count around 100, got %d (maxBuckets exceeded)", count)
	}

	// Should have evicted some but still have most recent
	if count < 50 {
		t.Errorf("expected at least 50 buckets remaining, got %d (too many evicted)", count)
	}
}

func TestRateLimiter_EvictOldest(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 10, MaxBuckets: 10})
	defer rl.Stop()

	// Create 10 clients
	for i := 0; i < 10; i++ {
		ip := net.ParseIP(fmt.Sprintf("10.0.0.%d", i))
		rl.Allow(ip)
	}

	rl.mu.Lock()
	count := len(rl.buckets)
	rl.mu.Unlock()

	if count != 10 {
		t.Errorf("expected 10 buckets, got %d", count)
	}

	// Add one more - should trigger eviction
	ip := net.ParseIP("10.0.0.100")
	rl.Allow(ip)

	rl.mu.Lock()
	count = len(rl.buckets)
	hasNew := rl.buckets[ip.String()] != nil
	rl.mu.Unlock()

	if count > 10 {
		t.Errorf("expected at most 10 buckets after eviction, got %d", count)
	}
	if !hasNew {
		t.Error("new bucket should exist after eviction")
	}
}

// TestRateLimiter_EvictOldest_UsesLastTimeNotCreatedAt regresses
// SECURITY-REPORT.md M-5. evictOldest used to key on bucket.createdAt
// (creation time). An attacker spraying source IPs would churn through
// fresh buckets while the eviction loop dropped the longest-tenured
// legitimate clients first; when those legitimate clients next showed
// up they got a brand-new bucket with full burst, effectively
// resetting the per-IP cap cluster-wide. Switching the sort key to
// lastTime gives true LRU: a steady legitimate client whose bucket
// stays warm outlives cold attacker buckets whose first request
// happened minutes ago.
func TestRateLimiter_EvictOldest_UsesLastTimeNotCreatedAt(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 5, Burst: 20, MaxBuckets: 100})
	defer rl.Stop()

	now := time.Now()
	legitKey := "203.0.113.1"
	attackerKey := "198.51.100.1"

	rl.mu.Lock()
	// Legitimate client: bucket has been around a long time but is
	// actively kept warm — should NOT be the eviction victim.
	rl.buckets[legitKey] = &bucket{tokens: 10, lastTime: now.Add(-2 * time.Second)}
	// Attacker bucket: just created during a spray, used once, then
	// abandoned. lastTime is older than the legit client's last use.
	rl.buckets[attackerKey] = &bucket{tokens: 10, lastTime: now.Add(-1 * time.Minute)}
	rl.mu.Unlock()

	rl.evictOldest(1)

	rl.mu.Lock()
	_, legitStillPresent := rl.buckets[legitKey]
	_, attackerStillPresent := rl.buckets[attackerKey]
	rl.mu.Unlock()

	if !legitStillPresent {
		t.Error("M-5 regression: legitimate (warmest lastTime) bucket was evicted")
	}
	if attackerStillPresent {
		t.Error("M-5 regression: stale-lastTime attacker bucket survived eviction — limit can be bypassed by IP rotation")
	}
}
