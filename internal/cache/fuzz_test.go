package cache

// Stateful fuzz harness for the cache's eviction and accounting paths.
// The cache itself never decodes wire bytes (the protocol layer hands
// it parsed messages), so the interesting attack surface is *operation
// ordering* — the LRU/eviction state machine. fc40eb7 was exactly that
// shape of bug: refresh-of-existing-key silently churned the shard.
// The fuzzer drives a long sequence of operations and after each one
// asserts the size-vs-capacity invariant; any panic, deadlock, or
// over-capacity excursion fails the run.

import (
	"fmt"
	"testing"
)

func FuzzCacheOperations(f *testing.F) {
	// Seeds: a few short op streams plus one that mimics the fc40eb7
	// shape (fill to capacity then refresh the same key).
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 1, 0, 2, 0, 3})       // 4 SetNegative on distinct keys
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) // 5 refreshes of the same key
	f.Add([]byte{0, 0, 1, 0, 2, 0, 3, 0, 0, 0}) // fill + interleaved Gets

	f.Fuzz(func(t *testing.T, ops []byte) {
		const capacity = numShards * 4
		cfg := DefaultConfig()
		cfg.Capacity = capacity
		c := New(cfg)

		// Interpret ops in (verb, key-id) pairs.
		// verb := ops[i] & 0x03 — 0=SetNegative, 1=Get, 2=Delete, 3=GetStale
		// keyID := ops[i+1] & 0x0f — at most 16 distinct keys so we churn
		// the same shards repeatedly (cap = numShards*4, so two-thirds of
		// op streams should provoke eviction).
		for i := 0; i+1 < len(ops); i += 2 {
			verb := ops[i] & 0x03
			keyID := ops[i+1] & 0x0f
			key := fmt.Sprintf("k%d", keyID)

			switch verb {
			case 0:
				c.SetNegative(key, 3)
			case 1:
				_ = c.Get(key)
			case 2:
				c.Delete(key)
			case 3:
				_ = c.GetStale(key)
			}

			// Invariant: the cache must never exceed its capacity, and
			// Size must agree with the eviction-bookkeeping side of
			// Stats (entries+evictions ≥ inserts is implied by the LRU
			// contract; we check the strict cap here because that's what
			// fc40eb7-style bugs violate first).
			if size := c.Size(); size > capacity {
				t.Fatalf("cache over capacity: size=%d cap=%d after verb=%d key=%s",
					size, capacity, verb, key)
			}
		}
	})
}
