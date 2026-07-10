package cache

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestAgeAdjustedMessage_DecrementsTTLByAge verifies that serving a cached
// entry decrements each RR TTL by the time the entry has spent in cache
// (RFC 1035 §4.1.3 / RFC 2181), never mutating the stored copy, and floors at 1.
func TestAgeAdjustedMessage_DecrementsTTLByAge(t *testing.T) {
	clock := newFakeCacheClock()
	cfg := DefaultConfig()
	cfg.MinTTL = time.Second
	cfg.MaxTTL = 24 * time.Hour
	c := New(cfg)
	c.setClockForTest(clock)

	msg := &protocol.Message{}
	name, _ := protocol.ParseName("www.example.com.")
	msg.Answers = append(msg.Answers,
		&protocol.ResourceRecord{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
		&protocol.ResourceRecord{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 30, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 5}}},
	)

	c.Set("www.example.com.:1", msg, 300)

	// Advance 100s of cache age.
	clock.Advance(100 * time.Second)

	entry := c.Get("www.example.com.:1")
	if entry == nil {
		t.Fatal("expected cache hit")
	}
	adjusted := entry.AgeAdjustedMessage(clock.Now())
	if adjusted == nil {
		t.Fatal("AgeAdjustedMessage returned nil")
	}

	// 300 - 100 = 200; 30 - 100 -> floored at 1.
	if got := adjusted.Answers[0].TTL; got != 200 {
		t.Errorf("first RR TTL = %d, want 200 (300 - 100s age)", got)
	}
	if got := adjusted.Answers[1].TTL; got != 1 {
		t.Errorf("second RR TTL = %d, want 1 (30 - 100s age, floored)", got)
	}

	// The cached original must be untouched (still 300 / 30).
	if entry.Message.Answers[0].TTL != 300 || entry.Message.Answers[1].TTL != 30 {
		t.Errorf("cached message TTLs were mutated: %d, %d (want 300, 30)",
			entry.Message.Answers[0].TTL, entry.Message.Answers[1].TTL)
	}
}

// TestAgeAdjustedMessage_ZeroAge returns the original TTLs when just cached.
func TestAgeAdjustedMessage_ZeroAge(t *testing.T) {
	clock := newFakeCacheClock()
	cfg := DefaultConfig()
	cfg.MinTTL = time.Second
	c := New(cfg)
	c.setClockForTest(clock)

	msg := &protocol.Message{}
	name, _ := protocol.ParseName("a.example.com.")
	msg.Answers = append(msg.Answers,
		&protocol.ResourceRecord{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 120, Data: &protocol.RDataA{Address: [4]byte{9, 9, 9, 9}}})
	c.Set("a.example.com.:1", msg, 120)

	entry := c.Get("a.example.com.:1")
	if entry == nil {
		t.Fatal("expected cache hit")
	}
	adjusted := entry.AgeAdjustedMessage(clock.Now())
	if got := adjusted.Answers[0].TTL; got != 120 {
		t.Errorf("TTL = %d, want 120 (no age elapsed)", got)
	}
}
