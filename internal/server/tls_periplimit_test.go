package server

import "testing"

// TestTLSServer_DecrementIPConn verifies per-IP connection accounting cleans up
// map entries at zero (no unbounded growth) and never underflows.
func TestTLSServer_DecrementIPConn(t *testing.T) {
	s := NewTLSServer("127.0.0.1:0", nil, nil)

	// Two connections from one IP, one from another.
	s.ipConnCount["1.2.3.4"] = 2
	s.ipConnCount["5.6.7.8"] = 1

	s.decrementIPConn("1.2.3.4")
	if got := s.ipConnCount["1.2.3.4"]; got != 1 {
		t.Errorf("after one decrement, count = %d, want 1", got)
	}

	s.decrementIPConn("1.2.3.4")
	if _, ok := s.ipConnCount["1.2.3.4"]; ok {
		t.Errorf("entry for 1.2.3.4 should be deleted at zero, still present")
	}

	s.decrementIPConn("5.6.7.8")
	if _, ok := s.ipConnCount["5.6.7.8"]; ok {
		t.Errorf("entry for 5.6.7.8 should be deleted at zero, still present")
	}

	// Decrementing an absent key must not panic or create a negative entry.
	s.decrementIPConn("9.9.9.9")
	if _, ok := s.ipConnCount["9.9.9.9"]; ok {
		t.Errorf("decrementing an absent key must not create an entry")
	}
}
