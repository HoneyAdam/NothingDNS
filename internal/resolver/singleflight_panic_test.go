package resolver

import (
	"sync"
	"testing"
	"time"
)

// TestSingleflight_PanicDoesNotWedge is a regression test: a panic inside the
// singleflight fn used to leave c.ready unclosed and the key stuck in
// sf.active, so waiters blocked forever and every future call for that key
// deadlocked. The panic must instead be converted to an error, the waiters
// released, and the key cleaned up so subsequent calls proceed.
func TestSingleflight_PanicDoesNotWedge(t *testing.T) {
	var sf singleflight[int]

	// First call panics.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err, _ := sf.Do("k", func() (int, error) {
			panic("boom")
		})
		if err == nil {
			t.Errorf("expected an error from a panicking fn, got nil")
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Do() with a panicking fn did not return — singleflight is wedged")
	}

	// The key must have been cleaned up: a subsequent call runs fn again and
	// succeeds (it is not blocked on a never-closed ready channel).
	got, err, _ := sf.Do("k", func() (int, error) { return 42, nil })
	if err != nil {
		t.Fatalf("subsequent Do returned error: %v", err)
	}
	if got != 42 {
		t.Fatalf("subsequent Do = %d, want 42", got)
	}
}

// TestSingleflight_ConcurrentWaitersReleasedOnPanic ensures every coalesced
// waiter is unblocked (with an error) when the leader's fn panics.
func TestSingleflight_ConcurrentWaitersReleasedOnPanic(t *testing.T) {
	var sf singleflight[int]

	start := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup

	// Leader: blocks until released, then panics.
	wg.Add(1)
	go func() {
		defer wg.Done()
		close(start)
		sf.Do("k", func() (int, error) {
			<-release
			panic("leader boom")
		})
	}()

	<-start
	// Give a few waiters time to coalesce onto the same key.
	waiters := 5
	waiterDone := make(chan struct{}, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			sf.Do("k", func() (int, error) { return 1, nil })
			waiterDone <- struct{}{}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release) // leader panics now

	deadline := time.After(2 * time.Second)
	for i := 0; i < waiters; i++ {
		select {
		case <-waiterDone:
		case <-deadline:
			t.Fatalf("waiter %d never released after leader panic — deadlock", i)
		}
	}
	wg.Wait()
}
