package audit

import (
	"io"
	"sync"
	"testing"
	"time"
)

// newTestAuditLogger builds an enabled logger writing to w, with the output set
// before the background writer starts (so tests never race-swap a.output).
func newTestAuditLogger(w io.Writer) *AuditLogger {
	return newAuditLogger(w, nil)
}

// blockingWriter blocks inside Write until release is closed, and signals
// (once) when the first Write is entered, so a test can deterministically catch
// the background writer while it is stalled.
type blockingWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}

// TestAuditLogger_LogDoesNotBlockOnStalledWriter is the core regression test for
// the audit-logger hot-path fix: a stalled output writer must NEVER block the
// DNS request path (Log*). Previously Log* wrote synchronously under a global
// mutex, so a full disk or stalled volume stalled ALL query resolution. Now
// Log* enqueues non-blocking and drops when the queue is full.
func TestAuditLogger_LogDoesNotBlockOnStalledWriter(t *testing.T) {
	w := &blockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
	al := newTestAuditLogger(w)
	defer func() {
		close(w.release) // unblock the writer so Close can drain and return
		al.Close()
	}()

	// Trigger the writer to pull a line and enter (and stall in) Write.
	al.LogQuery(QueryAuditEntry{QueryName: "first.example.com", QueryType: "A"})
	select {
	case <-w.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("background writer never reached Write")
	}

	// The writer is now blocked in Write and cannot drain. Fill the queue and
	// overflow it; every one of these Log* calls must return promptly (no block)
	// and the overflow must be dropped.
	done := make(chan struct{})
	go func() {
		for i := 0; i < auditQueueSize+500; i++ {
			al.LogQuery(QueryAuditEntry{QueryName: "x.example.com", QueryType: "A"})
		}
		close(done)
	}()

	select {
	case <-done:
		// good — Log* returned promptly despite the stalled writer
	case <-time.After(3 * time.Second):
		t.Fatal("LogQuery blocked on a stalled writer — the request path is not non-blocking")
	}

	if al.Dropped() == 0 {
		t.Error("expected audit lines to be dropped while the writer was stalled and the queue full")
	}
}
