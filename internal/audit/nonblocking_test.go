package audit

import (
	"io"
	"testing"
	"time"
)

// newTestAuditLogger builds an enabled logger writing to w, with the output set
// before the background writer starts (so tests never race-swap a.output).
func newTestAuditLogger(w io.Writer) *AuditLogger {
	return newAuditLogger(w, nil)
}

// blockingWriter blocks the first Write until release is closed, simulating a
// stalled disk / network volume.
type blockingWriter struct{ release chan struct{} }

func (w blockingWriter) Write(p []byte) (int, error) {
	<-w.release
	return len(p), nil
}

// TestAuditLogger_LogDoesNotBlockOnStalledWriter is the core regression test for
// the audit-logger hot-path fix: a stalled output writer must NEVER block the
// DNS request path (Log*). Previously Log* wrote synchronously under a global
// mutex, so a full disk or stalled volume stalled ALL query resolution. Now
// Log* enqueues non-blocking and drops when the queue is full.
func TestAuditLogger_LogDoesNotBlockOnStalledWriter(t *testing.T) {
	release := make(chan struct{})
	al := newTestAuditLogger(blockingWriter{release: release})
	defer func() {
		close(release) // unblock the writer so Close can drain and return
		al.Close()
	}()

	// Fire far more than the queue can hold while the writer is stuck. None of
	// these calls may block.
	done := make(chan struct{})
	go func() {
		for i := 0; i < auditQueueSize+1000; i++ {
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
		t.Error("expected some audit lines to be dropped while the writer was stalled")
	}
}
