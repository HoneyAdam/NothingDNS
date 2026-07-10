package otel

import (
	"context"
	"testing"
)

// TestTracer_SpanRetentionBounded verifies finished spans are capped so a live
// tracer that isn't drained cannot grow without bound (OOM landmine).
func TestTracer_SpanRetentionBounded(t *testing.T) {
	tr := NewTracer(Config{Enabled: true})
	for i := 0; i < maxRetainedSpans*3; i++ {
		_, s := tr.StartSpan(context.Background(), "op")
		tr.EndSpan(s, nil)
	}
	if got := len(tr.Export()); got > maxRetainedSpans {
		t.Errorf("retained %d spans, want <= %d (unbounded growth)", got, maxRetainedSpans)
	}
	if tr.DroppedSpans() == 0 {
		t.Error("expected spans to be dropped at the retention cap")
	}
}

// TestTracer_SampleRate verifies SampleRate is honored: 0 drops all, 1 keeps all.
func TestTracer_SampleRate(t *testing.T) {
	none := NewTracer(Config{Enabled: true, SampleRate: 0.0001})
	sampled := 0
	for i := 0; i < 2000; i++ {
		if _, s := none.StartSpan(context.Background(), "op"); s != nil {
			sampled++
		}
	}
	if sampled > 100 { // ~0.01% of 2000 ≈ 0-1 expected; allow generous slack
		t.Errorf("SampleRate 0.0001 sampled %d/2000 spans, want ~0", sampled)
	}

	all := NewTracer(Config{Enabled: true, SampleRate: 1.0})
	for i := 0; i < 100; i++ {
		if _, s := all.StartSpan(context.Background(), "op"); s == nil {
			t.Fatal("SampleRate 1.0 must sample every span")
		}
	}
}
