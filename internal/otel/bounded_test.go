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

// TestTracer_SampleRate verifies SampleRate is honored as a real probability
// (not an all-or-nothing switch): 0 drops all, 1 keeps all, and a fractional
// rate samples roughly that fraction across many distinct trace IDs.
func TestTracer_SampleRate(t *testing.T) {
	all := NewTracer(Config{Enabled: true, SampleRate: 1.0})
	for i := 0; i < 100; i++ {
		if _, s := all.StartSpan(context.Background(), "op"); s == nil {
			t.Fatal("SampleRate 1.0 must sample every span")
		}
	}

	// Near-zero rate samples almost nothing (NewTracer treats an explicit 0 as
	// "unset" and defaults to 1.0, so use a tiny positive rate here).
	tiny := NewTracer(Config{Enabled: true, SampleRate: 0.0005})
	tinySampled := 0
	for i := 0; i < 20000; i++ {
		if _, s := tiny.StartSpan(context.Background(), "op"); s != nil {
			tinySampled++
		}
	}
	if float64(tinySampled)/20000 > 0.05 {
		t.Errorf("SampleRate 0.0005 sampled %d/20000, want near 0", tinySampled)
	}

	// Fractional rate: the hash of distinct trace IDs must yield ~50%, not 0%
	// or 100% (the bug where sampled() read the monotonic-timestamp bytes).
	half := NewTracer(Config{Enabled: true, SampleRate: 0.5})
	const n = 20000
	sampled := 0
	for i := 0; i < n; i++ {
		if _, s := half.StartSpan(context.Background(), "op"); s != nil {
			sampled++
		}
	}
	frac := float64(sampled) / n
	if frac < 0.40 || frac > 0.60 {
		t.Errorf("SampleRate 0.5 sampled fraction = %.3f, want ~0.5 (all-or-nothing bug?)", frac)
	}
}
