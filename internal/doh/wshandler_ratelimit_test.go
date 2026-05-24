package doh

import (
	"os"
	"strings"
	"testing"
)

// TestWSHandler_M7_RateLimitCallPresent regresses SECURITY-REPORT.md
// M-7 with a static-grep tripwire. A proper integration test for
// per-connection rate limiting would need a WebSocket client (the
// internal/websocket package only exposes the server side); rather
// than vendor a client just for this, we assert that the load-bearing
// `conn.SetRateLimit(...)` call still exists in ServeHTTP and that
// its constants are sane. Any refactor that removes the call or
// silently disables the limit (e.g. setting it to 0) will trip this
// test, prompting the reviewer to either restore the call or replace
// this tripwire with a proper integration test against the new
// architecture.
//
// The risk this guards against is a single unauthenticated DoWS
// client flooding the resolver with DNS queries through one
// connection — the HTTP-layer apiRateLimiter only throttles the
// initial Upgrade, not per-message DNS traffic, and the 30-second
// read deadline resets per message.
func TestWSHandler_M7_RateLimitCallPresent(t *testing.T) {
	src, err := os.ReadFile("wshandler.go")
	if err != nil {
		t.Fatalf("read wshandler.go: %v", err)
	}
	const needle = "conn.SetRateLimit(wsRateLimitMessages, wsRateLimitWindow)"
	if !strings.Contains(string(src), needle) {
		t.Errorf("M-7 regression: wshandler.go must call %q immediately after Handshake — a single unauthenticated DoWS connection can otherwise flood the resolver", needle)
	}
	if wsRateLimitMessages <= 0 {
		t.Errorf("wsRateLimitMessages must be > 0, got %d", wsRateLimitMessages)
	}
	if wsRateLimitWindow <= 0 {
		t.Errorf("wsRateLimitWindow must be > 0, got %v", wsRateLimitWindow)
	}
}
