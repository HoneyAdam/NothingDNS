package main

import (
	"net"
	"testing"
)

// TestDoQResponseWriter_ClientInfoCarriesRealIP is a regression test: the DoQ
// response writer used to hardcode an empty net.UDPAddr{}, so ClientInfo().IP()
// returned nil for every DoQ query and the request pipeline silently skipped
// ACL, rate limiting, RPZ client policy, split-horizon, and DNS cookies (an
// open resolver / RRL bypass over DoQ). The writer must surface the real client
// address.
func TestDoQResponseWriter_ClientInfoCarriesRealIP(t *testing.T) {
	want := net.ParseIP("203.0.113.7")
	rw := &doqResponseWriter{
		remoteAddr: &net.UDPAddr{IP: want, Port: 4433},
	}

	ci := rw.ClientInfo()
	if ci == nil {
		t.Fatal("ClientInfo() returned nil")
	}
	if ci.Protocol != "quic" {
		t.Errorf("Protocol = %q, want %q", ci.Protocol, "quic")
	}
	got := ci.IP()
	if got == nil {
		t.Fatal("ClientInfo().IP() is nil — DoQ queries would bypass all per-client pipeline controls")
	}
	if !got.Equal(want) {
		t.Errorf("ClientInfo().IP() = %v, want %v", got, want)
	}
}

// TestDoQResponseWriter_ClientInfoNilAddrSafe ensures a missing address does not
// panic and yields a nil IP (fail-safe, not a crash).
func TestDoQResponseWriter_ClientInfoNilAddrSafe(t *testing.T) {
	rw := &doqResponseWriter{remoteAddr: nil}
	ci := rw.ClientInfo()
	if ci == nil {
		t.Fatal("ClientInfo() returned nil")
	}
	if ip := ci.IP(); ip != nil {
		t.Errorf("expected nil IP for empty address, got %v", ip)
	}
}
