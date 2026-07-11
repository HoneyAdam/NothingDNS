// NothingDNS - Coverage: simple standalone functions
package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

func TestDecodeHex32(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		wantLen int
	}{
		{name: "valid 32 bytes", input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", wantLen: 32},
		{name: "with whitespace", input: " 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f ", wantLen: 32},
		{name: "too short", input: "abcd", wantErr: true},
		{name: "too long", input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f01", wantErr: true},
		{name: "invalid hex", input: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeHex32(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tc.wantLen {
				t.Fatalf("len=%d want=%d", len(got), tc.wantLen)
			}
		})
	}
}

func TestResolverCacheAdapter_SetNegativeWithTTL(t *testing.T) {
	c := cache.New(cache.Config{Capacity: 100, DefaultTTL: 300 * time.Second})
	adapter := &resolverCacheAdapter{cache: c}
	adapter.SetNegativeWithTTL("neg-ttl.test.", protocol.RcodeNameError, 60)
	entry := c.Get("neg-ttl.test.")
	if entry == nil {
		t.Fatal("expected cache entry")
	}
	if !entry.IsNegative {
		t.Fatal("expected IsNegative=true")
	}
	if entry.RCode != protocol.RcodeNameError {
		t.Fatalf("RCode=%d want=%d", entry.RCode, protocol.RcodeNameError)
	}
}

func TestResolverCacheAdapter_SetNegativeMessage(t *testing.T) {
	c := cache.New(cache.Config{Capacity: 100, DefaultTTL: 300 * time.Second})
	adapter := &resolverCacheAdapter{cache: c}
	msg := &protocol.Message{Header: protocol.Header{ID: 42}}
	adapter.SetNegativeMessage("neg-msg.test.", protocol.RcodeNameError, msg, 120)
	entry := c.Get("neg-msg.test.")
	if entry == nil {
		t.Fatal("expected cache entry")
	}
	if !entry.IsNegative {
		t.Fatal("expected IsNegative=true")
	}
	if entry.RCode != protocol.RcodeNameError {
		t.Fatalf("RCode=%d want=%d", entry.RCode, protocol.RcodeNameError)
	}
}

func TestMapClusterPeers(t *testing.T) {
	tests := []struct {
		name  string
		peers []config.ClusterPeerConfig
		want  int
	}{
		{name: "nil", peers: nil, want: 0},
		{name: "empty", peers: []config.ClusterPeerConfig{}, want: 0},
		{name: "single", peers: []config.ClusterPeerConfig{{NodeID: "n1", Addr: "10.0.0.1:7946"}}, want: 1},
		{name: "multiple", peers: []config.ClusterPeerConfig{
			{NodeID: "n1", Addr: "10.0.0.1:7946"},
			{NodeID: "n2", Addr: "10.0.0.2:7946"},
		}, want: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mapClusterPeers(tc.peers)
			if len(got) != tc.want {
				t.Fatalf("len=%d want=%d", len(got), tc.want)
			}
			for i := range got {
				if got[i].NodeID != tc.peers[i].NodeID {
					t.Errorf("NodeID[%d]=%q want=%q", i, got[i].NodeID, tc.peers[i].NodeID)
				}
			}
		})
	}
}

func TestLogErrorf(t *testing.T) {
	orig := handlerLogger
	t.Cleanup(func() { handlerLogger = orig })

	var buf bytes.Buffer
	handlerLogger = util.NewLogger(util.ERROR, util.TextFormat, &buf)
	logErrorf("test error: %s", "something")
	if buf.Len() == 0 {
		t.Fatal("expected log output")
	}

	handlerLogger = nil
	logErrorf("should not panic: %s", "fine")
}
