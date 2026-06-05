package raft

// Multi-node end-to-end test over the REAL TCP RPC transport: a zone change
// proposed on the leader must replicate, commit, and fire the apply hook on a
// FOLLOWER — i.e. the change reaches the other node's state, not just the
// leader's. This is the strongest proof that a Raft cluster governs DNS data
// across nodes (the harness in harness_test.go uses an in-process transport;
// here the bytes actually go over a socket).

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// freeTCPAddr returns a currently-free loopback address. There's a tiny race
// between closing the probe listener and the RPC server re-binding it, but on
// loopback in a test that window is negligible.
func freeTCPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func TestMultiNode_ZoneChangeReplicatesToFollower(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-node RPC test skipped in -short mode")
	}

	addrA := freeTCPAddr(t)
	addrB := freeTCPAddr(t)
	// NodeIDs double as transport addresses in this package's TCP transport.
	idA, idB := NodeID(addrA), NodeID(addrB)

	ciA, err := NewClusterIntegration(idA, []NodeID{idB}, addrA, t.TempDir(), "", "", util.DefaultLogger())
	if err != nil {
		t.Fatalf("NewClusterIntegration A: %v", err)
	}
	ciB, err := NewClusterIntegration(idB, []NodeID{idA}, addrB, t.TempDir(), "", "", util.DefaultLogger())
	if err != nil {
		t.Fatalf("NewClusterIntegration B: %v", err)
	}

	var mu sync.Mutex
	applied := map[NodeID][]ZoneCommand{}
	record := func(id NodeID) func(ZoneCommand) {
		return func(cmd ZoneCommand) {
			mu.Lock()
			applied[id] = append(applied[id], cmd)
			mu.Unlock()
		}
	}
	ciA.SetApplyHook(record(idA))
	ciB.SetApplyHook(record(idB))

	if err := ciA.Start(); err != nil {
		t.Fatalf("start A: %v", err)
	}
	defer ciA.Stop()
	if err := ciB.Start(); err != nil {
		t.Fatalf("start B: %v", err)
	}
	defer ciB.Stop()

	// Wait for a leader to emerge.
	var leader, follower *ClusterIntegration
	deadline := time.Now().Add(8 * time.Second)
	for {
		if ciA.IsLeader() {
			leader, follower = ciA, ciB
			break
		}
		if ciB.IsLeader() {
			leader, follower = ciB, ciA
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no leader elected within 8s")
		}
		time.Sleep(20 * time.Millisecond)
	}
	followerID := idB
	if follower == ciA {
		followerID = idA
	}

	cmd := ZoneCommand{
		Type: "add_record", Zone: "example.com.", Name: "www",
		RRTypeStr: "A", Class: "IN", TTL: 300, RData: []string{"192.0.2.1"},
	}
	if err := leader.ProposeZoneChangeWait(cmd, 5*time.Second); err != nil {
		t.Fatalf("leader ProposeZoneChangeWait: %v", err)
	}

	// The follower must apply the replicated command shortly after.
	got := false
	waitDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(waitDeadline) {
		mu.Lock()
		for _, c := range applied[followerID] {
			if c.Type == "add_record" && c.Name == "www" && c.RRTypeStr == "A" {
				got = true
			}
		}
		mu.Unlock()
		if got {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !got {
		t.Fatalf("follower %s never applied the replicated zone change", followerID)
	}
}
