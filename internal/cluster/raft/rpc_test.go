package raft

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestInMemoryTransport_Basic exercises InMemoryTransport with a simple
// mock handler to verify it implements the Transport interface correctly.
func TestInMemoryTransport_Basic(t *testing.T) {
	hub := NewInMemoryHub()

	// Two nodes, each with a minimal blocking handler.
	node1Handler := &blockingHandler{}
	node2Handler := &blockingHandler{}
	hub.AddNode("node1", node1Handler)
	hub.AddNode("node2", node2Handler)

	transport1 := hub.NewTransport("node1")
	transport2 := hub.NewTransport("node2")

	ctx := context.Background()

	// Node1 sends a vote request to node2.
	resp, err := transport1.SendRequestVote(ctx, "node2", VoteRequest{
		Term:         1,
		CandidateID:  "node1",
		LastLogIndex: 5,
		LastLogTerm:  1,
	})
	if err != nil {
		t.Fatalf("SendRequestVote failed: %v", err)
	}
	if resp == nil {
		t.Fatal("vote response was nil")
	}

	// Node2 sends append entries to node1.
	appendResp, err := transport2.SendAppendEntries(ctx, "node1", AppendRequest{
		Term:         2,
		LeaderID:     "node2",
		PrevLogIndex: 3,
		PrevLogTerm:  1,
		Entries:      nil,
		LeaderCommit: 3,
	})
	if err != nil {
		t.Fatalf("SendAppendEntries failed: %v", err)
	}
	if appendResp == nil {
		t.Fatal("append response was nil")
	}
}

// TestInMemoryTransport_Timeout verifies that a context deadline is respected
// by the transport — the core D3 fix.
func TestInMemoryTransport_Timeout(t *testing.T) {
	hub := NewInMemoryHub()

	// A handler that never responds (simulates a dead peer).
	deadHandler := &noResponseHandler{}
	hub.AddNode("dead", deadHandler)

	transport := hub.NewTransport("alive")

	// Use a short timeout; the RPC should fail with context deadline exceeded
	// rather than blocking forever.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := transport.SendRequestVote(ctx, "dead", VoteRequest{Term: 1})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected context deadline error, got nil")
	}
	if !strings.Contains(err.Error(), "deadline") && !strings.Contains(err.Error(), "context") {
		t.Errorf("expected deadline/context error, got: %v", err)
	}
	// Should not take longer than 2× the deadline (generous margin).
	if elapsed > 200*time.Millisecond {
		t.Errorf("RPC took %v (expected < 200ms with 50ms deadline)", elapsed)
	}
}

// TestInMemoryTransport_PeerNotFound verifies that routing to an unknown peer
// returns ErrPeerNotFound.
func TestInMemoryTransport_PeerNotFound(t *testing.T) {
	hub := NewInMemoryHub()
	transport := hub.NewTransport("node1")

	_, err := transport.SendRequestVote(context.Background(), "unknown-peer", VoteRequest{})
	if err != ErrPeerNotFound {
		t.Errorf("expected ErrPeerNotFound, got: %v", err)
	}
}

// TestInMemoryTransport_SelfRouting verifies that routing to self returns
// a non-nil error rather than deadlocking.
func TestInMemoryTransport_SelfRouting(t *testing.T) {
	hub := NewInMemoryHub()
	hub.AddNode("self", &blockingHandler{})
	transport := hub.NewTransport("self")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := transport.SendAppendEntries(ctx, "self", AppendRequest{})
	if err == nil {
		t.Error("expected error for self-routing, got nil")
	}
}

// blockingHandler is an RPCHandler that responds with a zero response
// (suitable for Transport interface tests where we only care about
// call routing, not handler logic).
type blockingHandler struct{}

func (h *blockingHandler) HandleVoteRequest(req VoteRequest) VoteResponse {
	return VoteResponse{Term: req.Term, VoteGranted: false}
}

func (h *blockingHandler) HandleAppendRequest(req AppendRequest) AppendResponse {
	return AppendResponse{Term: req.Term, Success: true}
}

func (h *blockingHandler) HandleSnapshotRequest(req SnapshotRequest) {}

// noResponseHandler blocks forever on every handler call.
// Used to test that InMemoryTransport respects context deadlines.
type noResponseHandler struct{}

func (h *noResponseHandler) HandleVoteRequest(VoteRequest) VoteResponse {
	<-make(chan struct{}) // block forever
	panic("unreachable")
}

func (h *noResponseHandler) HandleAppendRequest(AppendRequest) AppendResponse {
	<-make(chan struct{})
	panic("unreachable")
}

func (h *noResponseHandler) HandleSnapshotRequest(SnapshotRequest) {
	<-make(chan struct{})
}
