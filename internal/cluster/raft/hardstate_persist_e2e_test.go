package raft

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/util"
)

// TestHardState_PersistsAcrossRestart is a regression test for a critical
// wiring omission: NewClusterIntegration never set config.DataDir, so
// persistHardStateLocked silently no-oped and NewNode skipped loadHardState.
// A restarted node came back at term 0 with no vote record and could grant the
// same term's vote twice → split-brain. This test drives a term advance + vote,
// restarts over the same data directory, and asserts both survived.
func TestHardState_PersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()

	ci1, err := NewClusterIntegration("n1", nil, nil, freeTCPAddr(t), dir, "", "", nil, util.DefaultLogger())
	if err != nil {
		t.Fatalf("ci1: %v", err)
	}

	// Persist a term advance and a vote for a peer, exactly as an election
	// would. advanceTermLocked resets votedFor, so vote AFTER advancing.
	ci1.node.mu.Lock()
	if err := ci1.node.advanceTermLocked(7); err != nil {
		ci1.node.mu.Unlock()
		t.Fatalf("advanceTermLocked: %v", err)
	}
	if err := ci1.node.setVotedForLocked("candidate-X"); err != nil {
		ci1.node.mu.Unlock()
		t.Fatalf("setVotedForLocked: %v", err)
	}
	ci1.node.mu.Unlock()

	// New incarnation over the same data directory.
	ci2, err := NewClusterIntegration("n1", nil, nil, freeTCPAddr(t), dir, "", "", nil, util.DefaultLogger())
	if err != nil {
		t.Fatalf("ci2: %v", err)
	}

	ci2.node.mu.Lock()
	gotTerm := ci2.node.currentTerm
	gotVote := ci2.node.votedFor
	ci2.node.mu.Unlock()

	if gotTerm != 7 {
		t.Errorf("restored currentTerm = %d, want 7 (HardState not persisted → double-vote/split-brain risk)", gotTerm)
	}
	if gotVote != "candidate-X" {
		t.Errorf("restored votedFor = %q, want %q (HardState not persisted)", gotVote, "candidate-X")
	}
}
