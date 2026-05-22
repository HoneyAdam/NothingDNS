package raft

// HardState persistence is the foundation of Raft election safety;
// it must survive crashes intact. These tests exercise the
// load/save round-trip, the empty-dataDir guard, the
// missing-file = zero-state convention, and the magic-mismatch
// rejection (which is the corruption-detection backstop).

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHardStatePath(t *testing.T) {
	got := hardStatePath("/tmp/foo")
	want := filepath.Join("/tmp/foo", "raft-hardstate.bin")
	if got != want {
		t.Errorf("hardStatePath = %q, want %q", got, want)
	}
}

func TestLoadHardState_MissingFile_ReturnsZeroState(t *testing.T) {
	dir := t.TempDir()
	hs, err := loadHardState(dir)
	if err != nil {
		t.Fatalf("loadHardState fresh dir: %v", err)
	}
	if hs.CurrentTerm != 0 || hs.VotedFor != "" {
		t.Errorf("fresh-dir HardState = %+v, want zero", hs)
	}
}

func TestLoadHardState_EmptyDataDir_Skips(t *testing.T) {
	hs, err := loadHardState("")
	if err != nil {
		t.Fatalf("empty dataDir should return zero, not error: %v", err)
	}
	if hs.CurrentTerm != 0 || hs.VotedFor != "" {
		t.Errorf("HardState = %+v, want zero", hs)
	}
}

func TestSaveAndLoadHardState_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	orig := HardState{CurrentTerm: 42, VotedFor: "node-7"}
	if err := saveHardState(dir, orig); err != nil {
		t.Fatalf("saveHardState: %v", err)
	}
	got, err := loadHardState(dir)
	if err != nil {
		t.Fatalf("loadHardState: %v", err)
	}
	if got != orig {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, orig)
	}
}

func TestSaveHardState_EmptyVotedFor(t *testing.T) {
	// votedFor == "" must serialize as zero-length and round-trip.
	dir := t.TempDir()
	orig := HardState{CurrentTerm: 1}
	if err := saveHardState(dir, orig); err != nil {
		t.Fatalf("saveHardState: %v", err)
	}
	got, err := loadHardState(dir)
	if err != nil {
		t.Fatalf("loadHardState: %v", err)
	}
	if got != orig {
		t.Errorf("round-trip with empty votedFor: got %+v, want %+v", got, orig)
	}
}

func TestSaveHardState_EmptyDataDir_Refused(t *testing.T) {
	// saveHardState refuses to silently no-op on an empty dataDir;
	// that would mask configuration bugs that lose election safety.
	if err := saveHardState("", HardState{CurrentTerm: 1}); err == nil {
		t.Error("expected error for empty dataDir")
	}
}

func TestLoadHardState_MagicMismatch_Rejected(t *testing.T) {
	dir := t.TempDir()
	// Drop a file with the right name but wrong magic.
	path := hardStatePath(dir)
	if err := os.WriteFile(path, []byte("XXXX\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := loadHardState(dir); err == nil {
		t.Error("expected error for bad magic")
	}
}

func TestLoadHardState_TruncatedHeader_Rejected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(hardStatePath(dir), []byte("RHST"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := loadHardState(dir); err == nil {
		t.Error("expected error for truncated header")
	}
}

func TestLoadHardState_TruncatedVotedFor_Rejected(t *testing.T) {
	dir := t.TempDir()
	// Magic + term=0 + votedForLen=10 but no body bytes.
	body := []byte{
		'R', 'H', 'S', 'T',
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 10,
	}
	if err := os.WriteFile(hardStatePath(dir), body, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := loadHardState(dir); err == nil {
		t.Error("expected error for truncated votedFor body")
	}
}

func TestSaveHardState_Overwrite(t *testing.T) {
	// Save twice — the second must overwrite the first atomically.
	dir := t.TempDir()
	if err := saveHardState(dir, HardState{CurrentTerm: 1, VotedFor: "a"}); err != nil {
		t.Fatalf("saveHardState 1: %v", err)
	}
	if err := saveHardState(dir, HardState{CurrentTerm: 2, VotedFor: "b"}); err != nil {
		t.Fatalf("saveHardState 2: %v", err)
	}
	got, err := loadHardState(dir)
	if err != nil {
		t.Fatalf("loadHardState: %v", err)
	}
	if got.CurrentTerm != 2 || got.VotedFor != "b" {
		t.Errorf("after overwrite: %+v, want {2 b}", got)
	}
}
