package raft

import (
	"context"
	"errors"
	"os"
	"path"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// --- WAL torn-tail + CRC regressions ---
//
// The legacy WAL had no per-record checksum and errored out of ReadAll on
// a torn tail — a power loss mid-Write made the node UNABLE TO BOOT.

func walTestEntries() []entry {
	return []entry{
		{Index: 1, Term: 1, Command: []byte("cmd-one"), Type: EntryNormal},
		{Index: 2, Term: 1, Command: []byte("cmd-two"), Type: EntryNormal},
		{Index: 3, Term: 2, Command: []byte("cmd-three"), Type: EntryNormal},
	}
}

func TestWAL_TornTailIsTruncatedNotFatal(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWAL(dir)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	for _, e := range walTestEntries() {
		if err := w.Write(e); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Simulate a crash mid-append: a partial record at the tail.
	logPath := path.Join(dir, "raft-wal.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open for tear: %v", err)
	}
	if _, err := f.Write([]byte{0xDE, 0xAD, 0xBE}); err != nil {
		t.Fatalf("append torn bytes: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen: boot must succeed with the intact prefix.
	w2, err := NewWAL(dir)
	if err != nil {
		t.Fatalf("NewWAL after torn tail: %v", err)
	}
	defer w2.Close()
	got, err := w2.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll after torn tail: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("entries after torn tail = %d, want 3", len(got))
	}

	// The tail must be gone from disk: append + reread must stay consistent.
	if err := w2.Write(entry{Index: 4, Term: 2, Command: []byte("cmd-four"), Type: EntryNormal}); err != nil {
		t.Fatalf("Write after repair: %v", err)
	}
	got, err = w2.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll after repair+append: %v", err)
	}
	if len(got) != 4 || got[3].Index != 4 {
		t.Fatalf("entries after repair+append = %d (last=%+v), want 4", len(got), got[len(got)-1])
	}
}

func TestWAL_CRCMismatchTruncatesFromCorruption(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWAL(dir)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	for _, e := range walTestEntries() {
		if err := w.Write(e); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Flip one bit inside the SECOND record's command bytes.
	logPath := path.Join(dir, "raft-wal.log")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Layout: magic(8) + rec1(28+7+1) + rec2(...). Corrupt a byte well
	// inside record 2's command.
	rec1Size := walRecordHeaderSize + len("cmd-one") + 1
	corruptAt := len(walMagic) + rec1Size + walRecordHeaderSize + 2
	data[corruptAt] ^= 0x01
	if err := os.WriteFile(logPath, data, 0600); err != nil {
		t.Fatalf("write corrupted: %v", err)
	}

	w2, err := NewWAL(dir)
	if err != nil {
		t.Fatalf("NewWAL after corruption: %v", err)
	}
	defer w2.Close()
	got, err := w2.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll after corruption: %v", err)
	}
	// Only record 1 survives; the corrupted record and everything after it
	// are truncated (record boundaries are untrustworthy past a bad CRC).
	if len(got) != 1 || got[0].Index != 1 {
		t.Fatalf("entries after corruption = %d, want 1 (index 1)", len(got))
	}
}

func TestWAL_LegacyFormatMigratesOnOpen(t *testing.T) {
	dir := t.TempDir()
	logPath := path.Join(dir, "raft-wal.log")

	// Hand-write a legacy (no magic, no CRC) WAL with two records plus a
	// torn tail.
	var legacy []byte
	for _, e := range walTestEntries()[:2] {
		rec := encodeWALEntry(e)
		legacy = append(legacy, rec[4:]...) // strip the v1 CRC prefix
	}
	legacy = append(legacy, 0x00, 0x00, 0x00) // torn tail
	if err := os.WriteFile(logPath, legacy, 0600); err != nil {
		t.Fatalf("write legacy WAL: %v", err)
	}

	w, err := NewWAL(dir)
	if err != nil {
		t.Fatalf("NewWAL on legacy file: %v", err)
	}
	defer w.Close()
	got, err := w.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll after migration: %v", err)
	}
	if len(got) != 2 || got[0].Index != 1 || got[1].Index != 2 {
		t.Fatalf("migrated entries = %+v, want indices 1,2", got)
	}

	// File must now carry the v1 magic.
	head := make([]byte, len(walMagic))
	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open migrated: %v", err)
	}
	defer f.Close()
	if _, err := f.Read(head); err != nil {
		t.Fatalf("read migrated head: %v", err)
	}
	if string(head) != walMagic {
		t.Fatalf("migrated WAL missing v1 magic")
	}
}

// --- InstallSnapshot ACK regressions ---
//
// The leader used to advance matchIndex on transport success alone; a
// follower that refused the install (Restore failure, stale term) was
// still counted as caught-up, letting an uninstalled snapshot reach quorum.

// failingRestoreSM fails every Restore.
type failingRestoreSM struct{}

func (f *failingRestoreSM) Apply(entry) error         { return nil }
func (f *failingRestoreSM) Snapshot() ([]byte, error) { return nil, nil }
func (f *failingRestoreSM) Restore([]byte) error      { return errors.New("disk full") }

func TestHandleSnapshotRequest_RestoreFailureReturnsFailure(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "follower"
	node := NewNode(config, []NodeID{"leader"}, transport)
	node.SetStateMachine(&failingRestoreSM{})

	resp := node.HandleSnapshotRequest(SnapshotRequest{
		Term:      1,
		LeaderID:  "leader",
		Data:      []byte("snapshot-bytes"),
		LastIndex: 10,
		LastTerm:  1,
	})
	if resp.Success {
		t.Fatal("HandleSnapshotRequest reported Success despite Restore failure")
	}

	node.mu.Lock()
	lastSnap := node.lastSnapshot
	node.mu.Unlock()
	if lastSnap == 10 {
		t.Fatal("snapshot indices advanced despite Restore failure")
	}
}

func TestHandleSnapshotRequest_StaleTermRefused(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "follower"
	node := NewNode(config, []NodeID{"leader"}, transport)

	node.mu.Lock()
	node.currentTerm = 5
	node.mu.Unlock()

	resp := node.HandleSnapshotRequest(SnapshotRequest{Term: 3, LeaderID: "leader", LastIndex: 10, LastTerm: 3})
	if resp.Success {
		t.Fatal("stale-term snapshot install must not report Success")
	}
	if resp.Term != 5 {
		t.Fatalf("response Term = %d, want 5", resp.Term)
	}
}

// ackTransport lets the test script SendSnapshot responses.
type ackTransport struct {
	resp *SnapshotResponse
	err  error
	sent chan struct{}
}

func (a *ackTransport) SendRequestVote(context.Context, NodeID, VoteRequest) (*VoteResponse, error) {
	return &VoteResponse{}, nil
}
func (a *ackTransport) SendAppendEntries(context.Context, NodeID, AppendRequest) (*AppendResponse, error) {
	return &AppendResponse{}, nil
}
func (a *ackTransport) SendSnapshot(context.Context, NodeID, SnapshotRequest) (*SnapshotResponse, error) {
	defer func() {
		select {
		case a.sent <- struct{}{}:
		default:
		}
	}()
	return a.resp, a.err
}

func leaderMatchIndexAfterSnapshot(t *testing.T, resp *SnapshotResponse, sendErr error) Index {
	t.Helper()
	tr := &ackTransport{resp: resp, err: sendErr, sent: make(chan struct{}, 1)}
	config := DefaultConfig()
	config.NodeID = "leader"
	node := NewNode(config, []NodeID{"follower"}, tr)

	node.mu.Lock()
	node.state = StateLeader
	node.currentTerm = 2
	node.matchIndex["follower"] = 0
	node.nextIndex["follower"] = 1
	node.mu.Unlock()

	node.sendInstallSnapshot("follower", SnapshotRequest{
		Term: 2, LeaderID: "leader", Data: []byte("snap"), LastIndex: 42, LastTerm: 2,
	})

	select {
	case <-tr.sent:
	case <-time.After(3 * time.Second):
		t.Fatal("SendSnapshot never called")
	}
	// The goroutine updates matchIndex after the RPC returns; poll briefly.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		node.mu.Lock()
		mi := node.matchIndex["follower"]
		node.mu.Unlock()
		if mi == 42 {
			return mi
		}
		time.Sleep(5 * time.Millisecond)
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	return node.matchIndex["follower"]
}

func TestSendInstallSnapshot_AdvancesOnlyOnAck(t *testing.T) {
	if got := leaderMatchIndexAfterSnapshot(t, &SnapshotResponse{Term: 2, Success: true}, nil); got != 42 {
		t.Fatalf("matchIndex after ACK = %d, want 42", got)
	}
	if got := leaderMatchIndexAfterSnapshot(t, &SnapshotResponse{Term: 2, Success: false}, nil); got != 0 {
		t.Fatalf("matchIndex after NACK = %d, want 0", got)
	}
	if got := leaderMatchIndexAfterSnapshot(t, nil, errors.New("conn reset")); got != 0 {
		t.Fatalf("matchIndex after transport error = %d, want 0", got)
	}
}

// --- applyEntryWithRetry regressions ---
//
// A failed Apply used to be logged and SKIPPED (appliedIndex advanced
// anyway), silently diverging the node from the committed log.

func TestApplyEntryWithRetry_TransientFailureHeals(t *testing.T) {
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	attempts := 0
	apply := func(entry) error {
		attempts++
		if attempts < 3 {
			return errors.New("transient I/O error")
		}
		return nil
	}
	stopCh := make(chan struct{})
	if err := applyEntryWithRetry(apply, entry{Index: 7, Term: 1}, stopCh, logger); err != nil {
		t.Fatalf("applyEntryWithRetry: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestApplyEntryWithRetry_StopUnblocksWithError(t *testing.T) {
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	apply := func(entry) error { return errors.New("permanent failure") }
	stopCh := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- applyEntryWithRetry(apply, entry{Index: 9, Term: 1}, stopCh, logger)
	}()
	time.Sleep(50 * time.Millisecond)
	close(stopCh)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error on shutdown with unapplied entry")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("applyEntryWithRetry did not stop on stopCh close")
	}
}
