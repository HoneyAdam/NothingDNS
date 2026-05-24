package raft

// Fuzz tests for the Raft wire-format decoders. AppendRequest,
// VoteRequest, SnapshotRequest, EntrySlice and snapshot files are
// all read from data an attacker controls (a malicious peer in the
// keyring, or a planted on-disk snapshot file). The decoders must
// never panic on adversarial input — every length field they decode
// is consumed by a slice or make() call that would crash the daemon
// if left unchecked.

import (
	"bytes"
	"testing"
)

func FuzzDecodeVoteRequest(f *testing.F) {
	// Seeds: empty, truncated, and a real round-trip-encoded message.
	f.Add([]byte{})
	f.Add(make([]byte, 27)) // one byte short of the 28-byte minimum
	if b, err := encodeVoteRequest(VoteRequest{Term: 7, CandidateID: "n1", LastLogIndex: 3, LastLogTerm: 2}); err == nil {
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var v VoteRequest
		_ = decodeVoteRequest(&v, data)
	})
}

func FuzzDecodeAppendRequest(f *testing.F) {
	f.Add([]byte{})
	if b, err := encodeAppendRequest(AppendRequest{
		Term:         1,
		LeaderID:     "leader",
		PrevLogIndex: 0,
		PrevLogTerm:  0,
		LeaderCommit: 0,
	}); err == nil {
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var a AppendRequest
		_ = decodeAppendRequest(&a, data)
	})
}

func FuzzDecodeSnapshotRequest(f *testing.F) {
	f.Add([]byte{})
	if b, err := encodeSnapshotRequest(SnapshotRequest{
		Term:      1,
		LeaderID:  "leader",
		LastIndex: 5,
		LastTerm:  1,
		Data:      []byte("snap"),
	}); err == nil {
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var s SnapshotRequest
		_ = decodeSnapshotRequest(&s, data)
	})
}

func FuzzDecodeEntrySlice(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0}) // count=0
	if b, err := encodeEntrySlice([]entry{
		{Index: 1, Term: 1, Type: EntryNormal, Command: []byte("hi"), Commitment: 0},
	}); err == nil {
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var got []entry
		_ = decodeEntrySlice(&got, data)
	})
}

// FuzzReadSnapshot drives the on-disk snapshot decoder with arbitrary
// bytes. b9f0ed5 added length-field caps so a planted file can't
// drive runaway make() allocations; this fuzzer exercises every
// length-decode site without those caps having to fire.
func FuzzReadSnapshot(f *testing.F) {
	snap, err := NewSnapshotter(f.TempDir())
	if err != nil {
		f.Skip("NewSnapshotter:", err)
	}

	// Seed: 4×8 zero header + zero dataLen + zero mCount = valid empty snapshot.
	f.Add(make([]byte, 32+8+4))
	// Pure garbage and short.
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = snap.readSnapshot(bytes.NewReader(data))
	})
}
