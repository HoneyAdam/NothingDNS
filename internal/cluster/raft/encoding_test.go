package raft

// Round-trip tests for the Raft wire-format encoders/decoders that
// have lived at 0% coverage. These are pure binary marshalers — no
// network, no goroutines, easy to drive through known values.

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEncodeDecodeVoteResponse(t *testing.T) {
	orig := VoteResponse{
		Term:        7,
		VoteGranted: true,
		From:        "node-alpha",
	}
	buf, err := encodeVoteResponse(orig)
	if err != nil {
		t.Fatalf("encodeVoteResponse: %v", err)
	}

	var got VoteResponse
	if err := decodeVoteResponse(&got, buf); err != nil {
		t.Fatalf("decodeVoteResponse: %v", err)
	}
	if got != orig {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, orig)
	}

	// Vote-not-granted variant exercises the false branch of the bool byte.
	orig2 := VoteResponse{Term: 9, VoteGranted: false, From: "x"}
	buf2, _ := encodeVoteResponse(orig2)
	var got2 VoteResponse
	if err := decodeVoteResponse(&got2, buf2); err != nil {
		t.Fatalf("decodeVoteResponse (false): %v", err)
	}
	if got2 != orig2 {
		t.Errorf("false-vote round-trip: got %+v, want %+v", got2, orig2)
	}
}

func TestDecodeVoteResponse_TruncatedData(t *testing.T) {
	var got VoteResponse
	if err := decodeVoteResponse(&got, []byte{0x01, 0x02}); err == nil {
		t.Error("expected error for truncated VoteResponse")
	}
}

func TestEncodeDecodeAppendRequest_Empty(t *testing.T) {
	orig := AppendRequest{
		Term:         3,
		LeaderID:     "leader-1",
		PrevLogIndex: 12,
		PrevLogTerm:  2,
		Entries:      nil,
		LeaderCommit: 10,
	}
	buf, err := encodeAppendRequest(orig)
	if err != nil {
		t.Fatalf("encodeAppendRequest: %v", err)
	}

	var got AppendRequest
	if err := decodeAppendRequest(&got, buf); err != nil {
		t.Fatalf("decodeAppendRequest: %v", err)
	}
	if got.Term != orig.Term || got.LeaderID != orig.LeaderID ||
		got.PrevLogIndex != orig.PrevLogIndex || got.PrevLogTerm != orig.PrevLogTerm ||
		got.LeaderCommit != orig.LeaderCommit {
		t.Errorf("AppendRequest header round-trip mismatch: %+v vs %+v", got, orig)
	}
	if len(got.Entries) != 0 {
		t.Errorf("expected zero entries, got %d", len(got.Entries))
	}
}

func TestEncodeDecodeAppendRequest_WithEntries(t *testing.T) {
	orig := AppendRequest{
		Term:         5,
		LeaderID:     "leader",
		PrevLogIndex: 100,
		PrevLogTerm:  4,
		Entries: []entry{
			{Index: 101, Term: 5, Type: EntryNormal, Command: []byte("apply-this")},
			{Index: 102, Term: 5, Type: EntryNoOp, Commitment: 42},
		},
		LeaderCommit: 100,
	}
	buf, err := encodeAppendRequest(orig)
	if err != nil {
		t.Fatalf("encodeAppendRequest: %v", err)
	}

	var got AppendRequest
	if err := decodeAppendRequest(&got, buf); err != nil {
		t.Fatalf("decodeAppendRequest: %v", err)
	}
	if len(got.Entries) != len(orig.Entries) {
		t.Fatalf("entries len = %d, want %d", len(got.Entries), len(orig.Entries))
	}
	for i := range orig.Entries {
		o, g := orig.Entries[i], got.Entries[i]
		if o.Index != g.Index || o.Term != g.Term || o.Type != g.Type ||
			!bytes.Equal(o.Command, g.Command) || o.Commitment != g.Commitment {
			t.Errorf("entry %d mismatch: got %+v, want %+v", i, g, o)
		}
	}
}

func TestDecodeAppendRequest_TruncatedHeader(t *testing.T) {
	var got AppendRequest
	if err := decodeAppendRequest(&got, []byte{0, 0, 0, 0}); err == nil {
		t.Error("expected error for truncated AppendRequest header")
	}
}

func TestEncodeDecodeEntrySlice_RoundTrip(t *testing.T) {
	orig := []entry{
		{Index: 1, Term: 1, Type: EntryNormal, Command: []byte("a")},
		{Index: 2, Term: 1, Type: EntryAddNode, Command: []byte("node-9 127.0.0.1:7000")},
		{Index: 3, Term: 2, Type: EntryNoOp},
	}
	buf, err := encodeEntrySlice(orig)
	if err != nil {
		t.Fatalf("encodeEntrySlice: %v", err)
	}
	var got []entry
	if err := decodeEntrySlice(&got, buf); err != nil {
		t.Fatalf("decodeEntrySlice: %v", err)
	}
	if len(got) != len(orig) {
		t.Fatalf("len = %d, want %d", len(got), len(orig))
	}
	for i := range orig {
		o, g := orig[i], got[i]
		if o.Index != g.Index || o.Term != g.Term || o.Type != g.Type ||
			!bytes.Equal(o.Command, g.Command) {
			t.Errorf("entry %d: got %+v, want %+v", i, g, o)
		}
	}
}

func TestDecodeEntrySlice_TruncatedHeader(t *testing.T) {
	var got []entry
	if err := decodeEntrySlice(&got, []byte{0}); err == nil {
		t.Error("expected error for truncated count header")
	}
}

// TestDecodeEntrySlice_RejectsAttackerCount regresses e9687fe:
// decodeEntrySlice must cap the wire-supplied count against what the
// remaining buffer could physically hold (>= minEntryBytes per entry),
// rejecting before make([]entry, 0, count). Without the cap a peer
// could pack count = 2^32-1 into a small frame and the cap-allocation
// would request ~160 GB up front for the 40-byte entry struct, OOM-
// panicking the Raft member.
func TestDecodeEntrySlice_RejectsAttackerCount(t *testing.T) {
	// 4-byte count of 1,000,000 followed by nothing — clearly cannot
	// fit a million 25-byte entries in zero remaining bytes.
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, 1_000_000)

	var got []entry
	err := decodeEntrySlice(&got, buf)
	if err == nil {
		t.Fatal("expected error for impossible count, got nil")
	}
	// The regression test must hit the new make()-guard, NOT the
	// per-iteration overflow inside the loop. Pin to the guard's
	// distinctive wording so a future refactor that drops the cap
	// (and falls back to "entry %d overflow") fails this test.
	if !contains(err.Error(), "exceeds possible") {
		t.Errorf("error %q should mention 'exceeds possible' (the make-guard message)", err)
	}
}

func TestDecodeEntrySlice_TruncatedEntry(t *testing.T) {
	// Count = 1 but no entry body.
	buf := []byte{0, 0, 0, 1}
	var got []entry
	if err := decodeEntrySlice(&got, buf); err == nil {
		t.Error("expected error for entry body overflow")
	}
}

func TestDecodeEntrySlice_TruncatedCommandPayload(t *testing.T) {
	// One entry with cmdLen=10 but no command bytes following.
	buf := []byte{
		0, 0, 0, 1, // count
		0, 0, 0, 0, 0, 0, 0, 1, // index
		0, 0, 0, 0, 0, 0, 0, 1, // term
		byte(EntryNormal),      // type
		0, 0, 0, 10,            // cmdLen
		// command bytes missing
	}
	var got []entry
	if err := decodeEntrySlice(&got, buf); err == nil {
		t.Error("expected error for cmd payload overflow")
	}
}
