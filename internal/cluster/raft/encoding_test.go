package raft

// Round-trip tests for the Raft wire-format encoders/decoders that
// have lived at 0% coverage. These are pure binary marshalers — no
// network, no goroutines, easy to drive through known values.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"testing"

	"github.com/nothingdns/nothingdns/internal/util"
)

func testAEAD(t *testing.T) cipher.AEAD {
	t.Helper()
	// Fixed 32-byte key → AES-256-GCM, matching the cluster's transport cipher.
	key := bytes.Repeat([]byte{0x42}, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	return aead
}

// TestFrameAEADRoundTrip guards against regressing the nonce-on-the-wire bug
// (Seal(nonceBuf[:0], ...) dropped the nonce, making encrypted clusters
// undecryptable). The encrypted RPC framing path previously had zero coverage.
func TestFrameAEADRoundTrip(t *testing.T) {
	req := AppendRequest{
		Term:         9,
		LeaderID:     "leader-1",
		PrevLogIndex: 3,
		PrevLogTerm:  8,
		LeaderCommit: 2,
		Entries: []entry{
			{Index: 4, Term: 9, Command: []byte("set a=1")},
			{Index: 5, Term: 9, Command: []byte("set b=2")},
		},
	}

	var buf bytes.Buffer
	fw := newFrameWriter(&buf, testAEAD(t))
	if err := fw.writeFramed(msgTypeAppendRequest, req); err != nil {
		t.Fatalf("writeFramed: %v", err)
	}

	// The framed payload must be longer than the plaintext by at least
	// nonce+tag — proving the nonce is actually on the wire.
	aead := testAEAD(t)
	wireLen := binary.BigEndian.Uint32(buf.Bytes()[1:frameHeaderSize])
	if int(wireLen) <= aead.NonceSize()+aead.Overhead() {
		t.Fatalf("ciphertext length %d does not include nonce+tag", wireLen)
	}

	fr := newFrameReader(bytes.NewReader(buf.Bytes()), aead)
	var got AppendRequest
	msgType, err := fr.readFramed(&got)
	if err != nil {
		t.Fatalf("readFramed (encrypted): %v", err)
	}
	if msgType != msgTypeAppendRequest {
		t.Fatalf("msgType = %d, want %d", msgType, msgTypeAppendRequest)
	}
	if got.Term != req.Term || got.LeaderID != req.LeaderID || len(got.Entries) != len(req.Entries) {
		t.Fatalf("decoded AppendRequest = %+v, want %+v", got, req)
	}
	for i := range req.Entries {
		if !bytes.Equal(got.Entries[i].Command, req.Entries[i].Command) {
			t.Fatalf("entry %d command = %q, want %q", i, got.Entries[i].Command, req.Entries[i].Command)
		}
	}
}

// TestDecodeEntrySlice_HugeCmdLenRejected guards the V15 bounds check: an entry
// declaring a near-uint32-max command length must be rejected (not panic, not
// attempt a huge allocation). On 32-bit platforms the previous int arithmetic
// could overflow and bypass this guard.
func TestDecodeEntrySlice_HugeCmdLenRejected(t *testing.T) {
	data := make([]byte, 29)
	binary.BigEndian.PutUint32(data[0:], 1) // count = 1
	// entry: index[4:12], term[12:20], type[20], cmdLen[21:25]
	binary.BigEndian.PutUint32(data[21:], 0xFFFFFFFF)

	var entries []entry
	err := decodeEntrySlice(&entries, data)
	if err == nil {
		t.Fatal("expected overflow error for oversized cmdLen, got nil")
	}
}

// TestFrameAEADTamperRejected confirms the AAD/tag actually authenticates the
// frame: flipping a ciphertext byte must fail Open rather than decode garbage.
func TestFrameAEADTamperRejected(t *testing.T) {
	var buf bytes.Buffer
	fw := newFrameWriter(&buf, testAEAD(t))
	if err := fw.writeFramed(msgTypeVoteRequest, VoteRequest{Term: 1, CandidateID: "x"}); err != nil {
		t.Fatalf("writeFramed: %v", err)
	}
	b := buf.Bytes()
	b[len(b)-1] ^= 0xFF // flip a tag byte

	fr := newFrameReader(bytes.NewReader(b), testAEAD(t))
	var got VoteRequest
	if _, err := fr.readFramed(&got); err == nil {
		t.Fatal("expected AEAD open failure on tampered frame, got nil")
	}
}

func TestFrameWriterCompletesPartialWrites(t *testing.T) {
	w := &chunkedWriter{maxWrite: 2}
	req := VoteRequest{
		Term:         7,
		CandidateID:  "node-a",
		LastLogIndex: 42,
		LastLogTerm:  6,
	}

	fw := newFrameWriter(w, nil)
	if err := fw.writeFramed(msgTypeVoteRequest, req); err != nil {
		t.Fatalf("writeFramed: %v", err)
	}
	if w.calls < 2 {
		t.Fatalf("chunked writer should require multiple writes, got %d", w.calls)
	}

	fr := newFrameReader(bytes.NewReader(w.buf.Bytes()), nil)
	var got VoteRequest
	msgType, err := fr.readFramed(&got)
	if err != nil {
		t.Fatalf("readFramed: %v", err)
	}
	if msgType != msgTypeVoteRequest {
		t.Fatalf("msgType = %d, want %d", msgType, msgTypeVoteRequest)
	}
	if got != req {
		t.Fatalf("VoteRequest = %+v, want %+v", got, req)
	}
}

func TestWriteAllRejectsZeroProgress(t *testing.T) {
	err := util.WriteFull(zeroProgressWriter{}, []byte{1})
	if err != io.ErrNoProgress {
		t.Fatalf("WriteFull error = %v, want %v", err, io.ErrNoProgress)
	}
}

type chunkedWriter struct {
	buf      bytes.Buffer
	maxWrite int
	calls    int
}

func (w *chunkedWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.maxWrite <= 0 || len(p) <= w.maxWrite {
		return w.buf.Write(p)
	}
	return w.buf.Write(p[:w.maxWrite])
}

type zeroProgressWriter struct{}

func (zeroProgressWriter) Write([]byte) (int, error) {
	return 0, nil
}

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

// TestDecodeAppendRequest_TruncatedLeaderCommit pins the trailing-field
// bound check added alongside encoding.go:353. A peer that packs
// entriesLen to consume every remaining byte leaves data[off:] empty
// at the LeaderCommit read site — without the guard, the Uint64 call
// panics with index-out-of-range, giving any keyring peer a one-message
// DoS against every Raft member. The corpus seed
// FuzzDecodeAppendRequest/8a11b8a6ad0520c7 originally tripped this.
func TestDecodeAppendRequest_TruncatedLeaderCommit(t *testing.T) {
	// Build a minimal AppendRequest body where entries fill the buffer.
	//   Term(8) + leaderLen(4)=0 + LeaderID(0) + PrevLogIndex(8) +
	//   PrevLogTerm(8) + entriesLen(4) + entries(N) — and NO LeaderCommit.
	// Set entriesLen = 4 and use 4 trailing bytes that decodeEntrySlice
	// accepts (count=0 → empty entries), so the trailing slice is fully
	// consumed before the LeaderCommit read.
	buf := make([]byte, 0, 36)
	buf = append(buf, 0, 0, 0, 0, 0, 0, 0, 1) // Term = 1
	buf = append(buf, 0, 0, 0, 0)             // leaderLen = 0
	buf = append(buf, 0, 0, 0, 0, 0, 0, 0, 0) // PrevLogIndex
	buf = append(buf, 0, 0, 0, 0, 0, 0, 0, 0) // PrevLogTerm
	buf = append(buf, 0, 0, 0, 4)             // entriesLen = 4 (consumes all remaining)
	buf = append(buf, 0, 0, 0, 0)             // entries body: count=0
	// LeaderCommit deliberately omitted.

	var a AppendRequest
	err := decodeAppendRequest(&a, buf)
	if err == nil {
		t.Fatal("expected error for truncated LeaderCommit, got nil")
	}
	if !contains(err.Error(), "LeaderCommit") {
		t.Errorf("error %q should mention LeaderCommit", err)
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
		byte(EntryNormal), // type
		0, 0, 0, 10,       // cmdLen
		// command bytes missing
	}
	var got []entry
	if err := decodeEntrySlice(&got, buf); err == nil {
		t.Error("expected error for cmd payload overflow")
	}
}
