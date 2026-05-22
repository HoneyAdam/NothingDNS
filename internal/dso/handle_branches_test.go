package dso

// Tests for HandleDSORequest's per-TLV-type branches. Lifts dso
// coverage by driving each switch arm of the TLV processing loop
// through real RawBody bytes (the same path a real DSO client takes).

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// packTLV builds an RFC 8490 TLV: type(2) || length(2) || value
func packTLV(typ uint16, value []byte) []byte {
	out := make([]byte, 4+len(value))
	binary.BigEndian.PutUint16(out[0:2], typ)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(value)))
	copy(out[4:], value)
	return out
}

// dsoMessage wraps a TLV stream in the OPCODE-DSO header form
// HandleDSORequest expects.
func dsoMessage(tlvs ...[]byte) *protocol.Message {
	var body []byte
	for _, t := range tlvs {
		body = append(body, t...)
	}
	return &protocol.Message{
		Header: protocol.Header{
			ID:    0,
			Flags: protocol.Flags{Opcode: protocol.OpcodeDSO},
		},
		RawBody: body,
	}
}

// freshSession returns a non-nil DSO session usable as the request peer.
func freshSession() *Session {
	return &Session{
		ID:         1,
		MaxPayload: 65535,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
}

func TestHandleDSORequest_Keepalive(t *testing.T) {
	m := NewManager(DefaultConfig(), nil)
	sess := freshSession()

	// RFC 8490 §4.1: Keepalive TLV body = primary(4) || secondary(4),
	// both in 100-ms units. 15s = 150 units, 60s = 600 units.
	body := make([]byte, 8)
	binary.BigEndian.PutUint32(body[0:4], 150)
	binary.BigEndian.PutUint32(body[4:8], 600)

	resp, err := m.HandleDSORequest(sess, dsoMessage(packTLV(DSOTLVKeepalive, body)))
	if err != nil {
		t.Fatalf("HandleDSORequest: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !sess.keepalivesEnabled {
		t.Error("keepalivesEnabled should be true after Keepalive TLV")
	}
	if sess.KeepaliveTime != 15*time.Second {
		t.Errorf("KeepaliveTime = %v, want 15s", sess.KeepaliveTime)
	}
}

func TestHandleDSORequest_MaximumPayload_ShrinksOnRequest(t *testing.T) {
	m := NewManager(DefaultConfig(), nil)
	sess := freshSession()
	// Send a smaller-than-default max payload (4096); session should adopt it.
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, 4096)

	_, err := m.HandleDSORequest(sess, dsoMessage(packTLV(DSOTLVMaximumPayload, body)))
	if err != nil {
		t.Fatalf("HandleDSORequest: %v", err)
	}
	if sess.MaxPayload != 4096 {
		t.Errorf("MaxPayload = %d, want 4096 (shrunk from 65535)", sess.MaxPayload)
	}
}

func TestHandleDSORequest_MaximumPayload_NoGrowOverSessionCap(t *testing.T) {
	m := NewManager(DefaultConfig(), nil)
	sess := freshSession()
	sess.MaxPayload = 8192 // pre-set session cap
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, 65000) // client wants more

	_, err := m.HandleDSORequest(sess, dsoMessage(packTLV(DSOTLVMaximumPayload, body)))
	if err != nil {
		t.Fatalf("HandleDSORequest: %v", err)
	}
	if sess.MaxPayload != 8192 {
		t.Errorf("MaxPayload = %d, want 8192 (client may not raise it)", sess.MaxPayload)
	}
}

func TestHandleDSORequest_Padding_Ignored(t *testing.T) {
	// Padding TLVs in requests are explicitly ignored — no error, no
	// response TLV added.
	m := NewManager(DefaultConfig(), nil)
	sess := freshSession()
	resp, err := m.HandleDSORequest(sess, dsoMessage(packTLV(DSOTLVPadding, []byte{0, 0, 0, 0})))
	if err != nil {
		t.Fatalf("HandleDSORequest: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestHandleDSORequest_RetryDelay_RejectedInRequest(t *testing.T) {
	// RetryDelay is a server→client-only TLV (RFC 8490 §6.6.1). When a
	// client sends one, the request must be rejected.
	m := NewManager(DefaultConfig(), nil)
	sess := freshSession()
	body := make([]byte, 4) // RetryDelay payload: uint32 ms
	binary.BigEndian.PutUint32(body, 5000)
	_, err := m.HandleDSORequest(sess, dsoMessage(packTLV(DSOTLVRetryDelay, body)))
	if err == nil {
		t.Error("expected error for client-side RetryDelay TLV")
	}
}

func TestHandleDSORequest_UnknownTLV_Rejected(t *testing.T) {
	// Per RFC 8490 §8.2 the server returns DSO TYPE NOT IMPLEMENTED
	// (or in our implementation, an error) for unknown primary TLVs.
	m := NewManager(DefaultConfig(), nil)
	sess := freshSession()
	_, err := m.HandleDSORequest(sess, dsoMessage(packTLV(0x7FFF, []byte{1, 2, 3})))
	if err == nil {
		t.Error("expected error for unknown TLV type")
	}
}

func TestHandleDSORequest_MultipleTLVsInOneRequest(t *testing.T) {
	// A DSO message can carry multiple TLVs back-to-back. Confirm
	// both branches fire and the session state reflects both.
	m := NewManager(DefaultConfig(), nil)
	sess := freshSession()

	// 5s = 50 units, 30s = 300 units (100ms each per RFC 8490).
	keepalive := make([]byte, 8)
	binary.BigEndian.PutUint32(keepalive[0:4], 50)
	binary.BigEndian.PutUint32(keepalive[4:8], 300)
	mp := make([]byte, 2)
	binary.BigEndian.PutUint16(mp, 16000)

	_, err := m.HandleDSORequest(sess, dsoMessage(
		packTLV(DSOTLVKeepalive, keepalive),
		packTLV(DSOTLVMaximumPayload, mp),
	))
	if err != nil {
		t.Fatalf("HandleDSORequest: %v", err)
	}
	if !sess.keepalivesEnabled {
		t.Error("keepalive should be enabled")
	}
	if sess.MaxPayload != 16000 {
		t.Errorf("MaxPayload = %d, want 16000", sess.MaxPayload)
	}
}
