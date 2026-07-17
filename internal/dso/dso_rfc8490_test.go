package dso

import (
	"errors"
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// RFC 8490 §5.4: an unsolicited DSO response (QR=1) is a fatal protocol
// error — it must never be answered or treated as a request.
func TestHandleDSORequest_QRResponseIsFatal(t *testing.T) {
	m := NewManager(DefaultConfig(), nil)
	sess := freshSession()
	msg := dsoMessage(packTLV(DSOTLVKeepalive, make([]byte, 4)))
	msg.Header.Flags.QR = true

	resp, err := m.HandleDSORequest(sess, msg)
	if err == nil {
		t.Fatal("QR=1 DSO message must be a fatal error")
	}
	if !errors.Is(err, ErrDSOFatal) {
		t.Errorf("QR=1 error must wrap ErrDSOFatal, got %v", err)
	}
	if resp != nil {
		t.Error("must not produce a response to a DSO response")
	}
}

// Fatal framing errors (nonzero section counts) wrap ErrDSOFatal so the
// transport aborts; recoverable ones do not.
func TestHandleDSORequest_FramingErrorIsFatal(t *testing.T) {
	m := NewManager(DefaultConfig(), nil)
	sess := freshSession()
	msg := dsoMessage(packTLV(DSOTLVKeepalive, make([]byte, 4)))
	msg.Header.QDCount = 1 // §5.2 violation

	_, err := m.HandleDSORequest(sess, msg)
	if err == nil || !errors.Is(err, ErrDSOFatal) {
		t.Fatalf("nonzero section count must be fatal, got %v", err)
	}
}

// CreateSession returns ErrMaxSessions (wrapped) when the table is full,
// so the transport can answer SERVFAIL and keep the connection instead of
// aborting.
func TestCreateSession_MaxSessionsSentinel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxSessions = 1
	cfg.AllowPlainTCP = true
	m := NewManager(cfg, nil)

	c1, _ := net.Pipe()
	c2, _ := net.Pipe()
	if _, err := m.CreateSession(c1); err != nil {
		t.Fatalf("first session: %v", err)
	}
	_, err := m.CreateSession(c2)
	if err == nil {
		t.Fatal("expected ErrMaxSessions on a full table")
	}
	if !errors.Is(err, ErrMaxSessions) {
		t.Errorf("error must wrap ErrMaxSessions, got %v", err)
	}
}

// Ensure the DSOTYPENI RCODE is what RFC 8490 assigns.
func TestDSOTypeNIRcode(t *testing.T) {
	if protocol.RcodeDSOTypeNI != 11 {
		t.Fatalf("DSOTYPENI = %d, want 11", protocol.RcodeDSOTypeNI)
	}
}
