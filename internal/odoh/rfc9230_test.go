package odoh

// RFC 9230 / RFC 9180 end-to-end round-trip tests.

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

// rfc9230MockHandler returns a fixed response for any query so we can
// assert the round-trip identity.
type rfc9230MockHandler struct {
	response *protocol.Message
}

func (h *rfc9230MockHandler) ServeDNS(w server.ResponseWriter, _ *protocol.Message) {
	if h.response != nil {
		_, _ = w.Write(h.response)
	}
}

// TestRFC9230RoundTrip exercises the full ODoH flow with the conformant
// HPKE implementation:
//
//  1. Build target with a fresh HPKE key pair.
//  2. Fetch its ObliviousDoHConfigContents.
//  3. Encrypt a DNS query under RFC 9230 §4.1.1 (HPKE base mode).
//  4. POST to the target's ServeHTTP.
//  5. Decrypt the response under RFC 9230 §4.1.2 (response-key
//     derivation from query plaintext + ephemeral pk).
//  6. Confirm the decrypted DNS answer matches what the handler emitted.
func TestRFC9230RoundTrip(t *testing.T) {
	// Build a mock DNS response that the target's handler will produce.
	respMsg, err := protocol.NewQuery(0xbeef, "example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}
	respMsg.Header.Flags.QR = true
	respMsg.Header.Flags.AA = true
	rr, err := protocol.NewResourceRecord(
		"example.com.", protocol.TypeA, protocol.ClassIN, 300,
		&protocol.RDataA{Address: [4]byte{93, 184, 216, 34}},
	)
	if err != nil {
		t.Fatalf("NewResourceRecord: %v", err)
	}
	respMsg.Answers = append(respMsg.Answers, rr)
	respMsg.Header.ANCount = 1

	target, err := NewObliviousTarget(
		NewODoHConfig("target.example.com", "proxy.example.com"),
		&rfc9230MockHandler{response: respMsg},
	)
	if err != nil {
		t.Fatalf("NewObliviousTarget: %v", err)
	}

	// Build a DNS query in wire format.
	queryMsg, err := protocol.NewQuery(0xbeef, "example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("NewQuery query: %v", err)
	}
	queryWire := make([]byte, queryMsg.WireLength())
	if _, err := queryMsg.Pack(queryWire); err != nil {
		t.Fatalf("Pack: %v", err)
	}

	// Client side: encrypt under the target's published config.
	msgBytes, qCtx, err := encryptQueryRFC9230(target.ConfigContents(), queryWire)
	if err != nil {
		t.Fatalf("encryptQueryRFC9230: %v", err)
	}

	// POST it through the target's HTTP handler.
	req := httptest.NewRequest("POST", "https://target/dns-query", bytes.NewReader(msgBytes))
	req.Header.Set("Content-Type", "application/oblivious-dns-message")
	w := httptest.NewRecorder()
	target.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("ServeHTTP status = %d, body = %q", w.Code, w.Body.String())
	}
	respBytes := w.Body.Bytes()

	// Client side: decrypt the response. The plaintext envelope used for
	// the response key derivation is the same plaintext the target saw
	// when opening the query — for the client it's the bytes it sealed,
	// reconstructed here.
	clientQueryPlain := append([]byte(nil), u16BE(uint16(len(queryWire)))...)
	clientQueryPlain = append(clientQueryPlain, queryWire...)
	clientQueryPlain = append(clientQueryPlain, u16BE(0)...) // pad_len = 0

	plain, err := qCtx.decryptResponse(respBytes, clientQueryPlain)
	if err != nil {
		t.Fatalf("decryptResponse: %v", err)
	}

	got, err := protocol.UnpackMessage(plain)
	if err != nil {
		t.Fatalf("UnpackMessage response: %v", err)
	}
	if got.Header.ID != 0xbeef {
		t.Errorf("response ID = %#x, want 0xbeef", got.Header.ID)
	}
	if len(got.Answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(got.Answers))
	}
	if a, ok := got.Answers[0].Data.(*protocol.RDataA); !ok || a.Address != [4]byte{93, 184, 216, 34} {
		t.Errorf("answer A = %+v, want 93.184.216.34", got.Answers[0].Data)
	}
}

// TestRFC9230_WrongKeyID confirms the target rejects messages framed
// with an incorrect key_id (e.g. addressed to a different target key).
func TestRFC9230_WrongKeyID(t *testing.T) {
	target, err := NewObliviousTarget(
		NewODoHConfig("target.example.com", "proxy.example.com"),
		&rfc9230MockHandler{},
	)
	if err != nil {
		t.Fatalf("NewObliviousTarget: %v", err)
	}

	// Encrypt to a *different* target's config (fresh key pair) so the
	// key_id won't match.
	other, err := newODoHKeyPair()
	if err != nil {
		t.Fatalf("newODoHKeyPair: %v", err)
	}
	msgBytes, _, err := encryptQueryRFC9230(other.configBytes, []byte{0, 0})
	if err != nil {
		t.Fatalf("encryptQueryRFC9230: %v", err)
	}

	req := httptest.NewRequest("POST", "https://target/dns-query", bytes.NewReader(msgBytes))
	w := httptest.NewRecorder()
	target.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400 for wrong key_id, got %d", w.Code)
	}
}

// TestRFC9230_ConfigsObjectShape verifies the outer-wrapped
// ObliviousDoHConfigs object has the expected header so clients can
// parse it.
func TestRFC9230_ConfigsObjectShape(t *testing.T) {
	target, err := NewObliviousTarget(
		NewODoHConfig("target.example.com", "proxy.example.com"),
		&rfc9230MockHandler{},
	)
	if err != nil {
		t.Fatalf("NewObliviousTarget: %v", err)
	}
	cfgs := target.ConfigsObject()
	// Outer: u16 total_length || inner (version u16 || length u16 || contents).
	if len(cfgs) < 6 {
		t.Fatalf("ConfigsObject too short: %d bytes", len(cfgs))
	}
	innerLen := uint16(cfgs[0])<<8 | uint16(cfgs[1])
	if int(innerLen)+2 != len(cfgs) {
		t.Errorf("outer length %d, want %d", innerLen, len(cfgs)-2)
	}
	version := uint16(cfgs[2])<<8 | uint16(cfgs[3])
	if version != 0x0001 {
		t.Errorf("version = %#x, want 0x0001", version)
	}
}
