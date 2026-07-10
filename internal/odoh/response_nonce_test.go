package odoh

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestRFC9230_ResponseNonceUnique is a security regression test for AES-GCM
// nonce reuse in ODoH response encryption. Replaying a byte-identical query
// must NOT produce responses sealed under the same (key, nonce): before the
// fix the response key+nonce were a deterministic function of (enc, query)
// only, so two responses to a replayed query reused the GCM nonce (enabling
// plaintext recovery and forgery by an untrusted proxy). Each response must now
// carry a fresh random response_nonce, yielding distinct ciphertexts that still
// decrypt correctly.
func TestRFC9230_ResponseNonceUnique(t *testing.T) {
	respMsg, err := protocol.NewQuery(0xbeef, "example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}
	respMsg.Header.Flags.QR = true
	rr, _ := protocol.NewResourceRecord("example.com.", protocol.TypeA, protocol.ClassIN, 300, &protocol.RDataA{Address: [4]byte{93, 184, 216, 34}})
	respMsg.Answers = append(respMsg.Answers, rr)
	respMsg.Header.ANCount = 1

	target, err := NewObliviousTarget(NewODoHConfig("target.example.com", "proxy.example.com"), &rfc9230MockHandler{response: respMsg})
	if err != nil {
		t.Fatalf("NewObliviousTarget: %v", err)
	}

	queryMsg, _ := protocol.NewQuery(0xbeef, "example.com.", protocol.TypeA)
	queryWire := make([]byte, queryMsg.WireLength())
	if _, err := queryMsg.Pack(queryWire); err != nil {
		t.Fatalf("Pack: %v", err)
	}

	// Encrypt ONE query; replay the identical ciphertext bytes twice.
	msgBytes, qCtx, err := encryptQueryRFC9230(target.ConfigContents(), queryWire)
	if err != nil {
		t.Fatalf("encryptQueryRFC9230: %v", err)
	}

	post := func() []byte {
		req := httptest.NewRequest("POST", "https://target/dns-query", bytes.NewReader(msgBytes))
		req.Header.Set("Content-Type", "application/oblivious-dns-message")
		w := httptest.NewRecorder()
		target.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("ServeHTTP status = %d, body=%q", w.Code, w.Body.String())
		}
		return append([]byte(nil), w.Body.Bytes()...)
	}

	resp1 := post()
	resp2 := post()

	if bytes.Equal(resp1, resp2) {
		t.Fatal("replayed identical query produced byte-identical responses — AES-GCM nonce reuse")
	}

	// Both must still decrypt to the same DNS answer.
	clientQueryPlain := append([]byte(nil), u16BE(uint16(len(queryWire)))...)
	clientQueryPlain = append(clientQueryPlain, queryWire...)
	clientQueryPlain = append(clientQueryPlain, u16BE(0)...)

	for i, resp := range [][]byte{resp1, resp2} {
		plain, err := qCtx.decryptResponse(resp, clientQueryPlain)
		if err != nil {
			t.Fatalf("decryptResponse #%d: %v", i, err)
		}
		got, err := protocol.UnpackMessage(plain)
		if err != nil {
			t.Fatalf("UnpackMessage #%d: %v", i, err)
		}
		if got.Header.ID != 0xbeef || len(got.Answers) != 1 {
			t.Errorf("response #%d wrong: id=%#x answers=%d", i, got.Header.ID, len(got.Answers))
		}
	}
}
