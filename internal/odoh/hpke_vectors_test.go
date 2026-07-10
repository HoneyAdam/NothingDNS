package odoh

// RFC 9180 Appendix A.1 test vectors for
//   DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, mode_base.
//
// The vectors below are copied verbatim from
// https://datatracker.ietf.org/doc/html/rfc9180#section-a.1
//
// We test the deterministic parts of the implementation against these:
//
//   1. KeySchedule(shared_secret, info)  →  key, base_nonce, exporter_secret
//   2. Context.Seal(aad, pt) for sequence numbers 0..N
//   3. DHKEM ExtractAndExpand reproduces the published shared_secret
//      when fed the published DH output and kem_context.
//
// We deliberately do NOT test Encap with a fake RNG — the goal is to
// prove our KDF/AEAD/KEM math matches the spec, not to verify
// crypto/ecdh's clamping behavior (which Go stdlib already covers).

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

// TestHPKE_RFC9180_A1_KeySchedule verifies that, given the published
// shared_secret and info, our KeySchedule derives the same AEAD
// base_nonce and AEAD key as RFC 9180 §A.1.1. The base_nonce is
// exposed directly on the context. The AEAD key is verified
// indirectly by sealing the canonical "Count-0" / "Beauty is truth"
// payload (§A.1.1.1, Encryption[0]) and comparing the ciphertext.
func TestHPKE_RFC9180_A1_KeySchedule(t *testing.T) {
	suite := defaultHPKESuite()

	sharedSecret := mustHex(t, "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc")
	info := mustHex(t, "4f6465206f6e2061204772656369616e2055726e")

	ctx, err := suite.keySchedule(sharedSecret, info)
	if err != nil {
		t.Fatalf("keySchedule: %v", err)
	}

	wantBaseNonce := mustHex(t, "56d890e5accaaf011cff4b7d")
	if !bytes.Equal(ctx.baseNonce, wantBaseNonce) {
		t.Fatalf("base_nonce:\n got %x\nwant %x", ctx.baseNonce, wantBaseNonce)
	}

	// RFC 9180 §A.1.1: exporter_secret and a Context.Export value. Validates the
	// exporter derivation ODoH now uses to bind the response key to the DH
	// secret.
	wantExporterSecret := mustHex(t, "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8")
	if !bytes.Equal(ctx.exporterSecret, wantExporterSecret) {
		t.Fatalf("exporter_secret:\n got %x\nwant %x", ctx.exporterSecret, wantExporterSecret)
	}
	// exporter_context = "" (L=32) → 3853fe2b...
	exp, err := ctx.export(nil, 32)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	wantExport := mustHex(t, "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee")
	if !bytes.Equal(exp, wantExport) {
		t.Fatalf("export(\"\",32):\n got %x\nwant %x", exp, wantExport)
	}

	// RFC 9180 §A.1.1.1 Encryption[0]:
	//   aad: Count-0
	//   pt:  "Beauty is truth, truth beauty"
	//   ct:  f938558b...321c4655dba6a7
	aad := []byte("Count-0")
	pt := []byte("Beauty is truth, truth beauty")
	// 29-byte pt + 16-byte GCM tag = 45-byte ct.
	wantCT := mustHex(t, "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a")

	ct, err := ctx.seal(aad, pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !bytes.Equal(ct, wantCT) {
		t.Errorf("seal[0]:\n got %x\nwant %x", ct, wantCT)
	}
}

// TestHPKE_RFC9180_A1_DHKEM verifies that ExtractAndExpand reproduces
// the published shared_secret when fed the published DH and kem_context.
func TestHPKE_RFC9180_A1_DHKEM(t *testing.T) {
	suite := defaultHPKESuite()

	// From RFC 9180 §A.1.1:
	//   skRm = 4612c550...    (recipient private key bytes after X25519 clamping)
	//   pkEm = 37fda356...    (sender ephemeral public key)
	//   pkRm = 3948cfe0...    (recipient public key)
	//
	// dh = DH(skRm, pkEm) which X25519 computes; the canonical value is
	// implied by the spec — we recompute it via crypto/ecdh to avoid
	// re-encoding it from a separate vector, since the point of this
	// test is the KEM extract+expand, not Go's X25519.
	skRm := mustHex(t, "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
	pkEm := mustHex(t, "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
	pkRm := mustHex(t, "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")

	skR, err := ecdh.X25519().NewPrivateKey(skRm)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	pkE, err := ecdh.X25519().NewPublicKey(pkEm)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	dh, err := skR.ECDH(pkE)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}

	kemContext := append([]byte{}, pkEm...)
	kemContext = append(kemContext, pkRm...)

	got, err := suite.extractAndExpand(dh, kemContext)
	if err != nil {
		t.Fatalf("extractAndExpand: %v", err)
	}
	want := mustHex(t, "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc")
	if !bytes.Equal(got, want) {
		t.Errorf("DHKEM shared_secret:\n got %x\nwant %x", got, want)
	}
}

func TestHPKELabeledExpandLengthBounds(t *testing.T) {
	suite := defaultHPKESuite()
	hashSize := suite.hkdfHash()().Size()
	maxLen := 255 * hashSize
	prk := make([]byte, hashSize)

	if _, err := suite.labeledExpand(prk, []byte("test"), nil, -1, labelKindHPKE); err == nil {
		t.Fatal("expected negative LabeledExpand length to fail")
	}
	if _, err := suite.labeledExpand(prk, []byte("test"), nil, maxLen+1, labelKindHPKE); err == nil {
		t.Fatal("expected over-HKDF-limit LabeledExpand length to fail")
	}
	if _, err := suite.labeledExpand(prk, []byte("test"), nil, 65536, labelKindHPKE); err == nil {
		t.Fatal("expected oversized LabeledExpand length to fail")
	}
	if got, err := suite.labeledExpand(prk, []byte("test"), nil, maxLen, labelKindHPKE); err != nil {
		t.Fatalf("max LabeledExpand length failed: %v", err)
	} else if len(got) != maxLen {
		t.Fatalf("LabeledExpand length = %d, want %d", len(got), maxLen)
	}
}
