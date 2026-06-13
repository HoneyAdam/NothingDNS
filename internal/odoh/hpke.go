package odoh

// RFC 9180 (HPKE) base-mode primitives for the ODoH target/client.
//
// Implements suite (KEM=DHKEM(X25519, HKDF-SHA256), KDF=HKDF-SHA256,
// AEAD=AES-128-GCM). Other AEADs (AES-256-GCM, ChaCha20Poly1305) are
// straightforward extensions but kept out of scope to limit external
// dependencies — the project's zero-deps policy excludes
// golang.org/x/crypto/chacha20poly1305.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc9180
//
// Only base mode (mode_base = 0x00) is implemented. PSK/Auth modes are
// not needed for ODoH (RFC 9230 uses base mode exclusively).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
)

// HPKE algorithm IDs per the IANA registry (RFC 9180 §7).
const (
	hpkeKEMX25519HKDFSHA256 uint16 = 0x0020
	hpkeKDFHKDFSHA256       uint16 = 0x0001
	hpkeAEADAES128GCM       uint16 = 0x0001
	hpkeAEADAES256GCM       uint16 = 0x0002
)

// HPKE-v1 version label used in every LabeledExtract/LabeledExpand call.
var hpkeVersionLabel = []byte("HPKE-v1")

// Mode constants (RFC 9180 §5.1). Only base mode is used by ODoH.
const hpkeModeBase byte = 0x00

// Errors surfaced by the HPKE implementation.
var (
	errHPKEEncap = errors.New("hpke: encap failed")
	errHPKEDecap = errors.New("hpke: decap failed")
)

// HPKE suite combining KEM/KDF/AEAD IDs. The ODoH target/client both
// instantiate the suite "DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
// AES-128-GCM" by default.
type hpkeSuite struct {
	kemID, kdfID, aeadID uint16
}

func defaultHPKESuite() hpkeSuite {
	return hpkeSuite{
		kemID:  hpkeKEMX25519HKDFSHA256,
		kdfID:  hpkeKDFHKDFSHA256,
		aeadID: hpkeAEADAES128GCM,
	}
}

// suiteIDHPKE builds the suite_id used in HPKE LabeledExtract/Expand:
//
//	suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
func (s hpkeSuite) suiteIDHPKE() []byte {
	out := make([]byte, 0, 10)
	out = append(out, []byte("HPKE")...)
	out = appendU16BE(out, s.kemID)
	out = appendU16BE(out, s.kdfID)
	out = appendU16BE(out, s.aeadID)
	return out
}

// suiteIDKEM builds the suite_id for KEM-only operations (DHKEM
// extract/expand): "KEM" || I2OSP(kem_id, 2).
func (s hpkeSuite) suiteIDKEM() []byte {
	out := make([]byte, 0, 5)
	out = append(out, []byte("KEM")...)
	out = appendU16BE(out, s.kemID)
	return out
}

// hkdfHash returns the constructor for the KDF's hash. Only SHA-256 is
// supported; extend with SHA-384/SHA-512 if more KDFs are added.
func (s hpkeSuite) hkdfHash() func() hash.Hash {
	switch s.kdfID {
	case hpkeKDFHKDFSHA256:
		return sha256.New
	default:
		return nil
	}
}

// aeadKeyLen returns the AEAD key length in bytes (RFC 9180 §7.3).
func (s hpkeSuite) aeadKeyLen() int {
	switch s.aeadID {
	case hpkeAEADAES128GCM:
		return 16
	case hpkeAEADAES256GCM:
		return 32
	default:
		return 0
	}
}

// aeadNonceLen returns the AEAD nonce length (always 12 for GCM).
func (s hpkeSuite) aeadNonceLen() int { return 12 }

// kemSecretLen returns the byte length of the KEM shared secret. For
// DHKEM(X25519, HKDF-SHA256) this is 32 (Nsecret from RFC 9180 §7.1).
func (s hpkeSuite) kemSecretLen() int {
	switch s.kemID {
	case hpkeKEMX25519HKDFSHA256:
		return 32
	default:
		return 0
	}
}

// labeledExtract implements RFC 9180 §4 LabeledExtract:
//
//	labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
//	return Extract(salt, labeled_ikm)
//
// `kind` selects between KEM ("KEM"-prefixed) and HPKE ("HPKE"-prefixed)
// suite IDs — see RFC 9180 §4.1.
func (s hpkeSuite) labeledExtract(salt, label, ikm []byte, kind labelKind) ([]byte, error) {
	suiteID := s.suiteIDForKind(kind)
	labeled := make([]byte, 0, len(hpkeVersionLabel)+len(suiteID)+len(label)+len(ikm))
	labeled = append(labeled, hpkeVersionLabel...)
	labeled = append(labeled, suiteID...)
	labeled = append(labeled, label...)
	labeled = append(labeled, ikm...)
	return hkdf.Extract(s.hkdfHash(), labeled, salt)
}

// labeledExpand implements RFC 9180 §4 LabeledExpand:
//
//	labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
//	return Expand(prk, labeled_info, L)
func (s hpkeSuite) labeledExpand(prk, label, info []byte, length int, kind labelKind) ([]byte, error) {
	if length < 0 || length > 0xffff {
		return nil, fmt.Errorf("hpke: LabeledExpand length %d out of range 0-65535", length)
	}
	maxHKDFOutput := 255 * s.hkdfHash()().Size()
	if length > maxHKDFOutput {
		return nil, fmt.Errorf("hpke: LabeledExpand length %d exceeds HKDF limit %d", length, maxHKDFOutput)
	}
	suiteID := s.suiteIDForKind(kind)
	labeled := make([]byte, 0, 2+len(hpkeVersionLabel)+len(suiteID)+len(label)+len(info))
	labeled = appendU16BE(labeled, uint16(length))
	labeled = append(labeled, hpkeVersionLabel...)
	labeled = append(labeled, suiteID...)
	labeled = append(labeled, label...)
	labeled = append(labeled, info...)
	return hkdf.Expand(s.hkdfHash(), prk, string(labeled), length)
}

// labelKind discriminates KEM vs HPKE labeling contexts.
type labelKind int

const (
	labelKindKEM  labelKind = 0
	labelKindHPKE labelKind = 1
)

func (s hpkeSuite) suiteIDForKind(k labelKind) []byte {
	switch k {
	case labelKindKEM:
		return s.suiteIDKEM()
	default:
		return s.suiteIDHPKE()
	}
}

// extractAndExpand performs DHKEM ExtractAndExpand on a Diffie-Hellman
// shared secret (RFC 9180 §4.1):
//
//	eae_prk = LabeledExtract("", "eae_prk", dh)        [KEM suite_id]
//	shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
func (s hpkeSuite) extractAndExpand(dh, kemContext []byte) ([]byte, error) {
	prk, err := s.labeledExtract(nil, []byte("eae_prk"), dh, labelKindKEM)
	if err != nil {
		return nil, err
	}
	return s.labeledExpand(prk, []byte("shared_secret"), kemContext, s.kemSecretLen(), labelKindKEM)
}

// hpkeEncap performs DHKEM(X25519, HKDF-SHA256) Encap (RFC 9180 §4.1):
// generate an ephemeral key pair, compute DH with pkR, and derive the
// shared secret. Returns the shared secret and the serialized
// ephemeral public key (enc).
func (s hpkeSuite) hpkeEncap(rand io.Reader, pkR *ecdh.PublicKey) (sharedSecret, enc []byte, err error) {
	if s.kemID != hpkeKEMX25519HKDFSHA256 {
		return nil, nil, errHPKEEncap
	}
	skE, err := ecdh.X25519().GenerateKey(rand)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: gen ephemeral: %w", err)
	}
	dh, err := skE.ECDH(pkR)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: ecdh: %w", err)
	}
	enc = skE.PublicKey().Bytes()
	kemContext := make([]byte, 0, 2*len(enc))
	kemContext = append(kemContext, enc...)
	kemContext = append(kemContext, pkR.Bytes()...)
	ss, err := s.extractAndExpand(dh, kemContext)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: extractAndExpand: %w", err)
	}
	return ss, enc, nil
}

// hpkeDecap performs DHKEM(X25519, HKDF-SHA256) Decap.
func (s hpkeSuite) hpkeDecap(enc []byte, skR *ecdh.PrivateKey) ([]byte, error) {
	if s.kemID != hpkeKEMX25519HKDFSHA256 {
		return nil, errHPKEDecap
	}
	pkE, err := ecdh.X25519().NewPublicKey(enc)
	if err != nil {
		return nil, fmt.Errorf("hpke: parse enc: %w", err)
	}
	dh, err := skR.ECDH(pkE)
	if err != nil {
		return nil, fmt.Errorf("hpke: ecdh: %w", err)
	}
	kemContext := make([]byte, 0, len(enc)+len(skR.PublicKey().Bytes()))
	kemContext = append(kemContext, enc...)
	kemContext = append(kemContext, skR.PublicKey().Bytes()...)
	return s.extractAndExpand(dh, kemContext)
}

// hpkeContext is the per-session HPKE encryption context after a
// successful Setup. It holds the AEAD key + base nonce + sequence
// counter (RFC 9180 §5.2).
type hpkeContext struct {
	suite     hpkeSuite
	aead      cipher.AEAD
	baseNonce []byte
	seq       uint64
}

// keySchedule implements RFC 9180 §5.1 KeySchedule (base mode only).
// info is the application-supplied context (ODoH uses a fixed label).
func (s hpkeSuite) keySchedule(sharedSecret, info []byte) (*hpkeContext, error) {
	// pskID_hash = LabeledExtract("", "psk_id_hash", "")
	pskIDHash, err := s.labeledExtract(nil, []byte("psk_id_hash"), nil, labelKindHPKE)
	if err != nil {
		return nil, err
	}
	// info_hash = LabeledExtract("", "info_hash", info)
	infoHash, err := s.labeledExtract(nil, []byte("info_hash"), info, labelKindHPKE)
	if err != nil {
		return nil, err
	}
	// key_schedule_context = mode || psk_id_hash || info_hash
	ksContext := make([]byte, 0, 1+len(pskIDHash)+len(infoHash))
	ksContext = append(ksContext, hpkeModeBase)
	ksContext = append(ksContext, pskIDHash...)
	ksContext = append(ksContext, infoHash...)

	// secret = LabeledExtract(shared_secret, "secret", "")  [in base mode psk = ""]
	secret, err := s.labeledExtract(sharedSecret, []byte("secret"), nil, labelKindHPKE)
	if err != nil {
		return nil, err
	}
	key, err := s.labeledExpand(secret, []byte("key"), ksContext, s.aeadKeyLen(), labelKindHPKE)
	if err != nil {
		return nil, err
	}
	baseNonce, err := s.labeledExpand(secret, []byte("base_nonce"), ksContext, s.aeadNonceLen(), labelKindHPKE)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("hpke: aead key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("hpke: aead init: %w", err)
	}
	return &hpkeContext{
		suite:     s,
		aead:      aead,
		baseNonce: baseNonce,
	}, nil
}

// computeNonce XORs the sequence number into the base nonce (RFC 9180
// §5.2 ComputeNonce). The sequence is encoded big-endian, right-aligned.
func (c *hpkeContext) computeNonce() []byte {
	out := make([]byte, len(c.baseNonce))
	copy(out, c.baseNonce)
	// XOR sequence (uint64) into the last 8 bytes.
	for i := 0; i < 8; i++ {
		out[len(out)-1-i] ^= byte(c.seq >> (8 * i))
	}
	return out
}

// seal AEAD-encrypts pt with aad under the current sequence; advances
// the counter on success.
func (c *hpkeContext) seal(aad, pt []byte) ([]byte, error) {
	nonce := c.computeNonce()
	ct := c.aead.Seal(nil, nonce, pt, aad)
	c.seq++
	return ct, nil
}

// open AEAD-decrypts ct with aad under the current sequence; advances
// the counter on success.
func (c *hpkeContext) open(aad, ct []byte) ([]byte, error) {
	nonce := c.computeNonce()
	pt, err := c.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("hpke: open: %w", err)
	}
	c.seq++
	return pt, nil
}

// hpkeSetupSender implements SetupBaseS (RFC 9180 §5.1.1).
func (s hpkeSuite) hpkeSetupSender(rand io.Reader, pkR *ecdh.PublicKey, info []byte) (enc []byte, ctx *hpkeContext, err error) {
	ss, enc, err := s.hpkeEncap(rand, pkR)
	if err != nil {
		return nil, nil, err
	}
	ctx, err = s.keySchedule(ss, info)
	if err != nil {
		return nil, nil, err
	}
	return enc, ctx, nil
}

// hpkeSetupRecipient implements SetupBaseR (RFC 9180 §5.1.1).
func (s hpkeSuite) hpkeSetupRecipient(enc []byte, skR *ecdh.PrivateKey, info []byte) (*hpkeContext, error) {
	ss, err := s.hpkeDecap(enc, skR)
	if err != nil {
		return nil, err
	}
	return s.keySchedule(ss, info)
}

// --- helpers ---

func appendU16BE(b []byte, v uint16) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return append(b, buf[:]...)
}
