package odoh

// RFC 9230 wire format and HPKE-based encapsulation on top of hpke.go.
//
// References:
//   - RFC 9230 §3: ObliviousDoHConfigContents / KeyConfig
//   - RFC 9230 §4: ObliviousDoHMessage framing + HPKE labels
//
// The wire format uses fixed labels for HPKE info:
//   query:    "odoh query"
//   response: "odoh response"

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// ODoH application labels (RFC 9230 §4).
var (
	odohQueryLabel    = []byte("odoh query")
	odohResponseLabel = []byte("odoh response")
)

// ObliviousDoHMessageType per RFC 9230 §6:
//
//	0x01 = query
//	0x02 = response
const (
	odohMsgTypeQuery    byte = 0x01
	odohMsgTypeResponse byte = 0x02
)

// odohKeyPair holds the target's HPKE key material plus the serialized
// ObliviousDoHConfigContents that clients receive over a trusted
// channel.
type odohKeyPair struct {
	suite       hpkeSuite
	skR         *ecdh.PrivateKey
	pkRBytes    []byte
	configBytes []byte // serialized ObliviousDoHConfigContents
	keyID       []byte // 32-byte SHA-256 of the config (used as AAD in responses)
}

// newODoHKeyPair generates a fresh target key pair using the default
// suite (DHKEM-X25519, HKDF-SHA256, AES-128-GCM).
func newODoHKeyPair() (*odohKeyPair, error) {
	suite := defaultHPKESuite()
	skR, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("odoh: gen target key: %w", err)
	}
	pk := skR.PublicKey().Bytes()

	// ObliviousDoHConfigContents per RFC 9230 §3.1:
	//   kem_id (2) || kdf_id (2) || aead_id (2)
	//   public_key_len (2) || public_key (...)
	var cfg bytes.Buffer
	cfg.Write(u16BE(suite.kemID))
	cfg.Write(u16BE(suite.kdfID))
	cfg.Write(u16BE(suite.aeadID))
	cfg.Write(u16BE(uint16(len(pk))))
	cfg.Write(pk)

	// keyID = LabeledExtract("", "key_id", config_contents)  per RFC 9230 §4.1
	keyID, err := suite.labeledExtract(nil, []byte("key_id"), cfg.Bytes(), labelKindHPKE)
	if err != nil {
		return nil, fmt.Errorf("odoh: key_id: %w", err)
	}
	return &odohKeyPair{
		suite:       suite,
		skR:         skR,
		pkRBytes:    pk,
		configBytes: cfg.Bytes(),
		keyID:       keyID,
	}, nil
}

// configBytes returns the marshaled ObliviousDoHConfig framing the
// contents:
//
//	ObliviousDoHConfig: u16 version (0x0001) || u16 length || contents
//	ObliviousDoHConfigs: u16 total_length || one or more configs
//
// Most clients fetch the ObliviousDoHConfigs object, so we return the
// outer-wrapped form ready to serve over /.well-known/odohconfigs.
func (kp *odohKeyPair) configsObject() ([]byte, error) {
	configLen, err := u16Length("config contents", len(kp.configBytes))
	if err != nil {
		return nil, err
	}

	// One config inside ObliviousDoHConfigs.
	inner := make([]byte, 0, 4+len(kp.configBytes))
	inner = append(inner, u16BE(0x0001)...) // version
	inner = append(inner, u16BE(configLen)...)
	inner = append(inner, kp.configBytes...)

	innerLen, err := u16Length("config list", len(inner))
	if err != nil {
		return nil, err
	}
	outer := make([]byte, 0, 2+len(inner))
	outer = append(outer, u16BE(innerLen)...)
	outer = append(outer, inner...)
	return outer, nil
}

// odohMessage is the wire form for both query and response (RFC 9230
// §6.1):
//
//	u8  message_type           (0x01 query, 0x02 response)
//	u16 key_id_len             (32 for SHA-256)
//	u8[]  key_id
//	u16 encrypted_message_len
//	u8[]  encrypted_message
type odohMessage struct {
	msgType          byte
	keyID            []byte
	encryptedMessage []byte
}

func marshalODoHMessage(m *odohMessage) ([]byte, error) {
	keyIDLen, err := u16Length("key_id", len(m.keyID))
	if err != nil {
		return nil, err
	}
	encryptedLen, err := u16Length("encrypted_message", len(m.encryptedMessage))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+2+len(m.keyID)+2+len(m.encryptedMessage))
	out = append(out, m.msgType)
	out = append(out, u16BE(keyIDLen)...)
	out = append(out, m.keyID...)
	out = append(out, u16BE(encryptedLen)...)
	out = append(out, m.encryptedMessage...)
	return out, nil
}

func parseODoHMessage(b []byte) (*odohMessage, error) {
	if len(b) < 1+2 {
		return nil, errors.New("odoh: message truncated (header)")
	}
	m := &odohMessage{msgType: b[0]}
	r := b[1:]
	keyIDLen := binary.BigEndian.Uint16(r[:2])
	r = r[2:]
	if len(r) < int(keyIDLen)+2 {
		return nil, errors.New("odoh: message truncated (key_id)")
	}
	m.keyID = make([]byte, keyIDLen)
	copy(m.keyID, r[:keyIDLen])
	r = r[keyIDLen:]
	encLen := binary.BigEndian.Uint16(r[:2])
	r = r[2:]
	if len(r) < int(encLen) {
		return nil, errors.New("odoh: message truncated (encrypted)")
	}
	m.encryptedMessage = make([]byte, encLen)
	copy(m.encryptedMessage, r[:encLen])
	return m, nil
}

// encryptQueryRFC9230 produces an ObliviousDoHMessage that the target
// can decrypt. Returns the wire bytes to POST to the proxy and the
// HPKE context preserved for response decryption.
func encryptQueryRFC9230(targetConfig []byte, dnsQuery []byte) (msgBytes []byte, queryCtx *queryContext, err error) {
	suite, pkR, err := parseConfigContents(targetConfig)
	if err != nil {
		return nil, nil, err
	}
	dnsLen, err := u16Length("dns query", len(dnsQuery))
	if err != nil {
		return nil, nil, err
	}

	keyID, err := suite.labeledExtract(nil, []byte("key_id"), targetConfig, labelKindHPKE)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: key_id: %w", err)
	}

	enc, ctx, err := suite.hpkeSetupSender(rand.Reader, pkR, odohQueryLabel)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: setup sender: %w", err)
	}

	// AAD for the query is: 0x01 || u16(keyIDLen) || key_id (RFC 9230 §4.1.1).
	aad := make([]byte, 0, 3+len(keyID))
	aad = append(aad, odohMsgTypeQuery)
	aad = append(aad, u16BE(uint16(len(keyID)))...)
	aad = append(aad, keyID...)

	// plaintext: DNS message + padding (padding optional; we add none).
	// RFC 9230 §6.2 plaintext format:
	//   u16 dns_message_len || dns_message || u16 padding_len || padding
	pt := make([]byte, 0, 4+len(dnsQuery))
	pt = append(pt, u16BE(dnsLen)...)
	pt = append(pt, dnsQuery...)
	pt = append(pt, u16BE(0)...) // padding_len = 0

	// encrypted_message = enc || aead.Seal(...)
	ct, err := ctx.seal(aad, pt)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: seal: %w", err)
	}
	encrypted := make([]byte, 0, len(enc)+len(ct))
	encrypted = append(encrypted, enc...)
	encrypted = append(encrypted, ct...)

	msg := &odohMessage{
		msgType:          odohMsgTypeQuery,
		keyID:            keyID,
		encryptedMessage: encrypted,
	}
	msgBytes, err = marshalODoHMessage(msg)
	if err != nil {
		return nil, nil, err
	}
	return msgBytes, &queryContext{suite: suite, ctx: ctx, enc: enc, keyID: keyID}, nil
}

type queryContext struct {
	suite hpkeSuite
	ctx   *hpkeContext
	enc   []byte // ephemeral public key bytes
	keyID []byte
}

// parseConfigContents parses a single ObliviousDoHConfigContents (NOT
// the outer ObliviousDoHConfigs wrapper) and returns the suite and
// recipient public key.
func parseConfigContents(b []byte) (hpkeSuite, *ecdh.PublicKey, error) {
	if len(b) < 8 {
		return hpkeSuite{}, nil, errors.New("odoh: config too short")
	}
	suite := hpkeSuite{
		kemID:  binary.BigEndian.Uint16(b[0:2]),
		kdfID:  binary.BigEndian.Uint16(b[2:4]),
		aeadID: binary.BigEndian.Uint16(b[4:6]),
	}
	pkLen := binary.BigEndian.Uint16(b[6:8])
	if len(b) < 8+int(pkLen) {
		return hpkeSuite{}, nil, errors.New("odoh: config truncated")
	}
	pk, err := ecdh.X25519().NewPublicKey(b[8 : 8+pkLen])
	if err != nil {
		return hpkeSuite{}, nil, fmt.Errorf("odoh: parse pk: %w", err)
	}
	if suite.kemID != hpkeKEMX25519HKDFSHA256 ||
		suite.kdfID != hpkeKDFHKDFSHA256 ||
		(suite.aeadID != hpkeAEADAES128GCM && suite.aeadID != hpkeAEADAES256GCM) {
		return hpkeSuite{}, nil, errors.New("odoh: unsupported suite")
	}
	return suite, pk, nil
}

// decryptQueryRFC9230 is the target side of encryptQueryRFC9230. Takes
// the marshaled ObliviousDoHMessage from the proxy and returns the
// plaintext DNS query plus a response context.
func (kp *odohKeyPair) decryptQuery(msgBytes []byte) (dnsQuery []byte, respCtx *responseContext, err error) {
	msg, err := parseODoHMessage(msgBytes)
	if err != nil {
		return nil, nil, err
	}
	if msg.msgType != odohMsgTypeQuery {
		return nil, nil, fmt.Errorf("odoh: wrong message type %d", msg.msgType)
	}
	if !bytes.Equal(msg.keyID, kp.keyID) {
		return nil, nil, errors.New("odoh: unknown key_id")
	}

	// encrypted_message = enc || ct, where len(enc) = X25519 pub key = 32 bytes.
	if len(msg.encryptedMessage) < 32 {
		return nil, nil, errors.New("odoh: ciphertext too short")
	}
	enc := msg.encryptedMessage[:32]
	ct := msg.encryptedMessage[32:]

	ctx, err := kp.suite.hpkeSetupRecipient(enc, kp.skR, odohQueryLabel)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: setup recipient: %w", err)
	}

	aad := make([]byte, 0, 3+len(kp.keyID))
	aad = append(aad, odohMsgTypeQuery)
	aad = append(aad, u16BE(uint16(len(kp.keyID)))...)
	aad = append(aad, kp.keyID...)

	pt, err := ctx.open(aad, ct)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: open: %w", err)
	}

	// Parse the plaintext envelope:  u16 dns_len || dns || u16 pad_len || pad
	if len(pt) < 4 {
		return nil, nil, errors.New("odoh: plaintext too short")
	}
	dnsLen := binary.BigEndian.Uint16(pt[0:2])
	if len(pt) < 2+int(dnsLen)+2 {
		return nil, nil, errors.New("odoh: plaintext truncated")
	}
	dnsQuery = make([]byte, dnsLen)
	copy(dnsQuery, pt[2:2+dnsLen])

	// Derive a fresh AEAD key+nonce for the response (RFC 9230 §4.1.2):
	//
	//   secret = Extract(enc, dns_query_plaintext)        [HKDF-Extract]
	//   key    = LabeledExpand(secret, "key", "odoh response", aead_key_len)
	//   nonce  = LabeledExpand(secret, "nonce", "odoh response", aead_nonce_len)
	//
	// where dns_query_plaintext is the WHOLE decrypted query envelope
	// (including padding fields), enc is the ephemeral PK bytes from the
	// query, and Extract uses the suite's KDF hash.
	respCtx = &responseContext{
		suite:         kp.suite,
		enc:           append([]byte(nil), enc...),
		queryPlain:    append([]byte(nil), pt...),
		responseLabel: odohResponseLabel,
	}
	return dnsQuery, respCtx, nil
}

// responseContext carries everything the target needs to AEAD-seal a
// response to the same client.
type responseContext struct {
	suite         hpkeSuite
	enc           []byte
	queryPlain    []byte
	responseLabel []byte
}

// encryptResponse seals dnsResponse and produces the wire-format
// ObliviousDoHMessage bytes to return to the proxy.
func (rc *responseContext) encryptResponse(dnsResponse []byte) ([]byte, error) {
	aead, nonce, err := rc.suite.deriveResponseAEAD(rc.enc, rc.queryPlain, rc.responseLabel)
	if err != nil {
		return nil, err
	}
	dnsLen, err := u16Length("dns response", len(dnsResponse))
	if err != nil {
		return nil, err
	}

	// AAD = 0x02 || u16(0) || []   (RFC 9230 §4.1.2 response AAD: just the
	// message type and empty key_id — see §6.1, key_id length is 0 for
	// responses since the recipient is the client, not a server key).
	aad := []byte{odohMsgTypeResponse, 0x00, 0x00}

	// Plaintext envelope:  u16 dns_len || dns || u16 pad_len || pad
	pt := make([]byte, 0, 4+len(dnsResponse))
	pt = append(pt, u16BE(dnsLen)...)
	pt = append(pt, dnsResponse...)
	pt = append(pt, u16BE(0)...) // padding_len = 0

	ct := aead.Seal(nil, nonce, pt, aad)

	msg := &odohMessage{
		msgType:          odohMsgTypeResponse,
		keyID:            nil, // responses carry no key_id (RFC 9230 §6.1)
		encryptedMessage: ct,
	}
	return marshalODoHMessage(msg)
}

// decryptResponse is the client side of encryptResponse.
func (qc *queryContext) decryptResponse(msgBytes []byte, queryPlain []byte) ([]byte, error) {
	msg, err := parseODoHMessage(msgBytes)
	if err != nil {
		return nil, err
	}
	if msg.msgType != odohMsgTypeResponse {
		return nil, fmt.Errorf("odoh: wrong response type %d", msg.msgType)
	}
	if len(msg.keyID) != 0 {
		return nil, errors.New("odoh: response key_id must be empty")
	}

	aead, nonce, err := qc.suite.deriveResponseAEAD(qc.enc, queryPlain, odohResponseLabel)
	if err != nil {
		return nil, err
	}

	aad := []byte{odohMsgTypeResponse, 0x00, 0x00}
	pt, err := aead.Open(nil, nonce, msg.encryptedMessage, aad)
	if err != nil {
		return nil, fmt.Errorf("odoh: open response: %w", err)
	}

	if len(pt) < 4 {
		return nil, errors.New("odoh: response plaintext too short")
	}
	dnsLen := binary.BigEndian.Uint16(pt[0:2])
	if len(pt) < 2+int(dnsLen)+2 {
		return nil, errors.New("odoh: response plaintext truncated")
	}
	return append([]byte(nil), pt[2:2+dnsLen]...), nil
}

// deriveResponseAEAD turns (enc, query_plaintext) into a fresh AEAD
// key+nonce for the response transit, per RFC 9230 §4.1.2.
func (s hpkeSuite) deriveResponseAEAD(enc, queryPlain, label []byte) (cipher.AEAD, []byte, error) {
	secret, err := hkdf.Extract(s.hkdfHash(), queryPlain, enc)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: response hkdf extract: %w", err)
	}
	key, err := s.labeledExpand(secret, []byte("key"), label, s.aeadKeyLen(), labelKindHPKE)
	if err != nil {
		return nil, nil, err
	}
	nonceBytes, err := s.labeledExpand(secret, []byte("nonce"), label, s.aeadNonceLen(), labelKindHPKE)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: response aead key: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: response aead init: %w", err)
	}
	return gcm, nonceBytes, nil
}

func u16BE(v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return b[:]
}

func u16Length(field string, n int) (uint16, error) {
	if n > 0xffff {
		return 0, fmt.Errorf("odoh: %s too large: %d bytes (max 65535)", field, n)
	}
	return uint16(n), nil
}
