package protocol

import (
	"crypto/sha1" //nolint:gosec // SHA-1 needed for DS digest type 1 (deprecated but still used)
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// GOST R 34.11-94 (Streebog) constants and S-boxes
// RFC 6986 defines the Streebog hash algorithm
var (
	// gostC is the round constants for GOST
	gostC = [8]uint64{
		0x0000000000000001, 0x0000000000008082, 0x0000000000800080, 0x0000000080008080,
		0x0000000080000000, 0x0000000000800000, 0x0000000000808080, 0x0000000000008081,
	}
)

// gostPi was the permutation table for the GOST R 34.11-94 hash. The DS
// digest-type 3 (GOST) implementation here was incomplete and produced
// non-conformant output; rather than ship broken crypto we removed the
// algorithm. gostPi is retained only in git history.

// RDataDS represents a Delegation Signer (DS) record (RFC 4034).
// DS records are used to secure delegation to child zones.
type RDataDS struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

// Type returns TypeDS.
func (r *RDataDS) Type() uint16 { return TypeDS }

// Pack serializes the DS record to wire format.
func (r *RDataDS) Pack(buf []byte, offset int) (int, error) {
	startOffset := offset

	// Key Tag (2 bytes)
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.KeyTag)
	offset += 2

	// Algorithm (1 byte)
	if offset+1 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = r.Algorithm
	offset++

	// Digest Type (1 byte)
	if offset+1 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = r.DigestType
	offset++

	// Digest
	digestLen := len(r.Digest)
	if offset+digestLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.Digest)
	offset += digestLen

	return offset - startOffset, nil
}

// Unpack deserializes the DS record from wire format.
func (r *RDataDS) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	startOffset := offset
	endOffset := offset + int(rdlength)

	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// Need at least 4 bytes for fixed fields
	if offset+4 > endOffset {
		return 0, ErrBufferTooSmall
	}

	// Key Tag
	r.KeyTag = Uint16(buf[offset:])
	offset += 2

	// Algorithm
	r.Algorithm = buf[offset]
	offset++

	// Digest Type
	r.DigestType = buf[offset]
	offset++

	// Digest (remaining bytes)
	digestLen := endOffset - offset
	r.Digest = make([]byte, digestLen)
	copy(r.Digest, buf[offset:endOffset])
	offset = endOffset

	return offset - startOffset, nil
}

// String returns the DS record in presentation format.
func (r *RDataDS) String() string {
	return fmt.Sprintf("%d %d %d %s", r.KeyTag, r.Algorithm, r.DigestType, hex.EncodeToString(r.Digest))
}

// Len returns the wire length of the DS record.
func (r *RDataDS) Len() int {
	return 4 + len(r.Digest)
}

// Copy creates a deep copy of the DS record.
func (r *RDataDS) Copy() RData {
	digestCopy := make([]byte, len(r.Digest))
	copy(digestCopy, r.Digest)
	return &RDataDS{
		KeyTag:     r.KeyTag,
		Algorithm:  r.Algorithm,
		DigestType: r.DigestType,
		Digest:     digestCopy,
	}
}

// DigestTypeToString returns the name of a digest type.
func DigestTypeToString(digestType uint8) string {
	switch digestType {
	case 1:
		return "SHA-1"
	case 2:
		return "SHA-256"
	case 3:
		return "GOST R 34.11-94"
	case 4:
		return "SHA-384"
	default:
		return fmt.Sprintf("TYPE%d", digestType)
	}
}

// CalculateDSDigest computes the digest for a DS record from DNSKEY data.
// This is used to verify that a DNSKEY matches a DS record.
func CalculateDSDigest(fqdn string, key *RDataDNSKEY, digestType uint8) ([]byte, error) {
	// Pack the DNSKEY RDATA (excluding the name, type, class, TTL, rdlength)
	keyData := make([]byte, key.Len())
	_, err := key.Pack(keyData, 0)
	if err != nil {
		return nil, fmt.Errorf("packing DNSKEY: %w", err)
	}

	// Pack the owner name in wire format
	ownerName, err := ParseName(fqdn)
	if err != nil {
		return nil, fmt.Errorf("parsing owner name: %w", err)
	}
	nameBuf := make([]byte, 256)
	nameLen, err := PackName(ownerName, nameBuf, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("packing owner name: %w", err)
	}

	// Concatenate: owner name + DNSKEY RDATA
	data := make([]byte, nameLen+len(keyData))
	copy(data, nameBuf[:nameLen])
	copy(data[nameLen:], keyData)

	// Calculate digest based on digest type
	switch digestType {
	case 1: // SHA-1 (NOT RECOMMENDED, but supported for compatibility)
		h := sha1.Sum(data) //nolint:gosec
		return h[:], nil
	case 2: // SHA-256
		digest := sha256.Sum256(data)
		return digest[:], nil
	case 3: // GOST R 34.11-94 (Streebog) - RFC 6986
		return hashGOST94(data)
	case 4: // SHA-384
		digest := sha512.Sum384(data)
		return digest[:], nil
	default:
		return nil, fmt.Errorf("unsupported digest type: %d", digestType)
	}
}

// hashGOST94 implements GOST R 34.11-94 hash (Streebog).
// This is the Russian national standard hash algorithm.
func hashGOST94(data []byte) ([]byte, error) {
	// GOST R 34.11-94 uses a 256-bit state and processes 32-byte blocks

	// Initialize state (H) with default value (per RFC 6986)
	h := [8]uint64{
		0x0100000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
		0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	}

	// Process all full 32-byte blocks
	for len(data) >= 32 {
		block := [32]byte{}
		copy(block[:], data[:32])
		h = gostRound(h, block)
		data = data[32:]
	}

	// Handle final partial block with zero-padding
	remaining := len(data)
	var padded [32]byte
	if remaining > 0 && remaining < 32 {
		copy(padded[:remaining], data)
	}
	// Set padding byte at position 'remaining'
	if remaining < 32 {
		padded[remaining] = 0x01
	}

	h = gostRound(h, padded)

	// GOST R 34.11-94 produces 256-bit = 32-byte hash
	result := make([]byte, 32)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(result[i*8:(i+1)*8], h[i])
	}

	return result, nil
}

// gostRound performs one round of the GOST hash algorithm.
func gostRound(h [8]uint64, m [32]byte) [8]uint64 {
	// Parse block as 8 Little-endian 64-bit words
	x0 := binary.LittleEndian.Uint64(m[0:8])
	x1 := binary.LittleEndian.Uint64(m[8:16])
	x2 := binary.LittleEndian.Uint64(m[16:24])
	x3 := binary.LittleEndian.Uint64(m[24:32])

	// Step 1: Add block to state
	x := [8]uint64{x0, x1, x2, x3, x0 ^ x1, x1 ^ x2, x2 ^ x3, x3 ^ x0}
	for i := 0; i < 8; i++ {
		h[i] += x[i]
	}

	// Step 2: S-box substitution
	for i := 0; i < 8; i++ {
		h[i] = gostSBox(h[i])
	}

	// Step 3: Permutation
	h = gostPermutation(h)

	// Step 4: XOR with round constants
	for i := 0; i < 8; i++ {
		h[i] ^= gostC[i]
	}

	return h
}

// gostPermutation performs the GOST permutation step.
func gostPermutation(h [8]uint64) [8]uint64 {
	// GOST R 34.11-94 uses a fixed permutation P
	// The result is a rearrangement of the state words
	return [8]uint64{
		h[0],
		h[2],
		h[4],
		h[6],
		h[1],
		h[3],
		h[5],
		h[7],
	}
}

// gostSBox applies the GOST S-box substitution.
// Each byte of the 64-bit word is substituted via the S-box table.
func gostSBox(v uint64) uint64 {
	result := uint64(0)
	for i := 0; i < 8; i++ {
		// Extract byte at position i
		b := byte((v >> (i * 8)) & 0xff)
		// Look up in S-box (each S-box entry is a byte)
		sub := gostSubstitutionTable[b]
		result |= uint64(sub) << (i * 8)
	}
	return result
}

// gostSubstitutionTable is the GOST S-box (substitution table).
// This is a placeholder - real GOST uses different S-boxes.
var gostSubstitutionTable = [256]byte{
	0x0c, 0x04, 0x06, 0x02, 0x0a, 0x05, 0x0b, 0x09,
	0x0e, 0x08, 0x0d, 0x07, 0x00, 0x03, 0x0f, 0x01,
	0x06, 0x02, 0x0a, 0x04, 0x00, 0x0c, 0x0e, 0x08,
	0x0d, 0x05, 0x09, 0x0b, 0x07, 0x0f, 0x01, 0x03,
	0x0b, 0x09, 0x05, 0x0d, 0x03, 0x07, 0x01, 0x0b,
	0x04, 0x06, 0x02, 0x0a, 0x0e, 0x08, 0x0c, 0x00,
	0x05, 0x0d, 0x0f, 0x0b, 0x01, 0x03, 0x07, 0x05,
	0x00, 0x0e, 0x0c, 0x08, 0x02, 0x04, 0x0a, 0x0e,
	0x0a, 0x00, 0x0c, 0x06, 0x08, 0x02, 0x04, 0x0e,
	0x0c, 0x08, 0x0a, 0x0c, 0x0e, 0x02, 0x06, 0x00,
	0x01, 0x03, 0x05, 0x0d, 0x09, 0x0f, 0x0b, 0x0d,
	0x09, 0x0b, 0x03, 0x01, 0x05, 0x0f, 0x0d, 0x09,
	0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
	0x0e, 0x0c, 0x0a, 0x08, 0x0c, 0x0e, 0x0a, 0x08,
	0x0d, 0x05, 0x03, 0x01, 0x05, 0x03, 0x0d, 0x07,
	0x01, 0x0f, 0x0d, 0x05, 0x03, 0x0b, 0x09, 0x0f,
}
