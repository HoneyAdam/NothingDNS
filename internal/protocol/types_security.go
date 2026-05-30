// Package protocol provides DNS protocol types for NothingDNS.
//
// Security record types: CAA, SSHFP, TLSA.

package protocol

import (
	"encoding/hex"
	"fmt"
)

// ============================================================================

// RDataCAA represents a CAA record.
type RDataCAA struct {
	Flags uint8
	Tag   string
	Value string
}

// Type returns TypeCAA.
func (r *RDataCAA) Type() uint16 { return TypeCAA }

// Pack serializes the CAA record.
func (r *RDataCAA) Pack(buf []byte, offset int) (int, error) {
	startOffset := offset

	// Flags (1 byte)
	if offset+1 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = r.Flags
	offset++

	// Tag length and Tag
	tagLen := len(r.Tag)
	if tagLen > 255 {
		return 0, ErrLabelTooLong
	}
	if offset+1+tagLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = byte(tagLen)
	offset++
	copy(buf[offset:], r.Tag)
	offset += tagLen

	// Value
	valueLen := len(r.Value)
	if offset+valueLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.Value)
	offset += valueLen

	return offset - startOffset, nil
}

// Unpack deserializes the CAA record.
func (r *RDataCAA) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	startOffset := offset
	endOffset := offset + int(rdlength)

	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// Need at least 2 bytes: flags + tag length
	if offset+2 > endOffset {
		return 0, ErrBufferTooSmall
	}

	// Flags
	r.Flags = buf[offset]
	offset++

	// Tag length and Tag
	tagLen := int(buf[offset])
	offset++

	if offset+tagLen > endOffset {
		return 0, ErrBufferTooSmall
	}
	r.Tag = string(buf[offset : offset+tagLen])
	offset += tagLen

	// Value (remaining bytes)
	r.Value = string(buf[offset:endOffset])
	offset = endOffset

	return offset - startOffset, nil
}

// String returns the CAA record data.
func (r *RDataCAA) String() string {
	return fmt.Sprintf("%d %s \"%s\"", r.Flags, r.Tag, r.Value)
}

// Len returns the wire length.
func (r *RDataCAA) Len() int { return 1 + 1 + len(r.Tag) + len(r.Value) }

// Copy creates a copy.
func (r *RDataCAA) Copy() RData {
	return &RDataCAA{Flags: r.Flags, Tag: r.Tag, Value: r.Value}
}

// ============================================================================
// SSHFP Record (SSH Key Fingerprint) - RFC 4255
// ============================================================================

// RDataSSHFP represents an SSHFP record.
type RDataSSHFP struct {
	Algorithm   uint8
	FPType      uint8
	Fingerprint []byte
}

// Type returns TypeSSHFP.
func (r *RDataSSHFP) Type() uint16 { return TypeSSHFP }

// Pack serializes the SSHFP record.
func (r *RDataSSHFP) Pack(buf []byte, offset int) (int, error) {
	length := 2 + len(r.Fingerprint)
	if offset+length > len(buf) {
		return 0, ErrBufferTooSmall
	}

	buf[offset] = r.Algorithm
	offset++
	buf[offset] = r.FPType
	offset++
	copy(buf[offset:], r.Fingerprint)

	return length, nil
}

// Unpack deserializes the SSHFP record.
func (r *RDataSSHFP) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	startOffset := offset
	if rdlength < 2 {
		return 0, ErrBufferTooSmall
	}
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Algorithm = buf[offset]
	offset++
	r.FPType = buf[offset]
	offset++

	fpLen := int(rdlength) - 2
	if offset+fpLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Fingerprint = make([]byte, fpLen)
	copy(r.Fingerprint, buf[offset:offset+fpLen])
	offset += fpLen

	return offset - startOffset, nil
}

// String returns the SSHFP record data.
func (r *RDataSSHFP) String() string {
	return fmt.Sprintf("%d %d %s", r.Algorithm, r.FPType, hex.EncodeToString(r.Fingerprint))
}

// Len returns the wire length.
func (r *RDataSSHFP) Len() int { return 2 + len(r.Fingerprint) }

// Copy creates a copy.
func (r *RDataSSHFP) Copy() RData {
	fpCopy := make([]byte, len(r.Fingerprint))
	copy(fpCopy, r.Fingerprint)
	return &RDataSSHFP{Algorithm: r.Algorithm, FPType: r.FPType, Fingerprint: fpCopy}
}

// ============================================================================
// TLSA Record (TLS Authentication) - RFC 6698
// ============================================================================

// RDataTLSA represents a TLSA record.
type RDataTLSA struct {
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Certificate  []byte
}

// Type returns TypeTLSA.
func (r *RDataTLSA) Type() uint16 { return TypeTLSA }

// Pack serializes the TLSA record.
func (r *RDataTLSA) Pack(buf []byte, offset int) (int, error) {
	length := 3 + len(r.Certificate)
	if offset+length > len(buf) {
		return 0, ErrBufferTooSmall
	}

	buf[offset] = r.Usage
	offset++
	buf[offset] = r.Selector
	offset++
	buf[offset] = r.MatchingType
	offset++
	copy(buf[offset:], r.Certificate)

	return length, nil
}

// Unpack deserializes the TLSA record.
func (r *RDataTLSA) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	startOffset := offset
	if rdlength < 3 {
		return 0, ErrBufferTooSmall
	}
	if offset+3 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Usage = buf[offset]
	offset++
	r.Selector = buf[offset]
	offset++
	r.MatchingType = buf[offset]
	offset++

	certLen := int(rdlength) - 3
	if offset+certLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Certificate = make([]byte, certLen)
	copy(r.Certificate, buf[offset:offset+certLen])
	offset += certLen

	return offset - startOffset, nil
}

// String returns the TLSA record data.
func (r *RDataTLSA) String() string {
	return fmt.Sprintf("%d %d %d %s", r.Usage, r.Selector, r.MatchingType, hex.EncodeToString(r.Certificate))
}

// Len returns the wire length.
func (r *RDataTLSA) Len() int { return 3 + len(r.Certificate) }

// Copy creates a copy.
func (r *RDataTLSA) Copy() RData {
	certCopy := make([]byte, len(r.Certificate))
	copy(certCopy, r.Certificate)
	return &RDataTLSA{Usage: r.Usage, Selector: r.Selector, MatchingType: r.MatchingType, Certificate: certCopy}
}
