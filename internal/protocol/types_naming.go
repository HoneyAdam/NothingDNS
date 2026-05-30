// Package protocol provides DNS protocol types for NothingDNS.
//
// Naming authority types: NAPTR, SVCB params.

package protocol

import (
	"fmt"
)

// ============================================================================

// RDataNAPTR represents a NAPTR record.
type RDataNAPTR struct {
	Order       uint16
	Preference  uint16
	Flags       string
	Service     string
	Regexp      string
	Replacement *Name
}

// Type returns TypeNAPTR.
func (r *RDataNAPTR) Type() uint16 { return TypeNAPTR }

// Pack serializes the NAPTR record.
func (r *RDataNAPTR) Pack(buf []byte, offset int) (int, error) {
	startOffset := offset

	// Order (2 bytes)
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.Order)
	offset += 2

	// Preference (2 bytes)
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.Preference)
	offset += 2

	// Flags length and Flags
	flagsLen := len(r.Flags)
	if flagsLen > 255 {
		return 0, ErrLabelTooLong
	}
	if offset+1+flagsLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = byte(flagsLen)
	offset++
	copy(buf[offset:], r.Flags)
	offset += flagsLen

	// Service length and Service
	serviceLen := len(r.Service)
	if serviceLen > 255 {
		return 0, ErrLabelTooLong
	}
	if offset+1+serviceLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = byte(serviceLen)
	offset++
	copy(buf[offset:], r.Service)
	offset += serviceLen

	// Regexp length and Regexp
	regexpLen := len(r.Regexp)
	if regexpLen > 255 {
		return 0, ErrLabelTooLong
	}
	if offset+1+regexpLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = byte(regexpLen)
	offset++
	copy(buf[offset:], r.Regexp)
	offset += regexpLen

	// Replacement domain name
	n, err := PackName(r.Replacement, buf, offset, nil)
	if err != nil {
		return 0, err
	}
	offset += n

	return offset - startOffset, nil
}

// Unpack deserializes the NAPTR record.
func (r *RDataNAPTR) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	startOffset := offset

	// Order
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Order = Uint16(buf[offset:])
	offset += 2

	// Preference
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Preference = Uint16(buf[offset:])
	offset += 2

	// Flags
	if offset >= len(buf) {
		return 0, ErrBufferTooSmall
	}
	flagsLen := int(buf[offset])
	offset++
	if offset+flagsLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Flags = string(buf[offset : offset+flagsLen])
	offset += flagsLen

	// Service
	if offset >= len(buf) {
		return 0, ErrBufferTooSmall
	}
	serviceLen := int(buf[offset])
	offset++
	if offset+serviceLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Service = string(buf[offset : offset+serviceLen])
	offset += serviceLen

	// Regexp
	if offset >= len(buf) {
		return 0, ErrBufferTooSmall
	}
	regexpLen := int(buf[offset])
	offset++
	if offset+regexpLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Regexp = string(buf[offset : offset+regexpLen])
	offset += regexpLen

	// Replacement
	replacement, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	r.Replacement = replacement
	offset += n

	return offset - startOffset, nil
}

// String returns the NAPTR record data.
func (r *RDataNAPTR) String() string {
	replacement := "."
	if r.Replacement != nil {
		replacement = r.Replacement.String()
	}
	return fmt.Sprintf("%d %d \"%s\" \"%s\" \"%s\" %s",
		r.Order, r.Preference, r.Flags, r.Service, r.Regexp, replacement)
}

// Len returns the wire length.
func (r *RDataNAPTR) Len() int {
	replacementLen := 0
	if r.Replacement != nil {
		replacementLen = r.Replacement.WireLength()
	}
	return 2 + 2 + 1 + len(r.Flags) + 1 + len(r.Service) + 1 + len(r.Regexp) + replacementLen
}

// Copy creates a copy.
func (r *RDataNAPTR) Copy() RData {
	var replacement *Name
	if r.Replacement != nil {
		replacement = NewName(r.Replacement.Labels, r.Replacement.FQDN)
	}
	return &RDataNAPTR{
		Order:       r.Order,
		Preference:  r.Preference,
		Flags:       r.Flags,
		Service:     r.Service,
		Regexp:      r.Regexp,
		Replacement: replacement,
	}
}

// ============================================================================
// SVCB / HTTPS Records (Service Binding) - RFC 9460
