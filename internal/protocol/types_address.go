// Package protocol provides DNS protocol types for NothingDNS.
//
// Address record types: A, AAAA, CNAME, DNAME, NS, PTR.

package protocol

import (
	"fmt"
	"net"
)

// ============================================================================

// RDataA represents an IPv4 address record.
type RDataA struct {
	Address [4]byte
}

// Type returns TypeA.
func (r *RDataA) Type() uint16 { return TypeA }

// Pack serializes the A record.
func (r *RDataA) Pack(buf []byte, offset int) (int, error) {
	if offset+4 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.Address[:])
	return 4, nil
}

// Unpack deserializes the A record.
func (r *RDataA) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if rdlength != 4 {
		return 0, fmt.Errorf("invalid A record length: %d", rdlength)
	}
	if offset+4 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(r.Address[:], buf[offset:offset+4])
	return 4, nil
}

// String returns the IPv4 address as a string.
func (r *RDataA) String() string {
	return net.IP(r.Address[:]).String()
}

// Len returns 4.
func (r *RDataA) Len() int { return 4 }

// Copy creates a copy.
func (r *RDataA) Copy() RData {
	return &RDataA{Address: r.Address}
}

// IP returns the address as net.IP.
func (r *RDataA) IP() net.IP {
	return net.IP(r.Address[:])
}

// SetIP sets the address from net.IP.
func (r *RDataA) SetIP(ip net.IP) {
	if v4 := ip.To4(); v4 != nil {
		copy(r.Address[:], v4)
	}
}

// ============================================================================
// AAAA Record (IPv6 Address) - RFC 3596
// ============================================================================

// RDataAAAA represents an IPv6 address record.
type RDataAAAA struct {
	Address [16]byte
}

// Type returns TypeAAAA.
func (r *RDataAAAA) Type() uint16 { return TypeAAAA }

// Pack serializes the AAAA record.
func (r *RDataAAAA) Pack(buf []byte, offset int) (int, error) {
	if offset+16 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.Address[:])
	return 16, nil
}

// Unpack deserializes the AAAA record.
func (r *RDataAAAA) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if rdlength != 16 {
		return 0, fmt.Errorf("invalid AAAA record length: %d", rdlength)
	}
	if offset+16 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(r.Address[:], buf[offset:offset+16])
	return 16, nil
}

// String returns the IPv6 address as a string.
func (r *RDataAAAA) String() string {
	return net.IP(r.Address[:]).String()
}

// Len returns 16.
func (r *RDataAAAA) Len() int { return 16 }

// Copy creates a copy.
func (r *RDataAAAA) Copy() RData {
	return &RDataAAAA{Address: r.Address}
}

// IP returns the address as net.IP.
func (r *RDataAAAA) IP() net.IP {
	return net.IP(r.Address[:])
}

// SetIP sets the address from net.IP.
func (r *RDataAAAA) SetIP(ip net.IP) {
	if v6 := ip.To16(); v6 != nil {
		copy(r.Address[:], v6)
	}
}

// ============================================================================
// CNAME Record (Canonical Name) - RFC 1035
// ============================================================================

// RDataCNAME represents a CNAME record.
type RDataCNAME struct {
	CName *Name
}

// Type returns TypeCNAME.
func (r *RDataCNAME) Type() uint16 { return TypeCNAME }

// Pack serializes the CNAME record.
func (r *RDataCNAME) Pack(buf []byte, offset int) (int, error) {
	return PackName(r.CName, buf, offset, nil)
}

// Unpack deserializes the CNAME record.
//
// Verifies the consumed bytes don't exceed rdlength so a malformed
// or attacker-crafted RDLENGTH can't desync UnpackResourceRecord's
// offset cursor for the rest of the message. See the TXT/SOA
// rdlength-bypass fixes for the broader class.
func (r *RDataCNAME) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	name, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	if n > int(rdlength) {
		return 0, fmt.Errorf("CNAME overflows rdlength (%d > %d)", n, rdlength)
	}
	r.CName = name
	return n, nil
}

// String returns the canonical name.
func (r *RDataCNAME) String() string {
	if r.CName == nil {
		return "."
	}
	return r.CName.String()
}

// Len returns the wire length.
func (r *RDataCNAME) Len() int {
	if r.CName == nil {
		return 1
	}
	return r.CName.WireLength()
}

// Copy creates a copy.
func (r *RDataCNAME) Copy() RData {
	var cname *Name
	if r.CName != nil {
		cname = NewName(r.CName.Labels, r.CName.FQDN)
	}
	return &RDataCNAME{CName: cname}
}

// ============================================================================
// DNAME Record (Delegation Name) - RFC 6672
// ============================================================================

// RDataDNAME represents a DNAME record.
type RDataDNAME struct {
	DName *Name
}

// Type returns TypeDNAME.
func (r *RDataDNAME) Type() uint16 { return TypeDNAME }

// Pack serializes the DNAME record.
func (r *RDataDNAME) Pack(buf []byte, offset int) (int, error) {
	return PackName(r.DName, buf, offset, nil)
}

// Unpack deserializes the DNAME record. See RDataCNAME.Unpack for the
// rdlength-bypass rationale.
func (r *RDataDNAME) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	name, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	if n > int(rdlength) {
		return 0, fmt.Errorf("DNAME overflows rdlength (%d > %d)", n, rdlength)
	}
	r.DName = name
	return n, nil
}

// String returns the delegation target name.
func (r *RDataDNAME) String() string {
	if r.DName == nil {
		return "."
	}
	return r.DName.String()
}

// Len returns the wire length.
func (r *RDataDNAME) Len() int {
	if r.DName == nil {
		return 1
	}
	return r.DName.WireLength()
}

// Copy creates a copy.
func (r *RDataDNAME) Copy() RData {
	var dname *Name
	if r.DName != nil {
		dname = NewName(r.DName.Labels, r.DName.FQDN)
	}
	return &RDataDNAME{DName: dname}
}

// ============================================================================
// NS Record (Name Server) - RFC 1035
// ============================================================================

// RDataNS represents an NS record.
type RDataNS struct {
	NSDName *Name
}

// Type returns TypeNS.
func (r *RDataNS) Type() uint16 { return TypeNS }

// Pack serializes the NS record.
func (r *RDataNS) Pack(buf []byte, offset int) (int, error) {
	return PackName(r.NSDName, buf, offset, nil)
}

// Unpack deserializes the NS record. See RDataCNAME.Unpack for the
// rdlength-bypass rationale.
func (r *RDataNS) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	name, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	if n > int(rdlength) {
		return 0, fmt.Errorf("NS overflows rdlength (%d > %d)", n, rdlength)
	}
	r.NSDName = name
	return n, nil
}

// String returns the NS domain name.
func (r *RDataNS) String() string {
	if r.NSDName == nil {
		return "."
	}
	return r.NSDName.String()
}

// Len returns the wire length.
func (r *RDataNS) Len() int {
	if r.NSDName == nil {
		return 1
	}
	return r.NSDName.WireLength()
}

// Copy creates a copy.
func (r *RDataNS) Copy() RData {
	var nsdname *Name
	if r.NSDName != nil {
		nsdname = NewName(r.NSDName.Labels, r.NSDName.FQDN)
	}
	return &RDataNS{NSDName: nsdname}
}

// ============================================================================
// PTR Record (Pointer) - RFC 1035
// ============================================================================

// RDataPTR represents a PTR record.
type RDataPTR struct {
	PtrDName *Name
}

// Type returns TypePTR.
func (r *RDataPTR) Type() uint16 { return TypePTR }

// Pack serializes the PTR record.
func (r *RDataPTR) Pack(buf []byte, offset int) (int, error) {
	return PackName(r.PtrDName, buf, offset, nil)
}

// Unpack deserializes the PTR record. See RDataCNAME.Unpack for the
// rdlength-bypass rationale.
func (r *RDataPTR) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	name, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	if n > int(rdlength) {
		return 0, fmt.Errorf("PTR overflows rdlength (%d > %d)", n, rdlength)
	}
	r.PtrDName = name
	return n, nil
}

// String returns the PTR domain name.
func (r *RDataPTR) String() string {
	if r.PtrDName == nil {
		return "."
	}
	return r.PtrDName.String()
}

// Len returns the wire length.
func (r *RDataPTR) Len() int {
	if r.PtrDName == nil {
		return 1
	}
	return r.PtrDName.WireLength()
}

// Copy creates a copy.
func (r *RDataPTR) Copy() RData {
	var ptrdname *Name
	if r.PtrDName != nil {
		ptrdname = NewName(r.PtrDName.Labels, r.PtrDName.FQDN)
	}
	return &RDataPTR{PtrDName: ptrdname}
}
