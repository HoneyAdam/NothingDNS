// Package zone implements DNS zone file parsing and management.
// This file implements RFC 8976 - Message Digests for DNS Zones (ZONEMD).
package zone

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"net"
	"sort"
	"strings"
)

// ZONEMD represents a Message Digest for DNS Zones per RFC 8976.
// ZONEMD provides cryptographic verification of zone contents during zone transfer.
type ZONEMD struct {
	ZoneName  string
	Hash      []byte
	Algorithm uint8 // 1=SHA-256, 2=SHA-384
	TTL       uint32
}

// ZONEMDAlgorithm represents the hash algorithm used for zone digests.
type ZONEMDAlgorithm uint8

const (
	// ZONEMDSHA256 is the SHA-256 algorithm for zone digests.
	ZONEMDSHA256 ZONEMDAlgorithm = 1
	// ZONEMDSHA384 is the SHA-384 algorithm for zone digests.
	ZONEMDSHA384 ZONEMDAlgorithm = 2
)

// ZoneMDError represents errors during ZONEMD computation.
type ZoneMDError struct {
	Zone string
	Msg  string
}

func (e *ZoneMDError) Error() string {
	return fmt.Sprintf("zonemd %s: %s", e.Zone, e.Msg)
}

// ComputeZoneMD computes the ZONEMD for a zone per RFC 8976 Section 4.
// The digest is computed over all RRsets in canonical order.
func ComputeZoneMD(z *Zone, algo ZONEMDAlgorithm) (*ZONEMD, error) {
	if z == nil {
		return nil, &ZoneMDError{Zone: "", Msg: "nil zone"}
	}
	if z.Origin == "" {
		return nil, &ZoneMDError{Zone: z.Origin, Msg: "empty origin"}
	}

	// Collect all RRsets for the zone
	rrsets, err := collectZoneRRsets(z)
	if err != nil {
		return nil, &ZoneMDError{Zone: z.Origin, Msg: err.Error()}
	}

	// Sort RRsets in canonical order per RFC 8976 Section 4.2
	sortRRsets(rrsets)

	// Compute hash over sorted RRsets
	var hash []byte
	switch algo {
	case ZONEMDSHA384:
		h := sha512.New384()
		for _, rrset := range rrsets {
			h.Write(rrset)
		}
		hash = h.Sum(nil)
	case ZONEMDSHA256, ZONEMDAlgorithm(0):
		h := sha256.New()
		for _, rrset := range rrsets {
			h.Write(rrset)
		}
		hash = h.Sum(nil)
	default:
		return nil, &ZoneMDError{Zone: z.Origin, Msg: fmt.Sprintf("unknown algorithm: %d", algo)}
	}

	return &ZONEMD{
		ZoneName:  z.Origin,
		Hash:      hash,
		Algorithm: uint8(algo),
		TTL:       0, // ZONEMD TTL is typically 0
	}, nil
}

// collectZoneRRsets collects all RRsets from a zone per RFC 8976 §3.1.1.
// Every RR in the zone is included in the digest EXCEPT:
//
//	the ZONEMD RR(s) themselves; and
//	any RRSIG RR whose Type Covered field is ZONEMD.
//
// SOA, apex NS/DNSKEY/etc. are included like any other RRset. Each RR is
// emitted in its full canonical wire form (owner|type|class|ttl|rdlen|rdata)
// per §3.3.2; concatenating only the RDATA, as an earlier version of this
// file did, produces a digest that does not match any RFC-compliant peer.
func collectZoneRRsets(z *Zone) ([][]byte, error) {
	var rrsets [][]byte

	const typeSOA uint16 = 6
	const typeRRSIG uint16 = 46
	const typeZONEMD uint16 = 63

	// Emit the apex SOA as a canonical RRset of its own. This replaces the
	// previous "bare RDATA" path.
	if z.SOA != nil {
		soaRdata := serializeSOA(z.SOA)
		soaTTL := z.SOA.TTL
		if soaTTL == 0 {
			soaTTL = z.DefaultTTL
		}
		rrsets = append(rrsets, buildCanonicalRRset(z.Origin, typeSOA, soaTTL, [][]byte{soaRdata}))
	}

	// Collect every other RR in the zone, grouped into RRsets by (name,type).
	for name, records := range z.Records {
		// Group records by type (RRset). All RRs in an RRset share a TTL
		// (RFC 1035 §3.2.1); we use the TTL of the first encountered RR.
		rrsetMap := make(map[uint16][][]byte)
		rrsetTTL := make(map[uint16]uint32)

		for _, rec := range records {
			rtype, err := parseRecordType(rec.Type)
			if err != nil {
				continue
			}

			// Skip the apex SOA here (emitted above from z.SOA).
			if rtype == typeSOA && (name == z.Origin || name == z.Origin+".") {
				continue
			}

			// RFC 8976 §3.1.1: exclude the ZONEMD RR itself.
			if rtype == typeZONEMD {
				continue
			}

			// And exclude RRSIGs that cover the ZONEMD RR. RRSIG RDATA
			// begins with a uint16 "Type Covered" field; we parse just
			// that to decide whether to skip.
			if rtype == typeRRSIG {
				rdata := serializeRecordData(rec)
				if len(rdata) >= 2 {
					covered := uint16(rdata[0])<<8 | uint16(rdata[1])
					if covered == typeZONEMD {
						continue
					}
				}
			}

			rdata := serializeRecordData(rec)
			rrsetMap[rtype] = append(rrsetMap[rtype], rdata)
			if _, ok := rrsetTTL[rtype]; !ok {
				rrsetTTL[rtype] = rec.TTL
			}
		}

		// Emit each RRset in canonical RR-by-RR form.
		for rtype, rdataList := range rrsetMap {
			rrset := buildCanonicalRRset(name, rtype, rrsetTTL[rtype], rdataList)
			rrsets = append(rrsets, rrset)
		}
	}

	return rrsets, nil
}

// sortRRsets sorts RRsets in canonical order per RFC 8976 Section 4.2.
// Order is: name (canonical DNS wire format), then type, then rdatas.
func sortRRsets(rrsets [][]byte) {
	sort.Slice(rrsets, func(i, j int) bool {
		return string(rrsets[i]) < string(rrsets[j])
	})
}

// buildCanonicalRRset emits an RRset in RFC 8976 §3.3.2 canonical wire form:
// each constituent RR is written as
//
//	owner name (canonical wire) | type (uint16 BE) |
//	class (uint16 BE = IN) | ttl (uint32 BE) |
//	rdlength (uint16 BE) | rdata
//
// and the RRs are concatenated in canonical-order. All zones served by this
// implementation use class IN; if multi-class zones become supported, this
// helper will need a class parameter as well.
func buildCanonicalRRset(name string, rtype uint16, ttl uint32, rdataList [][]byte) []byte {
	const classIN uint16 = 1

	nameWire := canonicalName(name)

	// Canonical RR ordering within the set: sort by RDATA bytewise per
	// RFC 4034 §6.3 (used here for ZONEMD canonicalisation per RFC 8976).
	sorted := make([][]byte, len(rdataList))
	copy(sorted, rdataList)
	sort.Slice(sorted, func(i, j int) bool { return string(sorted[i]) < string(sorted[j]) })

	var result []byte
	for _, rdata := range sorted {
		result = append(result, nameWire...)
		result = append(result, byte(rtype>>8), byte(rtype&0xff))
		result = append(result, byte(classIN>>8), byte(classIN&0xff))
		result = append(result, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl&0xff))
		rdlen := uint16(len(rdata))
		result = append(result, byte(rdlen>>8), byte(rdlen&0xff))
		result = append(result, rdata...)
	}
	return result
}

// canonicalName returns the canonical wire format of a domain name.
func canonicalName(name string) []byte {
	// Remove trailing dot if present
	name = strings.TrimSuffix(name, ".")

	var result []byte
	labels := strings.Split(name, ".")
	// Process from TLD to subdomain (reverse order for canonical)
	for i := len(labels) - 1; i >= 0; i-- {
		label := strings.ToLower(labels[i])
		result = append(result, byte(len(label)))
		result = append(result, label...)
	}
	result = append(result, 0) // Root label

	return result
}

// serializeSOA serializes SOA record data in canonical format.
func serializeSOA(soa *SOARecord) []byte {
	var result []byte

	// MName (primary nameserver)
	result = append(result, canonicalName(soa.MName)...)

	// RName (responsible person)
	result = append(result, canonicalName(soa.RName)...)

	// Serial (4 bytes)
	result = append(result, byte(soa.Serial>>24), byte(soa.Serial>>16), byte(soa.Serial>>8), byte(soa.Serial))

	// Refresh (4 bytes)
	result = append(result, byte(soa.Refresh>>24), byte(soa.Refresh>>16), byte(soa.Refresh>>8), byte(soa.Refresh))

	// Retry (4 bytes)
	result = append(result, byte(soa.Retry>>24), byte(soa.Retry>>16), byte(soa.Retry>>8), byte(soa.Retry))

	// Expire (4 bytes)
	result = append(result, byte(soa.Expire>>24), byte(soa.Expire>>16), byte(soa.Expire>>8), byte(soa.Expire))

	// Minimum (4 bytes)
	result = append(result, byte(soa.Minimum>>24), byte(soa.Minimum>>16), byte(soa.Minimum>>8), byte(soa.Minimum))

	return result
}

// serializeRecordData serializes record data in canonical format.
func serializeRecordData(rec Record) []byte {
	// This is a simplified implementation
	// Full implementation would handle each record type appropriately
	var result []byte

	switch strings.ToUpper(rec.Type) {
	case "A":
		// 4 bytes IPv4 address
		ip := net.ParseIP(rec.RData)
		if ip != nil {
			result = append(result, ip.To4()...)
		}
	case "AAAA":
		// 16 bytes IPv6 address
		ip := net.ParseIP(rec.RData)
		if ip != nil {
			result = append(result, ip.To16()...)
		}
	case "CNAME", "DNAME":
		result = append(result, canonicalName(rec.RData)...)
	case "NS":
		result = append(result, canonicalName(rec.RData)...)
	case "PTR":
		result = append(result, canonicalName(rec.RData)...)
	case "MX":
		// Priority (2 bytes) + target name
		// Format: priority | target
		parts := strings.Fields(rec.RData)
		if len(parts) >= 2 {
			var priority uint16
			fmt.Sscanf(parts[0], "%d", &priority)
			result = append(result, byte(priority>>8), byte(priority&0xff))
			result = append(result, canonicalName(parts[1])...)
		}
	case "TXT":
		// TXT records are stored as length-prefixed character strings.
		// Per RFC 1035, each string is max 255 bytes. Longer content
		// must be split into multiple strings.
		txtData := []byte(rec.RData)
		for len(txtData) > 0 {
			chunk := txtData
			if len(chunk) > 255 {
				chunk = chunk[:255]
			}
			result = append(result, byte(len(chunk)))
			result = append(result, chunk...)
			txtData = txtData[len(chunk):]
		}
	case "SPF":
		result = append(result, byte(len(rec.RData)))
		result = append(result, rec.RData...)
	default:
		// For unknown types, just use raw data
		result = []byte(rec.RData)
	}

	return result
}

// parseRecordType converts a record type string to uint16.
func parseRecordType(typeStr string) (uint16, error) {
	switch strings.ToUpper(typeStr) {
	case "A":
		return 1, nil
	case "NS":
		return 2, nil
	case "CNAME":
		return 5, nil
	case "SOA":
		return 6, nil
	case "PTR":
		return 12, nil
	case "MX":
		return 15, nil
	case "TXT":
		return 16, nil
	case "AAAA":
		return 28, nil
	case "SRV":
		return 33, nil
	case "NAPTR":
		return 35, nil
	case "DNSKEY":
		return 48, nil
	case "RRSIG":
		return 46, nil
	case "NSEC":
		return 47, nil
	case "DS":
		return 43, nil
	case "NSEC3":
		return 50, nil
	case "NSEC3PARAM":
		return 51, nil
	case "TLSA":
		return 52, nil
	case "ZONEMD":
		return 63, nil
	case "TYPE63":
		return 63, nil
	default:
		return 0, fmt.Errorf("unknown record type: %s", typeStr)
	}
}

// String returns a string representation of the ZONEMD.
func (z *ZONEMD) String() string {
	if z == nil {
		return ""
	}
	hashStr := ""
	for _, b := range z.Hash {
		hashStr += fmt.Sprintf("%02x", b)
	}
	return fmt.Sprintf("ZONEMD %s %d %s", z.ZoneName, z.Algorithm, hashStr)
}

// Verify checks if the computed ZONEMD matches an expected value.
func (z *ZONEMD) Verify(expected *ZONEMD) bool {
	if z.ZoneName != expected.ZoneName {
		return false
	}
	if z.Algorithm != expected.Algorithm {
		return false
	}
	if len(z.Hash) != len(expected.Hash) {
		return false
	}
	for i := range z.Hash {
		if z.Hash[i] != expected.Hash[i] {
			return false
		}
	}
	return true
}
