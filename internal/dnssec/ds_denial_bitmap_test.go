package dnssec

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestNSECProvesNoDS_BitmapConstraints checks RFC 4035 §5.4 / RFC 6840 §4.4:
// an insecure-delegation NoData(DS) NSEC must exactly match the delegation
// name and have NS set with DS and SOA clear. The SOA-clear rule blocks
// replaying a zone-apex NSEC to fake an insecure delegation.
func TestNSECProvesNoDS_BitmapConstraints(t *testing.T) {
	zone := "child.example.com."
	mkNSEC := func(types ...uint16) *protocol.RDataNSEC {
		next, _ := protocol.ParseName("z." + zone)
		return &protocol.RDataNSEC{NextDomain: next, TypeBitMap: types}
	}

	tests := []struct {
		name  string
		owner string
		nsec  *protocol.RDataNSEC
		want  bool
	}{
		{"valid delegation NSEC (NS, no DS/SOA)", zone, mkNSEC(protocol.TypeNS, protocol.TypeRRSIG), true},
		{"apex NSEC replay (SOA set) rejected", zone, mkNSEC(protocol.TypeNS, protocol.TypeSOA, protocol.TypeRRSIG), false},
		{"has DS rejected", zone, mkNSEC(protocol.TypeNS, protocol.TypeDS), false},
		{"no NS (not a delegation) rejected", zone, mkNSEC(protocol.TypeRRSIG), false},
		{"wrong owner rejected", "other.example.com.", mkNSEC(protocol.TypeNS), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := nsecProvesNoDS(tc.owner, zone, tc.nsec); got != tc.want {
				t.Errorf("nsecProvesNoDS = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNSEC3ProvesNoDS_MatchAndOptOut checks the NSEC3 form: a matching NSEC3
// needs NS set and DS/SOA clear; a covering NSEC3 authenticates an insecure
// delegation only with the Opt-Out flag set.
func TestNSEC3ProvesNoDS_MatchAndOptOut(t *testing.T) {
	zone := "child.example.com."
	raw, err := NSEC3Hash(zone, 1, 0, nil)
	if err != nil {
		t.Fatalf("NSEC3Hash: %v", err)
	}
	enc := strings.ToUpper(protocol.Base32Encode(raw))
	matchOwner := enc + ".example.com."

	// Matching NSEC3 with NS, no DS/SOA → accept.
	tight := make([]byte, len(raw))
	copy(tight, raw)
	tight[len(tight)-1]++
	matchOK := &protocol.RDataNSEC3{HashAlgorithm: 1, Iterations: 0, Salt: nil, NextHashed: tight, TypeBitMap: []uint16{protocol.TypeNS, protocol.TypeRRSIG}}
	if !nsec3ProvesNoDS(matchOwner, zone, matchOK) {
		t.Error("matching NSEC3 with NS and no DS/SOA should prove insecure delegation")
	}

	// Matching NSEC3 with SOA → reject.
	matchSOA := &protocol.RDataNSEC3{HashAlgorithm: 1, Iterations: 0, Salt: nil, NextHashed: tight, TypeBitMap: []uint16{protocol.TypeNS, protocol.TypeSOA}}
	if nsec3ProvesNoDS(matchOwner, zone, matchSOA) {
		t.Error("matching NSEC3 with SOA must be rejected (apex replay)")
	}

	// Covering NSEC3 (degenerate owner==next covers all but its own hash).
	otherRaw := make([]byte, len(raw))
	otherRaw[len(otherRaw)-1] = 0x01
	coverOwner := "00000000000000000000000000000001.example.com."
	coverOptOut := &protocol.RDataNSEC3{HashAlgorithm: 1, Iterations: 0, Salt: nil, Flags: protocol.NSEC3FlagOptOut, NextHashed: otherRaw, TypeBitMap: []uint16{}}
	if !nsec3ProvesNoDS(coverOwner, zone, coverOptOut) {
		t.Error("opt-out covering NSEC3 should prove insecure delegation")
	}
	coverNoOptOut := &protocol.RDataNSEC3{HashAlgorithm: 1, Iterations: 0, Salt: nil, Flags: 0, NextHashed: otherRaw, TypeBitMap: []uint16{}}
	if nsec3ProvesNoDS(coverOwner, zone, coverNoOptOut) {
		t.Error("covering NSEC3 WITHOUT opt-out must be rejected")
	}
}
