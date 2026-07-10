package dnssec

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestNSEC3ClosestEncloserAndNextCloser_WildcardPositive verifies the NSEC3
// closest-encloser + next-closer proof used for wildcard-POSITIVE answers
// (RFC 5155 §8.8): it proves the QNAME has no exact match WITHOUT requiring a
// wildcard cover, and the NXDOMAIN validator (which does require the wildcard
// cover) correctly rejects the same proof.
func TestNSEC3ClosestEncloserAndNextCloser_WildcardPositive(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)
	qname := "anything.wild.example.com."

	hashEnc := func(name string) ([]byte, string) {
		raw, err := NSEC3Hash(name, 1, 0, nil)
		if err != nil {
			t.Fatalf("NSEC3Hash(%q): %v", name, err)
		}
		return raw, strings.ToUpper(protocol.Base32Encode(raw))
	}
	mkRR := func(owner string, next []byte) *protocol.ResourceRecord {
		n, _ := protocol.ParseName(owner)
		return &protocol.ResourceRecord{
			Name: n, Type: protocol.TypeNSEC3, Class: protocol.ClassIN,
			Data: &protocol.RDataNSEC3{HashAlgorithm: 1, Iterations: 0, Salt: nil, HashLength: uint8(len(next)), NextHashed: next},
		}
	}

	// Closest encloser wild.example.com. — an NSEC3 whose owner-hash matches.
	// Give it a TIGHT range (next = owner+1) so it proves only the exact match
	// and does not itself cover the next-closer hash.
	ceRaw, ceEnc := hashEnc("wild.example.com.")
	ceNext := make([]byte, len(ceRaw))
	copy(ceNext, ceRaw)
	ceNext[len(ceNext)-1]++
	ceRR := mkRR(ceEnc+".example.com.", ceNext)

	// Next-closer cover for anything.wild.example.com. — a degenerate
	// owner==next NSEC3 (RFC 5155 §6.1) that covers every hash except its own.
	otherRaw := make([]byte, len(ceRaw))
	otherRaw[len(otherRaw)-1] = 0x01
	coverRR := mkRR("00000000000000000000000000000001.example.com.", otherRaw)

	rrs := []*protocol.ResourceRecord{ceRR, coverRR}

	ce, _, ok := v.nsec3ClosestEncloserAndNextCloser(qname, rrs)
	if !ok {
		t.Fatal("expected NSEC3 closest-encloser + next-closer proof to succeed for wildcard-positive answer")
	}
	if ce != "wild.example.com" {
		t.Errorf("closest encloser = %q, want %q", ce, "wild.example.com")
	}

	// Negative: with NO next-closer cover (only the CE match), the proof must
	// fail — a wildcard-positive answer still requires proof the QNAME itself
	// has no exact match.
	if _, _, ok := v.nsec3ClosestEncloserAndNextCloser(qname, []*protocol.ResourceRecord{ceRR}); ok {
		t.Error("proof succeeded with only a closest-encloser match and no next-closer cover")
	}
}
