package dnssec

import (
	"context"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestValidateMessage_WildcardDepthMismatchBogus is a security regression test
// for a wildcard fail-open: a genuine shallow "*.example.com" RRSIG (Labels=2)
// replayed onto a deep name a.sub.example.com — which must be NXDOMAIN because
// its real source of synthesis "*.sub.example.com" does not exist — must be
// rejected (BOGUS). The validator must bind the wildcard depth to the PROVEN
// closest encloser: the NSEC3 proof establishes closest encloser
// sub.example.com (3 labels), which does not match the wildcard's 2-label
// closest encloser example.com, so the answer is not authenticated.
func TestValidateMessage_WildcardDepthMismatchBogus(t *testing.T) {
	v, chain, priv, keyTag := wildcardTestFixture(t) // zone example.com.

	// Attacker's answer: A at a.sub.example.com signed with *.example.com
	// (Labels=2 → closest encloser = rightmost 2 labels = example.com).
	qname := "a.sub.example.com."
	owner, _ := protocol.ParseName(qname)
	aRecord := &protocol.ResourceRecord{Name: owner, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{6, 6, 6, 6}}}
	aRRSIG := signRR(t, v, aRecord, 2, priv, keyTag) // genuine *.example.com signature

	b32 := func(name string) string {
		h, err := NSEC3Hash(name, 1, 0, nil)
		if err != nil {
			t.Fatalf("NSEC3Hash(%q): %v", name, err)
		}
		return strings.ToUpper(protocol.Base32Encode(h))
	}
	nsec3RR := func(ownerName string, next []byte, types ...uint16) *protocol.ResourceRecord {
		n, _ := protocol.ParseName(ownerName)
		return &protocol.ResourceRecord{Name: n, Type: protocol.TypeNSEC3, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataNSEC3{HashAlgorithm: 1, Iterations: 0, Salt: nil, HashLength: uint8(len(next)), NextHashed: next, TypeBitMap: types}}
	}

	// Genuine NSEC3 matching closest encloser sub.example.com (its hash is an
	// owner). Tight next so it doesn't itself cover the next closer.
	ceRaw, _ := NSEC3Hash("sub.example.com", 1, 0, nil)
	ceNext := make([]byte, len(ceRaw))
	copy(ceNext, ceRaw)
	ceNext[len(ceNext)-1]++
	ceNSEC3 := nsec3RR(b32("sub.example.com")+".example.com.", ceNext, protocol.TypeNS)

	// Degenerate covering NSEC3 (covers every hash except its own) → covers the
	// next closer a.sub.example.com.
	other := make([]byte, len(ceRaw))
	other[len(other)-1] = 0x01
	coverNSEC3 := nsec3RR("00000000000000000000000000000001.example.com.", other)

	// Sign both NSEC3 RRs with the zone key (owner has 3 labels, not a wildcard).
	ceSig := signRR(t, v, ceNSEC3, 3, priv, keyTag)
	coverSig := signRR(t, v, coverNSEC3, 3, priv, keyTag)

	msg := &protocol.Message{
		Answers:     []*protocol.ResourceRecord{aRecord, aRRSIG},
		Authorities: []*protocol.ResourceRecord{ceNSEC3, ceSig, coverNSEC3, coverSig},
	}

	if got := v.validateMessage(context.Background(), msg, qname, chain); got != ValidationBogus {
		t.Errorf("depth-mismatched wildcard answer = %s, want BOGUS (fail-open: a *.example.com sig authenticated a.sub.example.com)", got)
	}
}
