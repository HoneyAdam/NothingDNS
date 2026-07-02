// Regression tests for the 2026-07-02 resolver cache fixes:
//   - side-record synthesis overwriting the main cache entry with an
//     A-only skeleton (dropping RRSIG/AA/AD → every cache hit went Bogus
//     under DNSSEC validation),
//   - negative cache entries losing their SOA + NSEC/NSEC3 denial proofs,
//     which chain building needs to validate cached DS lookups.

package resolver

import (
	"context"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func makeRRSIGRR(name string, covered uint16) *protocol.ResourceRecord {
	return &protocol.ResourceRecord{
		Name:  mustName(name),
		Type:  protocol.TypeRRSIG,
		Class: protocol.ClassIN,
		TTL:   300,
		Data: &protocol.RDataRRSIG{
			TypeCovered: covered,
			SignerName:  mustName(name),
			Signature:   []byte{1, 2, 3},
		},
	}
}

// The main cache entry for (name, qtype) must keep the FULL response. The
// side-record synthesis loop used to re-Set the same key with an A-only
// skeleton (no RRSIG, no AA/AD flags) whenever the query itself was A/AAAA —
// so the first cache hit onward, DNSSEC validation saw a signature-less
// answer and returned Bogus.
func TestCacheResponse_SideRecordDoesNotClobberMainEntry(t *testing.T) {
	cache := newMockCache()
	cfg := DefaultConfig()
	cfg.AllowPrivateUpstream = true
	r := NewResolver(cfg, cache, newMockTransport())

	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess},
		},
		Questions: []*protocol.Question{
			{Name: mustName("example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
	}
	resp.AddAnswer(makeARR("example.com.", "192.0.2.1"))
	resp.AddAnswer(makeARR("example.com.", "192.0.2.2"))
	resp.AddAnswer(makeRRSIGRR("example.com.", protocol.TypeA))

	r.cacheResponse("example.com.", protocol.TypeA, resp, "com.")

	entry := cache.Get(cacheKey("example.com.", protocol.TypeA))
	if entry == nil || entry.Message == nil {
		t.Fatal("missing main cache entry")
	}
	if len(entry.Message.Answers) != 3 {
		t.Fatalf("main entry answers = %d, want 3 (side-record synthesis clobbered the full response)",
			len(entry.Message.Answers))
	}
	hasSig := false
	for _, rr := range entry.Message.Answers {
		if rr.Type == protocol.TypeRRSIG {
			hasSig = true
		}
	}
	if !hasSig {
		t.Error("main entry lost its RRSIG — cache hits would validate Bogus")
	}
	if !entry.Message.Header.Flags.AA {
		t.Error("main entry lost the AA flag")
	}
}

// Side records for OTHER owners must still be synthesized (that behavior is
// load-bearing for NS-address lookups).
func TestCacheResponse_SideRecordStillCachedForOtherOwners(t *testing.T) {
	cache := newMockCache()
	cfg := DefaultConfig()
	cfg.AllowPrivateUpstream = true
	r := NewResolver(cfg, cache, newMockTransport())

	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess}},
		Questions: []*protocol.Question{
			{Name: mustName("www.example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
	}
	resp.AddAnswer(makeARR("www.example.com.", "192.0.2.1"))
	resp.AddAnswer(makeARR("ns1.example.com.", "192.0.2.53"))

	r.cacheResponse("www.example.com.", protocol.TypeA, resp, "example.com.")

	if side := cache.Get(cacheKey("ns1.example.com.", protocol.TypeA)); side == nil {
		t.Error("side record for ns1.example.com. missing — other-owner synthesis must survive the clobber fix")
	}
}

// negMessageMockCache extends mockCache with the negative-message extension.
type negMessageMockCache struct {
	*mockCache
	negMessages map[string]*protocol.Message
}

func (m *negMessageMockCache) SetNegativeMessage(key string, rcode uint8, msg *protocol.Message, ttl uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key] = &CacheEntry{IsNegative: true, RCode: rcode, Message: msg}
	m.negMessages[key] = msg
}

// cacheNegative must prefer the message-preserving path so the SOA and
// NSEC/NSEC3 denial proofs survive; a proof-less cached NODATA turns every
// validated DS lookup that hits it into Bogus.
func TestCacheNegative_KeepsDenialProofMessage(t *testing.T) {
	cache := &negMessageMockCache{mockCache: newMockCache(), negMessages: map[string]*protocol.Message{}}
	cfg := DefaultConfig()
	r := NewResolver(cfg, cache, newMockTransport())

	neg := &protocol.Message{
		Header: protocol.Header{Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess}},
		Questions: []*protocol.Question{
			{Name: mustName("unsigned.com."), QType: protocol.TypeDS, QClass: protocol.ClassIN},
		},
	}
	soa := &protocol.ResourceRecord{
		Name: mustName("com."), Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 900,
		Data: &protocol.RDataSOA{MName: mustName("a.gtld-servers.net."), RName: mustName("nstld.verisign-grs.com."), Minimum: 900},
	}
	nsec3 := &protocol.ResourceRecord{
		Name: mustName("hash.com."), Type: protocol.TypeNSEC3, Class: protocol.ClassIN, TTL: 900,
		Data: &protocol.RDataNSEC3{HashAlgorithm: 1, NextHashed: []byte{1, 2, 3}},
	}
	neg.AddAuthority(soa)
	neg.AddAuthority(nsec3)

	r.cacheNegative("unsigned.com.", protocol.TypeDS, protocol.RcodeSuccess, neg)

	stored := cache.negMessages[cacheKey("unsigned.com.", protocol.TypeDS)]
	if stored == nil {
		t.Fatal("negative entry stored without its message — denial proofs lost")
	}
	if len(stored.Authorities) != 2 {
		t.Errorf("stored negative authorities = %d, want 2 (SOA + NSEC3)", len(stored.Authorities))
	}

	// And a subsequent Resolve must serve those proofs back.
	msg, err := r.Resolve(context.Background(), "unsigned.com.", protocol.TypeDS)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	foundNSEC3 := false
	for _, rr := range msg.Authorities {
		if rr.Type == protocol.TypeNSEC3 {
			foundNSEC3 = true
		}
	}
	if !foundNSEC3 {
		t.Error("negative cache hit lost the NSEC3 denial proof")
	}
	if len(msg.Questions) != 1 || !strings.EqualFold(msg.Questions[0].Name.String(), "unsigned.com.") {
		t.Errorf("negative cache hit question = %v, want unsigned.com.", msg.Questions)
	}
}
