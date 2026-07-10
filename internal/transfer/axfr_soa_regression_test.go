package transfer

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// TestGenerateAXFRRecords_SingleApexSOAPerBoundary is a regression test for a
// critical zone-transfer bug: the zone parser stores the apex SOA in both
// z.SOA and z.Records[apex], so generateAXFRRecords used to emit the SOA three
// times (start + mid-stream + end). RFC 5936 secondaries treat the second SOA
// as end-of-transfer and discard every record after it, truncating the zone.
// The AXFR stream must contain exactly two SOA records: first and last.
func TestGenerateAXFRRecords_SingleApexSOAPerBoundary(t *testing.T) {
	const zoneText = `$ORIGIN example.test.
$TTL 3600
@   IN SOA ns1.example.test. admin.example.test. ( 2026071001 7200 3600 1209600 3600 )
@   IN NS  ns1.example.test.
ns1 IN A   192.0.2.1
@   IN A   192.0.2.10
www IN A   192.0.2.20
www IN AAAA 2001:db8::20
mail IN MX 10 mail.example.test.
`

	z, err := zone.ParseFile("example.test.zone", strings.NewReader(zoneText))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	// Sanity: the parser stores the apex SOA inside z.Records too — this is the
	// precondition that made the duplicate-SOA bug possible.
	var apexSOAsInRecords int
	for _, recs := range z.Records {
		for _, r := range recs {
			if strings.EqualFold(r.Type, "SOA") {
				apexSOAsInRecords++
			}
		}
	}
	if apexSOAsInRecords == 0 {
		t.Fatalf("test precondition failed: expected the parser to store the apex SOA in z.Records")
	}

	server := NewAXFRServer(map[string]*zone.Zone{"example.test.": z})
	records, err := server.generateAXFRRecords(z)
	if err != nil {
		t.Fatalf("generateAXFRRecords: %v", err)
	}

	var soaCount int
	for _, rr := range records {
		if rr.Type == protocol.TypeSOA {
			soaCount++
		}
	}
	if soaCount != 2 {
		t.Fatalf("AXFR stream has %d SOA records, want exactly 2 (first + last); duplicate mid-stream SOA truncates the zone on compliant secondaries", soaCount)
	}

	// The stream must begin and end with the SOA, and every other record must
	// survive between them (no truncation).
	if len(records) < 2 || records[0].Type != protocol.TypeSOA || records[len(records)-1].Type != protocol.TypeSOA {
		t.Fatalf("AXFR stream must start and end with SOA; got first=%v last=%v", records[0].Type, records[len(records)-1].Type)
	}

	// Confirm the non-apex records are actually present between the boundary
	// SOAs (i.e. the zone is not truncated to just the apex).
	var sawWWW bool
	for _, rr := range records {
		if strings.EqualFold(rr.Name.String(), "www.example.test.") {
			sawWWW = true
		}
	}
	if !sawWWW {
		t.Fatalf("AXFR stream is missing www.example.test. records — zone appears truncated")
	}
}
