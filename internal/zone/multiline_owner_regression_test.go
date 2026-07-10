package zone

import (
	"strings"
	"testing"
)

// TestParseFile_MultilineRecordOwnerName is a regression test for a zone-parser
// bug where a parenthesized multi-line record inherited the previous record's
// owner name instead of its own. The parser decided owner inheritance from
// p.scanner.Text(), which for a multi-line record points at the (indented)
// closing-paren line, so every multi-line TXT/DKIM/SPF/DNSKEY/RRSIG record was
// silently filed under the wrong owner.
func TestParseFile_MultilineRecordOwnerName(t *testing.T) {
	const zoneText = `$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1.example.com. admin.example.com. ( 2026071001 7200 3600 1209600 3600 )
@   IN NS  ns1.example.com.
ns1 IN A   192.0.2.1
selector._domainkey IN TXT ( "v=DKIM1; k=rsa; "
                             "p=MIGfMA0GCSq" )
www IN A 192.0.2.2
`

	z, err := ParseFile("example.com.zone", strings.NewReader(zoneText))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	// The DKIM TXT record must be filed under its own owner.
	dkimOwner := "selector._domainkey.example.com."
	recs, ok := z.Records[dkimOwner]
	if !ok {
		t.Fatalf("no records under %q; multi-line record was filed under the wrong owner. Owners present: %v", dkimOwner, ownerKeys(z))
	}
	var sawTXT bool
	for _, r := range recs {
		if strings.EqualFold(r.Type, "TXT") {
			sawTXT = true
			if !strings.Contains(r.RData, "v=DKIM1") || !strings.Contains(r.RData, "MIGfMA0GCSq") {
				t.Fatalf("DKIM TXT RData not assembled correctly: %q", r.RData)
			}
		}
	}
	if !sawTXT {
		t.Fatalf("expected a TXT record under %q, got %v", dkimOwner, recs)
	}

	// The previous owner (ns1) must NOT have absorbed the DKIM TXT.
	if recs, ok := z.Records["ns1.example.com."]; ok {
		for _, r := range recs {
			if strings.EqualFold(r.Type, "TXT") {
				t.Fatalf("ns1.example.com. wrongly absorbed the multi-line TXT record: %q", r.RData)
			}
		}
	}
}

func ownerKeys(z *Zone) []string {
	keys := make([]string, 0, len(z.Records))
	for k := range z.Records {
		keys = append(keys, k)
	}
	return keys
}
