package zone

import (
	"strings"
	"testing"
)

// TestParseFile_ExplicitZeroTTLPreserved verifies that an explicit TTL of 0
// (RFC 2181 §8 "do not cache") is preserved rather than silently replaced by
// the zone's $TTL default, while a record with no TTL field still inherits
// $TTL.
func TestParseFile_ExplicitZeroTTLPreserved(t *testing.T) {
	const zoneText = `$ORIGIN example.com.
$TTL 3600
@       IN SOA ns1.example.com. admin.example.com. ( 1 7200 3600 1209600 3600 )
@       IN NS  ns1.example.com.
nocache 0  IN A 192.0.2.1
normal     IN A 192.0.2.2
`

	z, err := ParseFile("example.com.zone", strings.NewReader(zoneText))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	find := func(owner string) Record {
		t.Helper()
		recs := z.Records[strings.ToLower(owner)]
		for _, r := range recs {
			if r.Type == "A" {
				return r
			}
		}
		t.Fatalf("no A record for %q (records: %v)", owner, recs)
		return Record{}
	}

	if got := find("nocache.example.com.").TTL; got != 0 {
		t.Errorf("explicit TTL 0 record: TTL = %d, want 0 (must not be replaced by $TTL)", got)
	}
	if got := find("normal.example.com.").TTL; got != 3600 {
		t.Errorf("no-TTL record: TTL = %d, want 3600 ($TTL default)", got)
	}
}
