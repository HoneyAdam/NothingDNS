package dnssec

import (
	"context"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestValidateMessage_BogusForUnsignedInBailiwickOwner is a security regression
// test: an Answer RRset owned by a name IN the signing zone's bailiwick but
// carrying NO RRSIG must make the whole response BOGUS, not SECURE. Previously
// the downgrade check was scoped only to the exact queried name, so an on-path
// attacker could strip the signature on an in-zone record reached via a CNAME
// chain (query www.example.com → CNAME foo.example.com → forged, unsigned
// foo.example.com A) and the message would still be declared SECURE with AD=1.
func TestValidateMessage_BogusForUnsignedInBailiwickOwner(t *testing.T) {
	zoneName, _ := protocol.ParseName("example.com.")
	chain := []*chainLink{{
		zone:      "example.com.",
		dnsKeys:   []*protocol.ResourceRecord{{Name: zoneName, Type: protocol.TypeDNSKEY, Data: &protocol.RDataDNSKEY{}}},
		validated: true,
	}}

	inZoneName, _ := protocol.ParseName("foo.example.com.")
	msg := &protocol.Message{
		Answers: []*protocol.ResourceRecord{{
			Name:  inZoneName,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{6, 6, 6, 6}},
		}},
	}

	config := DefaultValidatorConfig()
	config.RequireDNSSEC = false
	v := NewValidator(config, nil, nil)

	// Queried name is example.com.; the answer's only RRset is foo.example.com.
	// (inside the signed zone) and unsigned — a stripped-RRSIG downgrade.
	if result := v.validateMessage(context.Background(), msg, "example.com.", chain); result != ValidationBogus {
		t.Errorf("expected BOGUS for unsigned in-bailiwick owner (forged record), got %s", result)
	}
}

func TestInBailiwick(t *testing.T) {
	cases := []struct {
		owner, zone string
		want        bool
	}{
		{"foo.example.com.", "example.com.", true},
		{"example.com.", "example.com.", true},
		{"foo.example.com", "example.com.", true},   // trailing-dot insensitive
		{"FOO.Example.Com.", "example.com.", true},   // case insensitive
		{"target.elsewhere.net.", "example.com.", false},
		{"notexample.com.", "example.com.", false},   // suffix must be on a label boundary
		{"anything.", "", true},                       // root contains everything
		{"anything.", ".", true},
	}
	for _, c := range cases {
		if got := inBailiwick(c.owner, c.zone); got != c.want {
			t.Errorf("inBailiwick(%q, %q) = %v, want %v", c.owner, c.zone, got, c.want)
		}
	}
}
