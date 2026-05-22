package zone

// Fuzz the BIND-format zone parser. Zone file contents are
// attacker-controlled when received over AXFR/IXFR or loaded from
// untrusted templates, so the parser must never panic on malformed
// input. Errors are fine; crashes are not.

import (
	"bytes"
	"testing"
)

func FuzzParseZoneFile(f *testing.F) {
	// Seed corpus with valid, edge-case, and malformed zone snippets.
	f.Add([]byte("$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 hostmaster 1 7200 3600 1209600 3600\n"))
	f.Add([]byte("@ IN A 127.0.0.1\n"))
	f.Add([]byte("$GENERATE 1-3 host$ A 192.0.2.$\n"))
	f.Add([]byte("@ IN MX 10 mail.example.com.\n"))
	f.Add([]byte("@ IN TXT \"hello\\\"world\"\n"))
	// Multiline parens.
	f.Add([]byte("@ IN SOA (\n  ns1 hostmaster 1 7200 3600 1209600 3600 )\n"))
	// Pathological: unbalanced parens.
	f.Add([]byte("@ IN SOA ( ns1 hostmaster\n"))
	// Empty.
	f.Add([]byte{})
	// Just whitespace and comments.
	f.Add([]byte(";; comment\n   \n\t\n"))
	// Long label trigger.
	long := bytes.Repeat([]byte("x"), 300)
	f.Add(append([]byte("@ IN A "), long...))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic; errors are expected.
		_, _ = ParseFile("fuzz.zone", bytes.NewReader(data))
	})
}
