// NothingDNS - tests for presentation-format (text) RData parsing.

package protocol

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
)

// TestParseRRSIGTimeField verifies that RRSIG inception/expiration fields
// accept both the RFC 4034 §3.2 presentation format (YYYYMMDDHHMMSS, 14
// digits, UTC) and bare uint32 Unix seconds, and reject values outside the
// uint32 range. This is the single shared implementation used by the server,
// zone transfers, and dnsctl (which used to have a duplicate).
func TestParseRRSIGTimeField(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		want   uint32
		wantOK bool
	}{
		{name: "bind presentation before epoch rejected", in: "19691231235959"},
		{name: "bind presentation at epoch accepted", in: "19700101000000", want: 0, wantOK: true},
		{name: "bind presentation normal time accepted", in: "20250101000000", want: 1735689600, wantOK: true},
		{name: "bind presentation max uint32 accepted", in: "21060207062815", want: ^uint32(0), wantOK: true},
		{name: "bind presentation above max uint32 rejected", in: "21060207062816"},
		{name: "bind presentation malformed month rejected", in: "20251301000000"},
		{name: "bare unix seconds accepted", in: "1733088000", want: 1733088000, wantOK: true},
		{name: "bare max uint32 accepted", in: "4294967295", want: ^uint32(0), wantOK: true},
		{name: "bare above max uint32 rejected", in: "4294967296"},
		{name: "garbage rejected", in: "not-a-time"},
		{name: "empty rejected", in: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseRRSIGTimeField(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("parseRRSIGTimeField(%q) ok = %v, want %v", tt.in, ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Fatalf("parseRRSIGTimeField(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// TestParseRDataText_DNSSECRoundTrip parses DNSSEC record types from
// presentation format and verifies that re-serializing via String()
// and parsing again yields identical wire bytes (pack round trip).
func TestParseRDataText_DNSSECRoundTrip(t *testing.T) {
	keyB64 := base64.StdEncoding.EncodeToString([]byte("fake-public-key-bytes"))
	sigB64 := base64.StdEncoding.EncodeToString([]byte("fake-signature-bytes"))

	tests := []struct {
		rtype string
		rdata string
	}{
		{"DNSKEY", fmt.Sprintf("257 3 13 %s", keyB64)},
		{"DS", "12345 13 2 49fd46e6c4b45c55d4ac49fd46e6c4b45c55d4ac49fd46e6c4b45c55d4ac1234"},
		{"RRSIG", fmt.Sprintf("A 13 2 300 20250101000000 20241201000000 12345 example.com. %s", sigB64)},
		{"RRSIG", fmt.Sprintf("A 13 2 300 1735689600 1733011200 12345 example.com. %s", sigB64)},
		{"NSEC", "host.example.com. A MX RRSIG NSEC"},
		{"NSEC3", "1 0 5 abcdef 2t7b4g4vsa5smi47k61mv5bv1a22bojr A RRSIG"},
		{"NSEC3", "1 1 0 - 2t7b4g4vsa5smi47k61mv5bv1a22bojr"},
		{"NSEC3PARAM", "1 0 5 abcdef"},
	}

	for _, tt := range tests {
		t.Run(tt.rtype+" "+tt.rdata, func(t *testing.T) {
			rd := ParseRDataText(tt.rtype, tt.rdata)
			if rd == nil {
				t.Fatalf("ParseRDataText(%q, %q) = nil", tt.rtype, tt.rdata)
			}
			wire1 := packRDataForTest(t, rd)

			// Re-parse the presentation form produced by String().
			rd2 := ParseRDataText(tt.rtype, rd.String())
			if rd2 == nil {
				t.Fatalf("re-parse of String() output %q = nil", rd.String())
			}
			wire2 := packRDataForTest(t, rd2)

			if !bytes.Equal(wire1, wire2) {
				t.Fatalf("wire mismatch after round trip:\n first: %x\nsecond: %x", wire1, wire2)
			}
		})
	}
}

func packRDataForTest(t *testing.T, rd RData) []byte {
	t.Helper()
	buf := make([]byte, rd.Len())
	n, err := rd.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return buf[:n]
}
