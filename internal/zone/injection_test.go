package zone

import (
	"strings"
	"testing"
)

// TestValidateRecordData_RejectsControlChars verifies newline/CR/NUL in a
// record's name or RDATA are rejected — they would otherwise inject extra lines
// into the text zone file.
func TestValidateRecordData_RejectsControlChars(t *testing.T) {
	cases := []struct {
		name, rdata string
		wantErr     bool
	}{
		{"www", "192.0.2.1", false},
		{"www", "192.0.2.1\nevil 3600 IN A 6.6.6.6", true}, // newline injection
		{"www", "192.0.2.1\r\nevil", true},                 // CRLF
		{"www", "v=spf1\x00", true},                        // NUL
		{"ev\nil", "192.0.2.1", true},                      // newline in name
		{"mail", "10 mail.example.com.", false},
	}
	for _, c := range cases {
		err := ValidateRecordData(c.name, c.rdata)
		if (err != nil) != c.wantErr {
			t.Errorf("ValidateRecordData(%q, %q) err=%v, wantErr=%v", c.name, c.rdata, err, c.wantErr)
		}
	}
}

// TestAddRecord_RejectsInjection verifies the manager write path rejects a
// control-char RDATA.
func TestAddRecord_RejectsInjection(t *testing.T) {
	m := NewManager()
	z := NewZone("example.com.")
	z.SOA = &SOARecord{MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1}
	m.zones["example.com."] = z

	err := m.AddRecord("example.com.", Record{Name: "www", Type: "A", TTL: 300, RData: "192.0.2.1\nhijack 3600 IN A 6.6.6.6"})
	if err == nil {
		t.Fatal("AddRecord accepted RDATA with an embedded newline (zone-file injection)")
	}
}

// TestWriteZone_StripsControlChars is the serialization-boundary safety net: if
// a record with control chars somehow reaches the writer, the emitted zone file
// must not contain an injected line.
func TestWriteZone_StripsControlChars(t *testing.T) {
	z := NewZone("example.com.")
	z.SOA = &SOARecord{MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1, TTL: 3600}
	z.DefaultTTL = 3600
	// Bypass validation by inserting directly (simulating a hypothetical path).
	z.Records["www.example.com."] = []Record{{Name: "www.example.com.", Type: "A", Class: "IN", TTL: 300, RData: "192.0.2.1\nhijack 3600 IN A 6.6.6.6"}}

	out, err := WriteZone(z)
	if err != nil {
		t.Fatalf("WriteZone: %v", err)
	}
	if strings.Contains(out, "hijack") && strings.Contains(out, "\nhijack") {
		// Ensure "hijack" is not on its own injected line.
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "hijack") {
				t.Fatalf("zone file contains an injected line: %q", line)
			}
		}
	}
}
