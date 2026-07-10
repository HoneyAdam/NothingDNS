package transfer

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func mkName(t *testing.T, s string) *protocol.Name {
	t.Helper()
	n, err := protocol.ParseName(s)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", s, err)
	}
	return n
}

func mkSOARR(t *testing.T, serial uint32) *protocol.ResourceRecord {
	t.Helper()
	return &protocol.ResourceRecord{
		Name:  mkName(t, "example.com."),
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   3600,
		Data: &protocol.RDataSOA{
			MName:   mkName(t, "ns1.example.com."),
			RName:   mkName(t, "admin.example.com."),
			Serial:  serial,
			Refresh: 7200, Retry: 3600, Expire: 1209600, Minimum: 3600,
		},
	}
}

func mkARR(t *testing.T, name string, a, b, c, d byte) *protocol.ResourceRecord {
	t.Helper()
	return &protocol.ResourceRecord{
		Name:  mkName(t, name),
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   3600,
		Data:  &protocol.RDataA{Address: [4]byte{a, b, c, d}},
	}
}

func newTestSlaveZone(t *testing.T) *SlaveZone {
	t.Helper()
	sz, err := NewSlaveZone(SlaveZoneConfig{
		ZoneName: "example.com.",
		Masters:  []string{"192.0.2.1:53"},
	})
	if err != nil {
		t.Fatalf("NewSlaveZone: %v", err)
	}
	return sz
}

func zoneHas(z *zone.Zone, name, rtype, rdata string) bool {
	for _, r := range z.Records[strings.ToLower(name)] {
		if strings.EqualFold(r.Type, rtype) && r.RData == rdata {
			return true
		}
	}
	return false
}

// TestApplyIncrementalIXFR_AppliesDiff is the core regression test: an
// incremental IXFR must delete the records in the deletion section, add those
// in the addition section, and preserve every unchanged record. The old code
// treated the whole stream as additions, so it resurrected deleted records and
// dropped unchanged ones.
func TestApplyIncrementalIXFR_AppliesDiff(t *testing.T) {
	sm := &SlaveManager{}
	sz := newTestSlaveZone(t)

	// Seed the base zone (serial 100) via a full AXFR: keep + old.
	full := []*protocol.ResourceRecord{
		mkSOARR(t, 100),
		mkARR(t, "keep.example.com.", 192, 0, 2, 10),
		mkARR(t, "old.example.com.", 192, 0, 2, 20),
		mkSOARR(t, 100),
	}
	if err := sm.applyTransferredZone(sz, full); err != nil {
		t.Fatalf("seed applyTransferredZone: %v", err)
	}
	base := sz.GetZone()
	if !zoneHas(base, "keep.example.com.", "A", "192.0.2.10") ||
		!zoneHas(base, "old.example.com.", "A", "192.0.2.20") {
		t.Fatalf("base zone not seeded correctly: %+v", base.Records)
	}

	// Incremental IXFR 100 -> 101: delete old, add new. keep is untouched.
	incremental := []*protocol.ResourceRecord{
		mkSOARR(t, 101),                             // leading SOA (target)
		mkSOARR(t, 100),                             // old-SOA: begin deletions
		mkARR(t, "old.example.com.", 192, 0, 2, 20), // delete old
		mkSOARR(t, 101),                             // new-SOA: begin additions
		mkARR(t, "new.example.com.", 192, 0, 2, 30), // add new
		mkSOARR(t, 101),                             // trailing SOA
	}
	if err := sm.applyTransferredZone(sz, incremental); err != nil {
		t.Fatalf("incremental applyTransferredZone: %v", err)
	}

	z := sz.GetZone()
	if sz.GetLastSerial() != 101 {
		t.Fatalf("serial = %d, want 101", sz.GetLastSerial())
	}
	// Unchanged record preserved.
	if !zoneHas(z, "keep.example.com.", "A", "192.0.2.10") {
		t.Errorf("unchanged record keep.example.com. was lost")
	}
	// Deleted record gone (must NOT be resurrected).
	if zoneHas(z, "old.example.com.", "A", "192.0.2.20") {
		t.Errorf("deleted record old.example.com. is still present")
	}
	// Added record present.
	if !zoneHas(z, "new.example.com.", "A", "192.0.2.30") {
		t.Errorf("added record new.example.com. is missing")
	}
}

// TestApplyTransferredZone_FullAXFRStillRebuilds ensures the full-transfer path
// is unchanged: a fresh AXFR replaces the zone contents wholesale.
func TestApplyTransferredZone_FullAXFRStillRebuilds(t *testing.T) {
	sm := &SlaveManager{}
	sz := newTestSlaveZone(t)

	first := []*protocol.ResourceRecord{
		mkSOARR(t, 100),
		mkARR(t, "a.example.com.", 192, 0, 2, 1),
		mkSOARR(t, 100),
	}
	if err := sm.applyTransferredZone(sz, first); err != nil {
		t.Fatalf("first AXFR: %v", err)
	}

	// A later full AXFR (serial 200) with a different record set fully replaces.
	second := []*protocol.ResourceRecord{
		mkSOARR(t, 200),
		mkARR(t, "b.example.com.", 192, 0, 2, 2),
		mkSOARR(t, 200),
	}
	if err := sm.applyTransferredZone(sz, second); err != nil {
		t.Fatalf("second AXFR: %v", err)
	}
	z := sz.GetZone()
	if zoneHas(z, "a.example.com.", "A", "192.0.2.1") {
		t.Errorf("old record a.example.com. survived a full AXFR replacement")
	}
	if !zoneHas(z, "b.example.com.", "A", "192.0.2.2") {
		t.Errorf("new record b.example.com. missing after full AXFR")
	}
	if sz.GetLastSerial() != 200 {
		t.Errorf("serial = %d, want 200", sz.GetLastSerial())
	}
}
