package transfer

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func newAddTestZone() *zone.Zone {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", Serial: 4000000000}
	return z
}

func addOp(name string, qtype uint16, rdata string) UpdateOperation {
	return UpdateOperation{Name: name, Type: qtype, TTL: 300, RData: rdata, Operation: UpdateOpAdd}
}

func applyOps(t *testing.T, z *zone.Zone, ops ...UpdateOperation) {
	t.Helper()
	if err := ApplyUpdate(z, &UpdateRequest{ZoneName: z.Origin, Updates: ops}); err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}
}

// RFC 2136 §3.4.2.2: adding an RR identical to an existing one must not
// duplicate it — a replayed UPDATE used to stack copies of the same RR.
func TestApplyUpdate_AddIsIdempotent(t *testing.T) {
	z := newAddTestZone()
	applyOps(t, z, addOp("www.example.com.", protocol.TypeA, "192.0.2.1"))
	applyOps(t, z, addOp("www.example.com.", protocol.TypeA, "192.0.2.1"))

	if got := len(z.Records["www.example.com."]); got != 1 {
		t.Fatalf("records after duplicate add = %d, want 1", got)
	}
}

func TestApplyUpdate_AddSameTypeDifferentRData(t *testing.T) {
	z := newAddTestZone()
	applyOps(t, z,
		addOp("www.example.com.", protocol.TypeA, "192.0.2.1"),
		addOp("www.example.com.", protocol.TypeA, "192.0.2.2"),
	)
	if got := len(z.Records["www.example.com."]); got != 2 {
		t.Fatalf("records = %d, want 2 (distinct RDATA)", got)
	}
}

// RFC 2136 §3.4.2.2: a CNAME add is ignored when non-CNAME data exists,
// and non-CNAME adds are ignored at an alias owner.
func TestApplyUpdate_CNAMEExclusivity(t *testing.T) {
	z := newAddTestZone()
	applyOps(t, z, addOp("host.example.com.", protocol.TypeA, "192.0.2.1"))
	applyOps(t, z, addOp("host.example.com.", protocol.TypeCNAME, "target.example.com."))
	recs := z.Records["host.example.com."]
	if len(recs) != 1 || recs[0].Type != "A" {
		t.Fatalf("CNAME add over A data must be ignored, got %+v", recs)
	}

	applyOps(t, z, addOp("alias.example.com.", protocol.TypeCNAME, "target.example.com."))
	applyOps(t, z, addOp("alias.example.com.", protocol.TypeA, "192.0.2.9"))
	recs = z.Records["alias.example.com."]
	if len(recs) != 1 || recs[0].Type != "CNAME" {
		t.Fatalf("A add at alias owner must be ignored, got %+v", recs)
	}

	// CNAME over CNAME replaces (singleton RRset).
	applyOps(t, z, addOp("alias.example.com.", protocol.TypeCNAME, "other.example.com."))
	recs = z.Records["alias.example.com."]
	if len(recs) != 1 || recs[0].RData != "other.example.com." {
		t.Fatalf("CNAME add must replace existing CNAME, got %+v", recs)
	}
}

// RFC 2136 §3.4.2.2: an SOA add is ignored unless at the apex with a
// newer serial; a newer SOA replaces rather than stacks.
func TestApplyUpdate_SOARules(t *testing.T) {
	z := newAddTestZone()

	// Older serial: ignored.
	applyOps(t, z, addOp("example.com.", protocol.TypeSOA,
		"ns1.example.com. admin.example.com. 3999999999 3600 900 604800 300"))
	if z.SOA.Serial != 4000000001 { // 4000000000 + IncrementSerial from the apply itself
		t.Fatalf("older SOA must be ignored; serial = %d", z.SOA.Serial)
	}

	// Newer serial: replaces (then IncrementSerial bumps once more).
	applyOps(t, z, addOp("example.com.", protocol.TypeSOA,
		"ns2.example.com. admin.example.com. 4000000100 3600 900 604800 300"))
	if z.SOA.MName != "ns2.example.com." {
		t.Fatalf("newer SOA must replace; MName = %q", z.SOA.MName)
	}
	var soaCount int
	for _, r := range z.Records["example.com."] {
		if r.Type == "SOA" {
			soaCount++
		}
	}
	if soaCount > 1 {
		t.Fatalf("SOA records stacked: %d", soaCount)
	}

	// SOA outside apex: ignored.
	applyOps(t, z, addOp("sub.example.com.", protocol.TypeSOA,
		"ns1.example.com. admin.example.com. 4000000200 3600 900 604800 300"))
	if len(z.Records["sub.example.com."]) != 0 {
		t.Fatal("SOA outside apex must be ignored")
	}
}
