package main

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const smokeZone = `$ORIGIN smoke.test.
$TTL 300
@   IN SOA ns1.smoke.test. admin.smoke.test. (2026071701 3600 900 604800 300)
@   IN NS  ns1.smoke.test.
ns1 IN A   127.0.0.1
www IN A   192.0.2.10
al  IN CNAME www
`

func TestCNAMEChainFromRelativeZoneFile(t *testing.T) {
	z, err := zone.ParseFile("smoke.test.zone", strings.NewReader(smokeZone))
	if err != nil {
		t.Fatalf("parse zone: %v", err)
	}
	h := newTestHandler()
	h.zones = map[string]*zone.Zone{"smoke.test.": z}

	res := h.chaseCNAMEInZones("al.smoke.test.")
	if res.loopDetected {
		t.Fatal("unexpected loop")
	}
	if res.targetName != "www.smoke.test." {
		t.Fatalf("chase target = %q, want www.smoke.test.", res.targetName)
	}
	if len(res.cnameRecords) != 1 {
		t.Fatalf("cname records = %d, want 1", len(res.cnameRecords))
	}
	if res.cnameRecords[0].Name != "al.smoke.test." {
		t.Fatalf("cname owner = %q", res.cnameRecords[0].Name)
	}

	query, _ := protocol.NewQuery(1, "al.smoke.test.", protocol.TypeA)
	targets := h.resolveCNAMETarget(nil, query, query.Questions[0], res.targetName, protocol.TypeA)
	if len(targets) != 1 {
		t.Fatalf("target answers = %d, want 1", len(targets))
	}
	if got := targets[0].Name.String(); got != "www.smoke.test." {
		t.Fatalf("target owner = %q, want www.smoke.test.", got)
	}

	resp := h.buildCNAMEResponse(query, res.cnameRecords, targets)
	buf := make([]byte, resp.WireLength())
	n, err := resp.Pack(buf)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	rt, err := protocol.UnpackMessage(buf[:n])
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(rt.Answers) != 2 {
		t.Fatalf("answers = %d, want 2", len(rt.Answers))
	}
	if got := rt.Answers[0].Name.String(); got != "al.smoke.test." {
		t.Fatalf("wire CNAME owner = %q", got)
	}
	if got := rt.Answers[1].Name.String(); got != "www.smoke.test." {
		t.Fatalf("wire A owner = %q, want www.smoke.test.", got)
	}
}
