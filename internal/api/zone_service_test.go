package api

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestZoneService_ListZones_NilManager(t *testing.T) {
	zs := NewZoneService(nil)
	resp := zs.ListZones()

	if resp == nil {
		t.Fatal("ListZones() returned nil")
	}
	if resp.Total != 0 {
		t.Errorf("Total = %d, want 0", resp.Total)
	}
	if resp.Truncated {
		t.Error("Truncated = true, want false")
	}
	if len(resp.Zones) != 0 {
		t.Errorf("len(Zones) = %d, want 0", len(resp.Zones))
	}
}

func TestZoneService_GetZone_NilManager(t *testing.T) {
	zs := NewZoneService(nil)
	_, ok := zs.GetZone("example.com.")
	if ok {
		t.Error("GetZone on nil manager: ok = true, want false")
	}
}

func TestZoneService_ZoneExists_NilManager(t *testing.T) {
	zs := NewZoneService(nil)
	if zs.ZoneExists("example.com.") {
		t.Error("ZoneExists on nil manager: true, want false")
	}
}

func TestZoneService_ListZones_WithZones(t *testing.T) {
	mgr := zone.NewManager()
	soa := &zone.SOARecord{
		TTL:     3600,
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2025052901,
		Refresh: 3600,
		Retry:   1800,
		Expire:  604800,
		Minimum: 86400,
	}
	z := &zone.Zone{
		Origin: "example.com.",
		Records: map[string][]zone.Record{
			"example.com.": {
				{Type: "SOA", Name: "example.com.", RData: "ns1.example.com. admin.example.com. 2025052901 3600 1800 604800 86400"},
			},
			"www.example.com.": {
				{Type: "A", Name: "www.example.com.", TTL: 3600, RData: "192.0.2.1"},
			},
		},
		SOA: soa,
	}
	mgr.Load("example.com.", "")
	mgr.LoadZone(z, "")

	zs := NewZoneService(mgr)
	resp := zs.ListZones()

	if resp.Total != 1 {
		t.Errorf("Total = %d, want 1", resp.Total)
	}
	if len(resp.Zones) != 1 {
		t.Fatalf("len(Zones) = %d, want 1", len(resp.Zones))
	}
	if resp.Zones[0].Name != "example.com." {
		t.Errorf("Zones[0].Name = %q, want %q", resp.Zones[0].Name, "example.com.")
	}
	if resp.Zones[0].Serial != 2025052901 {
		t.Errorf("Zones[0].Serial = %d, want %d", resp.Zones[0].Serial, 2025052901)
	}
	if resp.Zones[0].Records != 2 {
		t.Errorf("Zones[0].Records = %d, want 2", resp.Zones[0].Records)
	}
}

func TestZoneService_GetZone_Found(t *testing.T) {
	mgr := zone.NewManager()
	soa := &zone.SOARecord{
		TTL:     3600,
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  42,
		Refresh: 3600,
		Retry:   1800,
		Expire:  604800,
		Minimum: 86400,
	}
	nsRec := zone.NSRecord{
		NSDName: "ns1.example.com.",
	}
	z := &zone.Zone{
		Origin: "example.com.",
		Records: map[string][]zone.Record{
			"example.com.": {
				{Type: "SOA", Name: "example.com.", RData: "ns1.example.com. admin.example.com. 42 3600 1800 604800 86400"},
			},
		},
		SOA: soa,
		NS:  []zone.NSRecord{nsRec},
	}
	mgr.Load("example.com.", "")
	mgr.LoadZone(z, "")

	zs := NewZoneService(mgr)
	resp, ok := zs.GetZone("example.com.")

	if !ok {
		t.Fatal("GetZone returned !ok")
	}
	if resp.Name != "example.com." {
		t.Errorf("Name = %q, want %q", resp.Name, "example.com.")
	}
	if resp.Serial != 42 {
		t.Errorf("Serial = %d, want 42", resp.Serial)
	}
	if resp.SOA == nil {
		t.Fatal("SOA = nil, want non-nil")
	}
	if resp.SOA.Serial != 42 {
		t.Errorf("SOA.Serial = %d, want 42", resp.SOA.Serial)
	}
	if len(resp.Nameservers) != 1 {
		t.Fatalf("len(Nameservers) = %d, want 1", len(resp.Nameservers))
	}
	if resp.Nameservers[0] != "ns1.example.com." {
		t.Errorf("Nameservers[0] = %q, want %q", resp.Nameservers[0], "ns1.example.com.")
	}
}

func TestZoneService_GetZone_NotFound(t *testing.T) {
	mgr := zone.NewManager()
	zs := NewZoneService(mgr)
	_, ok := zs.GetZone("nonexistent.example.")
	if ok {
		t.Error("GetZone for nonexistent zone: ok = true, want false")
	}
}

func TestZoneService_ZoneExists(t *testing.T) {
	mgr := zone.NewManager()
	z := &zone.Zone{Origin: "example.com."}
	mgr.Load("example.com.", "")
	mgr.LoadZone(z, "")

	zs := NewZoneService(mgr)

	if !zs.ZoneExists("example.com.") {
		t.Error("ZoneExists(example.com.) = false, want true")
	}
	if zs.ZoneExists("nonexistent.example.") {
		t.Error("ZoneExists(nonexistent.) = true, want false")
	}
}
