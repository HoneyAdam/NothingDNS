package main

// Tests for the ZoneProvider plumbing — concrete providers (static,
// manager, kv, radix) and the MultiZoneProvider fan-out.

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/zone"
)

func makeZone(origin string) *zone.Zone {
	return &zone.Zone{Origin: origin}
}

func TestStaticZoneProvider(t *testing.T) {
	zones := map[string]*zone.Zone{
		"example.com.":     makeZone("example.com."),
		"sub.example.com.": makeZone("sub.example.com."),
	}
	p := &staticZoneProvider{zones: zones}

	// ListZones returns all entries.
	list := p.ListZones()
	if len(list) != 2 {
		t.Errorf("ListZones len = %d, want 2", len(list))
	}

	// GetZone hit + miss.
	if z, ok := p.GetZone("example.com."); !ok || z.Origin != "example.com." {
		t.Errorf("GetZone(example.com.) = %v (%v)", z, ok)
	}
	if z, ok := p.GetZone("missing.com."); ok || z != nil {
		t.Errorf("GetZone(missing) should not match, got %v", z)
	}

	// FindZones returns both matching zones for a subdomain.
	matches := p.FindZones("api.sub.example.com.")
	if len(matches) < 1 {
		t.Errorf("FindZones returned %d matches, want ≥1", len(matches))
	}
}

func TestManagerZoneProvider(t *testing.T) {
	mgr := zone.NewManager()
	mgr.LoadZone(makeZone("example.com."), "")
	mgr.LoadZone(makeZone("other.com."), "")

	p := &managerZoneProvider{manager: mgr}

	if list := p.ListZones(); len(list) != 2 {
		t.Errorf("ListZones len = %d, want 2", len(list))
	}
	if _, ok := p.GetZone("example.com."); !ok {
		t.Error("GetZone(example.com.) should hit")
	}
	if _, ok := p.GetZone("missing.com."); ok {
		t.Error("GetZone(missing) should miss")
	}
	if got := p.FindZones("host.example.com."); len(got) == 0 {
		t.Error("FindZones(host.example.com.) should match example.com.")
	}
}

func TestRadixZoneProvider_NilTree(t *testing.T) {
	p := &radixZoneProvider{tree: nil}

	if got := p.FindZones("anything."); got != nil {
		t.Errorf("nil-tree FindZones should return nil, got %v", got)
	}
	if z, ok := p.GetZone("anything."); ok || z != nil {
		t.Errorf("nil-tree GetZone should miss, got %v", z)
	}
	if list := p.ListZones(); list != nil {
		t.Errorf("ListZones should return nil (radix has no List), got %v", list)
	}
}

func TestRadixZoneProvider_NonNilTree(t *testing.T) {
	tree := zone.NewRadixTree()
	tree.Insert("example.com.", makeZone("example.com."))
	p := &radixZoneProvider{tree: tree}

	matches := p.FindZones("host.example.com.")
	if len(matches) != 1 || matches[0].Origin != "example.com." {
		t.Errorf("FindZones = %+v, want one example.com. match", matches)
	}
	if z, ok := p.GetZone("example.com."); !ok || z.Origin != "example.com." {
		t.Errorf("GetZone(example.com.) = %v %v", z, ok)
	}
	// Sub-origin probe must not be reported as an exact match.
	if _, ok := p.GetZone("host.example.com."); ok {
		t.Error("GetZone(host.example.com.) should not exact-match the parent zone")
	}
}

func TestMultiZoneProvider_FanOut(t *testing.T) {
	staticZones := map[string]*zone.Zone{
		"static.com.": makeZone("static.com."),
	}
	mgr := zone.NewManager()
	mgr.LoadZone(makeZone("managed.com."), "")

	mp := NewMultiZoneProvider(staticZones, mgr, nil, nil)

	// ListZones merges across providers.
	list := mp.ListZones()
	if _, ok := list["static.com."]; !ok {
		t.Error("ListZones missing static.com.")
	}
	if _, ok := list["managed.com."]; !ok {
		t.Error("ListZones missing managed.com.")
	}

	// GetZone walks providers in order; static first.
	if z, ok := mp.GetZone("static.com."); !ok || z.Origin != "static.com." {
		t.Errorf("GetZone(static.com.) = %v %v", z, ok)
	}
	if z, ok := mp.GetZone("managed.com."); !ok || z.Origin != "managed.com." {
		t.Errorf("GetZone(managed.com.) = %v %v", z, ok)
	}

	// FindZones returns matches from any provider that owns the qname.
	if got := mp.FindZones("api.static.com."); len(got) == 0 {
		t.Error("FindZones(api.static.com.) should match static.com.")
	}
	if got := mp.FindZones("api.managed.com."); len(got) == 0 {
		t.Error("FindZones(api.managed.com.) should match managed.com.")
	}
}

func TestMultiZoneProvider_EmptyProviders(t *testing.T) {
	mp := NewMultiZoneProvider(nil, nil, nil, nil)
	if list := mp.ListZones(); len(list) != 0 {
		t.Errorf("empty providers ListZones len = %d, want 0", len(list))
	}
	if _, ok := mp.GetZone("anything."); ok {
		t.Error("empty providers GetZone should miss")
	}
	if got := mp.FindZones("anything."); got != nil {
		t.Errorf("empty providers FindZones = %v, want nil", got)
	}
}
