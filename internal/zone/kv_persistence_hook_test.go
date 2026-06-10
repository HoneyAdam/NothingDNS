package zone

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/storage"
)

func newHookTestKVP(t *testing.T) (*Manager, *KVPersistence) {
	t.Helper()
	m := NewManager()
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping KV test: %v", err)
	}
	t.Cleanup(func() { kv.Close() })

	kvp := NewKVPersistence(m, kv)
	kvp.Enable()
	return m, kvp
}

// TestMutationHook_ManagerPathPersistsToKV proves that mutations made
// directly through the zone.Manager (the path MCP tools and Raft apply use —
// no explicit persistZoneToKV calls anywhere) are durable in the KV store.
func TestMutationHook_ManagerPathPersistsToKV(t *testing.T) {
	m, kvp := newHookTestKVP(t)

	soa := &SOARecord{
		MName: "ns1.hook.example.", RName: "hostmaster.hook.example.",
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}
	if err := m.CreateZone("hook.example.", 3600, soa, []NSRecord{{NSDName: "ns1.hook.example."}}); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
	if _, found, err := kvp.LoadFromKV("hook.example."); err != nil {
		t.Fatalf("LoadFromKV after CreateZone: %v", err)
	} else if !found {
		t.Fatal("zone created via Manager.CreateZone not persisted to KV")
	}

	if err := m.AddRecord("hook.example.", Record{Name: "www", Type: "A", TTL: 300, RData: "192.0.2.1"}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	z, found, err := kvp.LoadFromKV("hook.example.")
	if err != nil || !found {
		t.Fatalf("LoadFromKV after AddRecord: found=%v err=%v", found, err)
	}
	recs := z.Records["www.hook.example."]
	if len(recs) != 1 || recs[0].RData != "192.0.2.1" {
		t.Fatalf("KV records after AddRecord = %#v, want one A 192.0.2.1", recs)
	}

	if err := m.UpdateRecord("hook.example.", "www", "A", "192.0.2.1",
		Record{Name: "www", Type: "A", TTL: 300, RData: "192.0.2.2"}); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}
	z, found, err = kvp.LoadFromKV("hook.example.")
	if err != nil || !found {
		t.Fatalf("LoadFromKV after UpdateRecord: found=%v err=%v", found, err)
	}
	recs = z.Records["www.hook.example."]
	if len(recs) != 1 || recs[0].RData != "192.0.2.2" {
		t.Fatalf("KV records after UpdateRecord = %#v, want one A 192.0.2.2", recs)
	}

	if err := m.DeleteRecord("hook.example.", "www", "A"); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
	z, found, err = kvp.LoadFromKV("hook.example.")
	if err != nil || !found {
		t.Fatalf("LoadFromKV after DeleteRecord: found=%v err=%v", found, err)
	}
	if recs := z.Records["www.hook.example."]; len(recs) != 0 {
		t.Fatalf("KV records after DeleteRecord = %#v, want none", recs)
	}

	if err := m.DeleteZone("hook.example."); err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}
	if _, found, err := kvp.LoadFromKV("hook.example."); err != nil {
		t.Fatalf("LoadFromKV after DeleteZone: %v", err)
	} else if found {
		t.Fatal("zone deleted via Manager.DeleteZone still present in KV")
	}
}

// TestMutationHook_LoadZoneDoesNotPersist verifies that loading a file-backed
// (config) zone does NOT push it into the KV store: KV durability is reserved
// for API-created zones, otherwise config zones would resurrect from KV after
// being removed from the config.
func TestMutationHook_LoadZoneDoesNotPersist(t *testing.T) {
	m, kvp := newHookTestKVP(t)

	z := &Zone{
		Origin:     "configzone.example.",
		DefaultTTL: 3600,
		SOA: &SOARecord{
			MName: "ns1.configzone.example.", RName: "hostmaster.configzone.example.", Serial: 1,
		},
		Records: map[string][]Record{},
	}
	m.LoadZone(z, "/tmp/configzone.example.zone")

	if _, found, err := kvp.LoadFromKV("configzone.example."); err != nil {
		t.Fatalf("LoadFromKV: %v", err)
	} else if found {
		t.Fatal("LoadZone must not persist file-backed zones to KV")
	}

	zones, err := kvp.ListKVZones()
	if err != nil {
		t.Fatalf("ListKVZones: %v", err)
	}
	if len(zones) != 0 {
		t.Fatalf("KV store should be empty after LoadZone, got %v", zones)
	}
}

// TestNotifyMutated_DirectZoneMutationPersists covers the DDNS-style path:
// the *Zone is mutated directly (bypassing the manager's mutation methods),
// then Manager.NotifyMutated is called to fire the hook.
func TestNotifyMutated_DirectZoneMutationPersists(t *testing.T) {
	m, kvp := newHookTestKVP(t)

	soa := &SOARecord{
		MName: "ns1.ddns.example.", RName: "hostmaster.ddns.example.",
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}
	if err := m.CreateZone("ddns.example.", 3600, soa, []NSRecord{{NSDName: "ns1.ddns.example."}}); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}

	// Mutate the zone directly, the way transfer.ApplyUpdate does.
	z, ok := m.Get("ddns.example.")
	if !ok {
		t.Fatal("zone not found")
	}
	z.Lock()
	z.Records["host.ddns.example."] = append(z.Records["host.ddns.example."],
		Record{Name: "host.ddns.example.", Type: "A", Class: "IN", TTL: 60, RData: "192.0.2.10"})
	z.Unlock()

	m.NotifyMutated("ddns.example.")

	stored, found, err := kvp.LoadFromKV("ddns.example.")
	if err != nil || !found {
		t.Fatalf("LoadFromKV after NotifyMutated: found=%v err=%v", found, err)
	}
	recs := stored.Records["host.ddns.example."]
	if len(recs) != 1 || recs[0].RData != "192.0.2.10" {
		t.Fatalf("KV records after NotifyMutated = %#v, want one A 192.0.2.10", recs)
	}
}
