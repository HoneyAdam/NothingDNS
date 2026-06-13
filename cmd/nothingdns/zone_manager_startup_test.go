package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/storage"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestNewZoneManagerLoadsZoneDirFiles(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "persisted.example.zone")
	zoneContent := `$ORIGIN persisted.example.
$TTL 3600
@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400
@ 3600 IN NS ns1
ns1 3600 IN A 192.0.2.1
www 3600 IN A 192.0.2.10
`
	if err := os.WriteFile(zoneFile, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("write zone file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "ignore.txt"), []byte(zoneContent), 0644); err != nil {
		t.Fatalf("write ignored file: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.ZoneDir = tmpDir
	cfg.Zones = nil

	mgr, err := NewZoneManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("NewZoneManager: %v", err)
	}

	if _, ok := mgr.Zones()["persisted.example."]; !ok {
		t.Fatalf("expected persisted.example. loaded from zone_dir")
	}
	if len(mgr.Zones()) != 1 {
		t.Fatalf("loaded zones = %d, want 1", len(mgr.Zones()))
	}
	if got := mgr.ZoneFiles()["persisted.example."]; got != zoneFile {
		t.Fatalf("zone file = %q, want %q", got, zoneFile)
	}
	if mgr.KVPersistence() == nil {
		t.Fatal("expected KV persistence")
	}
	// File-backed zones must NOT be mirrored into the KV store: the zone
	// file is their durable source, and a KV copy would resurrect the zone
	// at the next boot even after it is removed from the config/zone_dir.
	if _, found, err := mgr.KVPersistence().LoadFromKV("persisted.example."); err != nil {
		t.Fatalf("LoadFromKV: %v", err)
	} else if found {
		t.Fatal("zone_dir zone must not be seeded into KV (decommission via config removal would be impossible)")
	}
}

func TestNewZoneManagerLoadsKVOnlyZones(t *testing.T) {
	tmpDir := t.TempDir()

	seedManager := zone.NewManager()
	soa := &zone.SOARecord{
		MName: "ns1.kvonly.example.", RName: "hostmaster.kvonly.example.",
		Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400,
	}
	if err := seedManager.CreateZone("kvonly.example.", 3600, soa, []zone.NSRecord{{NSDName: "ns1.kvonly.example."}}); err != nil {
		t.Fatalf("CreateZone seed: %v", err)
	}

	kv, err := storage.OpenKVStore(tmpDir)
	if err != nil {
		t.Fatalf("OpenKVStore: %v", err)
	}
	kvp := zone.NewKVPersistence(seedManager, kv)
	kvp.Enable()
	if err := kvp.PersistAll(); err != nil {
		t.Fatalf("PersistAll seed: %v", err)
	}
	if err := kv.Close(); err != nil {
		t.Fatalf("Close KV seed: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.ZoneDir = tmpDir
	cfg.Zones = nil

	mgr, err := NewZoneManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("NewZoneManager: %v", err)
	}

	if _, ok := mgr.Zones()["kvonly.example."]; !ok {
		t.Fatalf("expected kvonly.example. loaded from KV")
	}
	if got := mgr.ZoneFiles()["kvonly.example."]; got != "" {
		t.Fatalf("KV-only zone file = %q, want empty", got)
	}
}

func TestNewZoneManagerUsesStorageDataDirForPersistentDB(t *testing.T) {
	zoneDir := t.TempDir()
	dbDir := t.TempDir()
	zoneFile := filepath.Join(zoneDir, "dbdir.example.zone")
	zoneContent := `$ORIGIN dbdir.example.
$TTL 3600
@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400
@ 3600 IN NS ns1
ns1 3600 IN A 192.0.2.1
`
	if err := os.WriteFile(zoneFile, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("write zone file: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.ZoneDir = zoneDir
	cfg.Storage.DataDir = dbDir
	cfg.Zones = nil

	mgr, err := NewZoneManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("NewZoneManager: %v", err)
	}
	// File-backed zones are not mirrored into the KV store (see
	// TestNewZoneManagerLoadsZoneDirFiles); the DB must still be created
	// in storage.data_dir and remain usable for API-created zones.
	if _, found, err := mgr.KVPersistence().LoadFromKV("dbdir.example."); err != nil {
		t.Fatalf("LoadFromKV: %v", err)
	} else if found {
		t.Fatal("file-backed zone must not be stored in persistent DB")
	}
	if err := mgr.KVPersistence().PersistZone("dbdir.example."); err != nil {
		t.Fatalf("PersistZone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dbDir, storage.DataFile)); err != nil {
		t.Fatalf("expected persistent DB in storage.data_dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(zoneDir, storage.DataFile)); !os.IsNotExist(err) {
		t.Fatalf("zone_dir should not contain persistent DB when storage.data_dir is set, stat err = %v", err)
	}
}

func TestNewZoneManagerExplicitStorageDataDirOpenError(t *testing.T) {
	tmpDir := t.TempDir()
	badDataDir := filepath.Join(tmpDir, "data-dir-file")
	if err := os.WriteFile(badDataDir, []byte("not a directory"), 0644); err != nil {
		t.Fatalf("write bad storage data dir: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Storage.DataDir = badDataDir
	cfg.Zones = nil

	mgr, err := NewZoneManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err == nil {
		t.Fatal("expected explicit storage.data_dir open failure")
	}
	if mgr != nil {
		t.Fatal("expected nil manager on explicit storage.data_dir open failure")
	}
	if !strings.Contains(err.Error(), "initializing persistent zone database") {
		t.Fatalf("error = %q, want persistent zone database context", err)
	}
}

// TestNewZoneManagerDuplicateOriginFirstWins verifies that a stray zone_dir
// file sharing the $ORIGIN of an already-loaded zone (e.g. a backup copy)
// does not silently replace it: discovery order is configured zones first,
// then zone_dir alphabetically, and the first load wins.
func TestNewZoneManagerDuplicateOriginFirstWins(t *testing.T) {
	tmpDir := t.TempDir()
	makeZone := func(name, ip string) string {
		path := filepath.Join(tmpDir, name)
		content := `$ORIGIN dup.example.
$TTL 3600
@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400
@ 3600 IN NS ns1
ns1 3600 IN A ` + ip + "\n"
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("write zone file %s: %v", name, err)
		}
		return path
	}
	primary := makeZone("aaa-live.zone", "192.0.2.1")
	makeZone("zzz-backup.zone", "203.0.113.99")

	cfg := config.DefaultConfig()
	cfg.ZoneDir = tmpDir
	cfg.Zones = []string{primary}

	mgr, err := NewZoneManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("NewZoneManager: %v", err)
	}

	if got := mgr.ZoneFiles()["dup.example."]; got != primary {
		t.Fatalf("zone file = %q, want first-loaded %q (duplicate origin must not clobber)", got, primary)
	}
	z := mgr.Zones()["dup.example."]
	if z == nil {
		t.Fatal("expected dup.example. zone")
	}
	for _, recs := range z.Records {
		for _, rec := range recs {
			if rec.Type == "A" && rec.RData == "203.0.113.99" {
				t.Fatal("backup zone file content leaked into the live zone")
			}
		}
	}
}
