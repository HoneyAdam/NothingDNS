package transfer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestKVJournalStore_NewKVJournalStore(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)
	if store == nil {
		t.Fatal("NewKVJournalStore returned nil")
	}
	if store.dataDir == "" {
		t.Error("dataDir is empty")
	}
	if store.maxJournalSize != 100 {
		t.Errorf("maxJournalSize = %d, want 100", store.maxJournalSize)
	}
	if store.hmacKey != nil {
		t.Error("hmacKey should be nil when not provided")
	}
}

func TestKVJournalStore_NewKVJournalStoreWithKey(t *testing.T) {
	tmpDir := t.TempDir()
	key := []byte("test-key-32-bytes-long-for-hmac!")
	store := NewKVJournalStore(tmpDir, key)
	if store == nil {
		t.Fatal("NewKVJournalStore returned nil")
	}
	if store.hmacKey == nil {
		t.Error("hmacKey should not be nil when provided")
	}
}

func TestKVJournalStore_SetMaxJournalSize(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)

	store.SetMaxJournalSize(50)
	if store.maxJournalSize != 50 {
		t.Errorf("maxJournalSize = %d, want 50", store.maxJournalSize)
	}

	store.SetMaxJournalSize(200)
	if store.maxJournalSize != 200 {
		t.Errorf("maxJournalSize = %d, want 200", store.maxJournalSize)
	}
}

func TestKVJournalStore_SaveAndLoadEntry(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)

	zoneName := "example.com."
	entry := &IXFRJournalEntry{
		Serial: 2024010101,
		Added: []zone.RecordChange{
			{Name: "test.example.com.", Type: protocol.TypeA, TTL: 300, RData: "192.0.2.1"},
		},
		Timestamp: time.Now(),
	}

	err := store.SaveEntry(zoneName, entry)
	if err != nil {
		t.Fatalf("SaveEntry failed: %v", err)
	}

	// Load and verify
	entries, err := store.LoadEntries(zoneName)
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("LoadEntries returned %d entries, want 1", len(entries))
	}

	if entries[0].Serial != entry.Serial {
		t.Errorf("Serial = %d, want %d", entries[0].Serial, entry.Serial)
	}
	if len(entries[0].Added) != 1 {
		t.Errorf("Added count = %d, want 1", len(entries[0].Added))
	}
	if entries[0].Added[0].Name != entry.Added[0].Name {
		t.Errorf("Added[0].Name = %q, want %q", entries[0].Added[0].Name, entry.Added[0].Name)
	}
}

func TestKVJournalStore_SaveAndLoadMultipleEntries(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)

	zoneName := "example.com."
	entries := []*IXFRJournalEntry{
		{Serial: 2024010101, Added: []zone.RecordChange{{Name: "a.example.com.", Type: protocol.TypeA}}, Timestamp: time.Now()},
		{Serial: 2024010102, Added: []zone.RecordChange{{Name: "b.example.com.", Type: protocol.TypeA}}, Timestamp: time.Now()},
		{Serial: 2024010103, Deleted: []zone.RecordChange{{Name: "c.example.com.", Type: protocol.TypeA}}, Timestamp: time.Now()},
	}

	for _, e := range entries {
		if err := store.SaveEntry(zoneName, e); err != nil {
			t.Fatalf("SaveEntry failed: %v", err)
		}
	}

	loaded, err := store.LoadEntries(zoneName)
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}

	if len(loaded) != len(entries) {
		t.Errorf("LoadEntries returned %d entries, want %d", len(loaded), len(entries))
	}

	// Verify ordering (should be sorted by serial)
	for i, e := range loaded {
		if e.Serial != entries[i].Serial {
			t.Errorf("entries[%d].Serial = %d, want %d", i, e.Serial, entries[i].Serial)
		}
	}
}

func TestKVJournalStore_LoadEntriesNonexistent(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)

	entries, err := store.LoadEntries("nonexistent.example.com.")
	if err != nil {
		t.Fatalf("LoadEntries failed unexpectedly: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("LoadEntries returned %d entries, want 0", len(entries))
	}
}

func TestKVJournalStore_Truncate(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)
	store.SetMaxJournalSize(3)

	zoneName := "example.com."
	for i := 0; i < 5; i++ {
		entry := &IXFRJournalEntry{
			Serial:    uint32(2024010100 + i),
			Added:     []zone.RecordChange{{Name: "test.example.com.", Type: protocol.TypeA}},
			Timestamp: time.Now(),
		}
		if err := store.SaveEntry(zoneName, entry); err != nil {
			t.Fatalf("SaveEntry failed: %v", err)
		}
	}

	// After 5 entries with maxJournalSize=3, should have 3 most recent
	entries, err := store.LoadEntries(zoneName)
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("LoadEntries returned %d entries, want 3", len(entries))
	}

	// LoadEntries sorts ascending, so entries should be: 2024010102, 2024010103, 2024010104
	if entries[0].Serial != 2024010102 {
		t.Errorf("entries[0].Serial = %d, want 2024010102", entries[0].Serial)
	}
	if entries[2].Serial != 2024010104 {
		t.Errorf("entries[2].Serial = %d, want 2024010104", entries[2].Serial)
	}
}

func TestKVJournalStore_SaveEntryWithHMAC(t *testing.T) {
	tmpDir := t.TempDir()
	key := []byte("test-key-32-bytes-long-for-hmac!")
	store := NewKVJournalStore(tmpDir, key)

	zoneName := "example.com."
	entry := &IXFRJournalEntry{
		Serial:    2024010101,
		Added:     []zone.RecordChange{{Name: "test.example.com.", Type: protocol.TypeA, TTL: 300}},
		Timestamp: time.Now(),
	}

	// Check zone dir path
	zoneDir := filepath.Join(tmpDir, "ixfr-journals", sanitizeFilename(zoneName))
	journalFile := filepath.Join(zoneDir, "2024010101.journal")
	t.Logf("zoneDir: %s", zoneDir)
	t.Logf("journalFile: %s", journalFile)

	// Check file doesn't exist before save
	if _, err := os.Stat(journalFile); err == nil {
		t.Error("Journal file should not exist before SaveEntry")
	}

	err := store.SaveEntry(zoneName, entry)
	if err != nil {
		t.Fatalf("SaveEntry failed: %v", err)
	}

	// Check file exists after save
	if _, err := os.Stat(journalFile); err != nil {
		t.Fatalf("Journal file should exist after SaveEntry: %v", err)
	}

	// Load with same key
	loaded, err := store.LoadEntries(zoneName)
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}

	t.Logf("LoadEntries returned %d entries", len(loaded))
	for i, e := range loaded {
		t.Logf("  [%d] Serial: %d", i, e.Serial)
	}

	if len(loaded) != 1 {
		t.Fatalf("LoadEntries returned %d entries, want 1", len(loaded))
	}

	if loaded[0].Serial != entry.Serial {
		t.Errorf("Serial = %d, want %d", loaded[0].Serial, entry.Serial)
	}
}

func TestKVJournalStore_InvalidHMACKey(t *testing.T) {
	tmpDir := t.TempDir()
	key := []byte("test-key-32-bytes-long-for-hmac!")
	store := NewKVJournalStore(tmpDir, key)

	zoneName := "example.com."
	entry := &IXFRJournalEntry{
		Serial:    2024010101,
		Added:     []zone.RecordChange{{Name: "test.example.com.", Type: protocol.TypeA}},
		Timestamp: time.Now(),
	}

	err := store.SaveEntry(zoneName, entry)
	if err != nil {
		t.Fatalf("SaveEntry failed: %v", err)
	}

	// Create store with different key - should fail to load
	store2 := NewKVJournalStore(tmpDir, []byte("different-key-32-bytes-long!!"))
	entries, err := store2.LoadEntries(zoneName)
	// The corrupted file should be removed, so we get 0 entries
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("LoadEntries returned %d entries, want 0 (corrupted)", len(entries))
	}
}

func TestKVJournalStore_IXFRJournalEntryJSON(t *testing.T) {
	entry := &IXFRJournalEntry{
		Serial: 2024010101,
		Added: []zone.RecordChange{
			{Name: "test.example.com.", Type: protocol.TypeA, TTL: 300, RData: "192.0.2.1"},
		},
		Deleted: []zone.RecordChange{
			{Name: "old.example.com.", Type: protocol.TypeA, TTL: 300, RData: "192.0.2.0"},
		},
		Timestamp: time.Now(),
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	var decoded IXFRJournalEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}

	if decoded.Serial != entry.Serial {
		t.Errorf("Serial = %d, want %d", decoded.Serial, entry.Serial)
	}
	if len(decoded.Added) != len(entry.Added) {
		t.Errorf("Added count = %d, want %d", len(decoded.Added), len(entry.Added))
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example_com"},
		{"example/com", "example_com"},
		{"C:\\Windows\\System32", "C__Windows_System32"},
		{"null\x00byte", "null_byte"},
		{"example.com.", "example_com_"},
		{"example..com.", "example__com_"},
	}

	for _, tc := range tests {
		result := sanitizeFilename(tc.input)
		if result != tc.expected {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestKVJournalStore_MultipleZones(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)

	zones := []string{"example.com.", "example.org.", "example.net."}

	for _, zoneName := range zones {
		entry := &IXFRJournalEntry{
			Serial:    2024010101,
			Added:     []zone.RecordChange{{Name: "test." + zoneName, Type: protocol.TypeA}},
			Timestamp: time.Now(),
		}
		if err := store.SaveEntry(zoneName, entry); err != nil {
			t.Fatalf("SaveEntry failed for zone %s: %v", zoneName, err)
		}
	}

	// Verify each zone has its own entry
	for _, zoneName := range zones {
		entries, err := store.LoadEntries(zoneName)
		if err != nil {
			t.Fatalf("LoadEntries failed for zone %s: %v", zoneName, err)
		}
		if len(entries) != 1 {
			t.Errorf("Zone %s: got %d entries, want 1", zoneName, len(entries))
		}
	}
}

func TestKVJournalStore_EntryWithAllFields(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)

	zoneName := "example.com."
	ts := time.Now()
	entry := &IXFRJournalEntry{
		Serial: 2024010101,
		Added: []zone.RecordChange{
			{Name: "fulltest.example.com.", Type: protocol.TypeMX, TTL: 600, RData: "10 mail.example.com."},
		},
		Deleted: []zone.RecordChange{
			{Name: "old.example.com.", Type: protocol.TypeA, TTL: 300, RData: "192.0.2.0"},
		},
		Timestamp: ts,
	}

	err := store.SaveEntry(zoneName, entry)
	if err != nil {
		t.Fatalf("SaveEntry failed: %v", err)
	}

	loaded, err := store.LoadEntries(zoneName)
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}

	if len(loaded) != 1 {
		t.Fatalf("LoadEntries returned %d entries, want 1", len(loaded))
	}

	if len(loaded[0].Added) != 1 {
		t.Errorf("Added count = %d, want 1", len(loaded[0].Added))
	}
	if loaded[0].Added[0].Type != protocol.TypeMX {
		t.Errorf("Added[0].Type = %d, want %d", loaded[0].Added[0].Type, protocol.TypeMX)
	}
	if len(loaded[0].Deleted) != 1 {
		t.Errorf("Deleted count = %d, want 1", len(loaded[0].Deleted))
	}
}

func TestKVJournalStore_ConcurrentSave(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)
	store.SetMaxJournalSize(100)

	zoneName := "example.com."

	// Concurrently save entries
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(idx int) {
			entry := &IXFRJournalEntry{
				Serial:    uint32(2024010100 + idx),
				Added:     []zone.RecordChange{{Name: "test.example.com.", Type: protocol.TypeA}},
				Timestamp: time.Now(),
			}
			store.SaveEntry(zoneName, entry)
			done <- struct{}{}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all entries were saved
	entries, err := store.LoadEntries(zoneName)
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}

	if len(entries) != 10 {
		t.Errorf("LoadEntries returned %d entries, want 10", len(entries))
	}
}

func TestKVJournalStore_CorruptedJournalFile(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)

	zoneName := "example.com."

	// Manually create a corrupted journal file in the correct sanitized directory
	zoneDir := filepath.Join(tmpDir, "ixfr-journals", "example_com_")
	os.MkdirAll(zoneDir, 0755)
	corruptedFile := filepath.Join(zoneDir, "2024010101.journal")
	os.WriteFile(corruptedFile, []byte("not valid json"), 0644)

	// Load should skip the corrupted file
	entries, err := store.LoadEntries(zoneName)
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("LoadEntries returned %d entries, want 0", len(entries))
	}

	// Corrupted file should have been removed
	if _, err := os.Stat(corruptedFile); err == nil {
		t.Error("Corrupted file should have been removed")
	}
}

func TestKVJournalStore_DeleteZoneClearsJournals(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)

	// Create entries for two zones
	store.SaveEntry("zone1.com.", &IXFRJournalEntry{Serial: 1, Added: []zone.RecordChange{{Name: "a.zone1.com.", Type: protocol.TypeA}}, Timestamp: time.Now()})
	store.SaveEntry("zone2.com.", &IXFRJournalEntry{Serial: 1, Added: []zone.RecordChange{{Name: "a.zone2.com.", Type: protocol.TypeA}}, Timestamp: time.Now()})

	// Verify both exist
	entries1, _ := store.LoadEntries("zone1.com.")
	entries2, _ := store.LoadEntries("zone2.com.")

	if len(entries1) != 1 || len(entries2) != 1 {
		t.Fatal("Setup failed")
	}

	// Verify zone directories exist (sanitizeFilename converts '.' to '_' and trailing '.' to '_')
	zone1Dir := filepath.Join(tmpDir, "ixfr-journals", "zone1_com_")
	zone2Dir := filepath.Join(tmpDir, "ixfr-journals", "zone2_com_")

	if _, err := os.Stat(zone1Dir); err != nil {
		t.Errorf("zone1 dir should exist: %v", err)
	}
	if _, err := os.Stat(zone2Dir); err != nil {
		t.Errorf("zone2 dir should exist: %v", err)
	}
}
