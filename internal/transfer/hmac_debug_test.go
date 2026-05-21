package transfer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestKVJournalStore_SaveAndLoadWithHMACDebug(t *testing.T) {
	tmpDir := t.TempDir()
	key := []byte("test-key-32-bytes-long-for-hmac!")
	store := NewKVJournalStore(tmpDir, key)

	zoneName := "example.com."
	entry := &IXFRJournalEntry{
		Serial:    2024010101,
		Added:     []zone.RecordChange{{Name: "test.example.com.", Type: protocol.TypeA, TTL: 300}},
		Timestamp: time.Now(),
	}

	err := store.SaveEntry(zoneName, entry)
	if err != nil {
		t.Fatalf("SaveEntry failed: %v", err)
	}

	// Check if file exists after SaveEntry
	zoneDir := store.zoneDir(zoneName)
	journalFile := filepath.Join(zoneDir, "2024010101.journal")
	if _, err := os.Stat(journalFile); err != nil {
		t.Fatalf("File does not exist after SaveEntry: %v", err)
	}
	t.Logf("File exists after SaveEntry")

	entries, err := store.LoadEntries(zoneName)
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}
	t.Logf("Got %d entries", len(entries))

	// Check if file exists after LoadEntries
	if _, err := os.Stat(journalFile); err != nil {
		t.Logf("File does NOT exist after LoadEntries: %v", err)
	} else {
		t.Logf("File still exists after LoadEntries")
	}
}