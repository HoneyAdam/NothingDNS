package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWALCreate(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	stats := wal.Stats()
	if stats.SegmentCount != 1 {
		t.Errorf("Expected 1 segment, got %d", stats.SegmentCount)
	}
}

func TestWALAppend(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	// Append entries
	for i := 0; i < 10; i++ {
		_, err := wal.Append(EntryTypePut, []byte("test_data"))
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	// Sync
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
}

func TestWALReadAll(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	// Append entries
	testData := [][]byte{
		[]byte("data1"),
		[]byte("data2"),
		[]byte("data3"),
	}

	for _, data := range testData {
		_, err := wal.Append(EntryTypePut, data)
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	// Sync and read
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	entries, err := wal.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(entries) != len(testData) {
		t.Errorf("Expected %d entries, got %d", len(testData), len(entries))
	}

	for i, entry := range entries {
		if string(entry.Data) != string(testData[i]) {
			t.Errorf("Entry %d: expected %s, got %s", i, testData[i], entry.Data)
		}
	}

	wal.Close()
}

func TestWALBatchAppend(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	entries := []WALEntry{
		{Type: EntryTypePut, Data: []byte("batch1")},
		{Type: EntryTypePut, Data: []byte("batch2")},
		{Type: EntryTypePut, Data: []byte("batch3")},
	}

	if err := wal.AppendBatch(entries); err != nil {
		t.Fatalf("AppendBatch failed: %v", err)
	}
}

func TestWALTruncate(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	// Create multiple segments by appending large data
	for i := 0; i < 100; i++ {
		data := make([]byte, 1024) // 1KB each
		_, err := wal.Append(EntryTypePut, data)
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	stats := wal.Stats()
	initialSegments := stats.SegmentCount

	// Truncate
	if err := wal.Truncate(0); err != nil {
		t.Fatalf("Truncate failed: %v", err)
	}

	stats = wal.Stats()
	if stats.SegmentCount > initialSegments {
		t.Errorf("Segment count should not increase after truncate")
	}
}

func TestWALRecovery(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()

	// Write data
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	testData := []byte("recovery_test")
	_, err = wal.Append(EntryTypePut, testData)
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	wal.Close()

	// Reopen and read
	wal2, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer wal2.Close()

	entries, err := wal2.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(entries))
	}

	if string(entries[0].Data) != string(testData) {
		t.Errorf("Expected %s, got %s", testData, entries[0].Data)
	}
}

func TestWALCompact(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	// Write some data
	for i := 0; i < 10; i++ {
		_, err := wal.Append(EntryTypePut, []byte("data"))
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	// Compact
	checkpoint := []byte("checkpoint_data")
	if err := wal.Compact(checkpoint); err != nil {
		t.Fatalf("Compact failed: %v", err)
	}
}

func TestWALReader(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	// Write data
	for i := 0; i < 5; i++ {
		_, err := wal.Append(EntryTypePut, []byte("reader_test"))
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	wal.Sync()

	// Read with ReadAll
	entries, err := wal.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(entries) != 5 {
		t.Errorf("Expected 5 entries, got %d", len(entries))
	}

	wal.Close()
}

// TestWALReader_MultiEntry guards against a regression where
// WALReader.Next() used bytes.Buffer.Truncate to "consume" a
// decoded payload — Truncate keeps the front and discards the
// tail, so a stream containing more than one entry returned
// garbage from the second call onward. Next() now uses
// bytes.Buffer.Next() to advance past the payload bytes.
func TestWALReader_MultiEntry(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	const n = 5
	payloads := [][]byte{
		[]byte("alpha"),
		[]byte("beta-payload"),
		[]byte("gamma"),
		[]byte("delta-payload-data"),
		[]byte("epsilon"),
	}
	for i := 0; i < n; i++ {
		if _, err := wal.Append(EntryTypePut, payloads[i]); err != nil {
			t.Fatalf("Append %d failed: %v", i, err)
		}
	}
	wal.Sync()

	reader := wal.NewReader()
	defer reader.Close()
	defer wal.Close()

	for i := 0; i < n; i++ {
		entry, err := reader.Next()
		if err != nil {
			t.Fatalf("Next %d returned error: %v", i, err)
		}
		if entry == nil {
			t.Fatalf("Next %d returned nil entry", i)
		}
		if string(entry.Data) != string(payloads[i]) {
			t.Errorf("entry %d: expected payload %q, got %q", i, payloads[i], entry.Data)
		}
	}
}

func TestWALEntryEncoding(t *testing.T) {
	wal := &WAL{}

	entry := &WALEntry{
		Type:      EntryTypePut,
		Data:      []byte("test_data_for_encoding"),
		Timestamp: time.Now().UnixNano(),
	}

	encoded, err := wal.encodeEntry(entry)
	if err != nil {
		t.Fatalf("encodeEntry failed: %v", err)
	}

	decoded, err := wal.decodeEntry(encoded)
	if err != nil {
		t.Fatalf("decodeEntry failed: %v", err)
	}

	if decoded.Type != entry.Type {
		t.Errorf("Type mismatch: expected %d, got %d", entry.Type, decoded.Type)
	}

	if string(decoded.Data) != string(entry.Data) {
		t.Errorf("Data mismatch: expected %s, got %s", entry.Data, decoded.Data)
	}
}

// TestWALRecovery_PartialTrailingEntry simulates a power-loss crash
// that left a torn entry at the end of the active segment: the
// first valid entry is intact, then the file ends mid-header (or
// mid-body) of what would have been the next entry. Recovery should
// return the valid entries it can read and stop cleanly, rather
// than failing the whole segment with "read header at N: unexpected
// EOF" — which is what the pre-fix code did.
func TestWALRecovery_PartialTrailingEntry(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if _, err := wal.Append(EntryTypePut, []byte("alpha")); err != nil {
		t.Fatalf("Append alpha: %v", err)
	}
	if _, err := wal.Append(EntryTypePut, []byte("beta")); err != nil {
		t.Fatalf("Append beta: %v", err)
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	wal.Close()

	// Find the active segment file and truncate the last few bytes
	// to simulate a torn write. Any segment file in the dir works.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var segPath string
	for _, e := range entries {
		if !e.IsDir() {
			segPath = filepath.Join(dir, e.Name())
		}
	}
	if segPath == "" {
		t.Fatal("no segment file found")
	}
	info, err := os.Stat(segPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Append 3 garbage bytes (less than a header) to mimic a torn write.
	f, err := os.OpenFile(segPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("open append: %v", err)
	}
	if _, err := f.Write([]byte{0x01, 0x02, 0x03}); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	f.Close()
	if newInfo, _ := os.Stat(segPath); newInfo.Size() != info.Size()+3 {
		t.Fatalf("size mismatch: expected +3, got %d", newInfo.Size()-info.Size())
	}

	// Reopen and ReadAll should succeed and return both valid entries.
	wal2, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	defer wal2.Close()
	got, err := wal2.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll on partial-tail segment: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries surviving torn trailer, got %d", len(got))
	}
	if string(got[0].Data) != "alpha" || string(got[1].Data) != "beta" {
		t.Errorf("entry data mismatch: %q, %q", got[0].Data, got[1].Data)
	}
}

// TestWALRecovery_AppendAfterTornTail verifies that after a torn write
// leaves garbage at the segment tail, the next OpenWAL → Append → close
// → re-Open cycle still surfaces the post-crash entries. The previous
// fix made readSegment stop *cleanly* at the torn bytes, but OpenWAL
// continued to use the file's raw size as the active offset and
// appended past the garbage. Recovery then re-stopped at the same
// torn bytes and never reached the new entries.
func TestWALRecovery_AppendAfterTornTail(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWALOptions()

	// Write entry, fsync, close.
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if _, err := wal.Append(EntryTypePut, []byte("pre-crash")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	wal.Sync()
	wal.Close()

	// Simulate torn tail.
	entries, _ := os.ReadDir(dir)
	var segPath string
	for _, e := range entries {
		segPath = filepath.Join(dir, e.Name())
	}
	f, _ := os.OpenFile(segPath, os.O_WRONLY|os.O_APPEND, 0)
	_, _ = f.Write([]byte{0xAA, 0xBB, 0xCC})
	f.Close()

	// Reopen, Append a recovery entry, close.
	wal2, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	if _, err := wal2.Append(EntryTypePut, []byte("post-crash")); err != nil {
		t.Fatalf("Append after torn tail: %v", err)
	}
	wal2.Sync()
	wal2.Close()

	// Re-open and ReadAll. Both entries must come back.
	wal3, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("Final reopen: %v", err)
	}
	defer wal3.Close()
	got, err := wal3.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries post-recovery, got %d", len(got))
	}
	if string(got[0].Data) != "pre-crash" || string(got[1].Data) != "post-crash" {
		t.Errorf("entry data: pre=%q post=%q", got[0].Data, got[1].Data)
	}
}

func TestWALCorruptedEntry(t *testing.T) {
	wal := &WAL{}

	// Create corrupted entry (bad checksum)
	corrupted := make([]byte, WALHeaderSize+10)
	corrupted[4] = EntryTypePut
	// Wrong checksum
	corrupted[0] = 0xFF
	corrupted[1] = 0xFF
	corrupted[2] = 0xFF
	corrupted[3] = 0xFF
	// Length
	corrupted[5] = 0
	corrupted[6] = 0
	corrupted[7] = 0
	corrupted[8] = 10

	_, err := wal.decodeEntry(corrupted)
	if err != ErrInvalidChecksum {
		t.Errorf("Expected ErrInvalidChecksum, got %v", err)
	}
}

func TestWALAppendReportsRollbackFailure(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	if err := wal.active.file.Close(); err != nil {
		t.Fatalf("close active file: %v", err)
	}

	_, err = wal.Append(EntryTypePut, []byte("test_data"))
	if err == nil {
		t.Fatal("Append with closed active file should fail")
	}
	if !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("Append error should include rollback failure, got: %v", err)
	}
}

func TestWALMultipleSegments(t *testing.T) {
	dir := t.TempDir()

	// Use small max segment size to force multiple segments
	opts := WALOptions{
		MaxSegmentSize:  1024, // 1KB
		SyncInterval:    100 * time.Millisecond,
		PreallocateSize: 0,
	}

	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	// Write enough data to create multiple segments
	for i := 0; i < 50; i++ {
		data := make([]byte, 100)
		_, err := wal.Append(EntryTypePut, data)
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	stats := wal.Stats()
	if stats.SegmentCount < 2 {
		t.Errorf("Expected multiple segments, got %d", stats.SegmentCount)
	}
}

func TestWALFileExists(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	wal.Close()

	// Check that WAL files exist
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}

	found := false
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".log" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to find .log files in WAL directory")
	}
}
