package storage

import (
	"errors"
	"strings"
	"testing"
)

// TestWAL_RejectsEntryLargerThanSegment verifies that an entry which cannot fit
// in any segment is rejected at Append time with ErrEntryTooLarge, rather than
// being written and then silently dropped by recovery (a false-durability /
// data-loss edge).
func TestWAL_RejectsEntryLargerThanSegment(t *testing.T) {
	dir := t.TempDir()
	wal, err := OpenWAL(dir, WALOptions{MaxSegmentSize: 4096})
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()

	// A normal small entry succeeds.
	if _, err := wal.Append(EntryTypePut, []byte("ok")); err != nil {
		t.Fatalf("small Append failed: %v", err)
	}

	// An entry larger than the segment must be rejected, not silently written.
	oversized := []byte(strings.Repeat("x", 8192))
	_, err = wal.Append(EntryTypePut, oversized)
	if !errors.Is(err, ErrEntryTooLarge) {
		t.Fatalf("Append(oversized) error = %v, want ErrEntryTooLarge", err)
	}
}
