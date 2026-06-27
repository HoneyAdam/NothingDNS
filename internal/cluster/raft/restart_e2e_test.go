package raft

// Restart / crash-recovery test: a node takes a snapshot (which compacts the
// WAL), shuts down, and a new instance over the SAME data directory boots from
// the snapshot — reconstructing state without replaying the (now-compacted)
// log prefix.

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

func TestSnapshot_BootFromSnapshotAfterRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("restart/boot-from-snapshot test skipped in -short mode")
	}

	dir := t.TempDir()
	const recordKey = "example.com.|www|A"

	// --- First incarnation: apply a record, snapshot, compact, stop. ---
	store1 := newTestZoneStore()
	ci1, err := NewClusterIntegration("n1", nil, nil, freeTCPAddr(t), dir, "", "", nil, util.DefaultLogger())
	if err != nil {
		t.Fatalf("ci1: %v", err)
	}
	ci1.SetApplyHook(func(c ZoneCommand) { store1.apply(c) })
	ci1.SetSnapshotFns(store1.snapshot, store1.restore)
	if err := ci1.Start(); err != nil {
		t.Fatalf("start ci1: %v", err)
	}

	// Single node elects itself.
	dl := time.Now().Add(5 * time.Second)
	for !ci1.IsLeader() && time.Now().Before(dl) {
		time.Sleep(10 * time.Millisecond)
	}
	if !ci1.IsLeader() {
		ci1.Stop()
		t.Fatal("ci1 never became leader")
	}

	if err := ci1.ProposeZoneChangeWait(ZoneCommand{
		Type: "add_record", Zone: "example.com.", Name: "www", RRTypeStr: "A", RData: []string{"192.0.2.10"},
	}, 5*time.Second); err != nil {
		ci1.Stop()
		t.Fatalf("propose: %v", err)
	}

	ci1.takeSnapshot()

	// The WAL must have been compacted: nothing at or below the snapshot index
	// remains.
	ci1.node.mu.Lock()
	snapIdx := ci1.node.lastSnapshot
	ci1.node.mu.Unlock()
	if snapIdx == 0 {
		ci1.Stop()
		t.Fatal("snapshot was not taken (lastSnapshot=0)")
	}
	walEntries, err := ci1.wal.ReadAll()
	if err != nil {
		ci1.Stop()
		t.Fatalf("read WAL: %v", err)
	}
	for _, e := range walEntries {
		if e.Index <= snapIdx {
			ci1.Stop()
			t.Fatalf("WAL not compacted: entry index %d <= snapshot %d still present", e.Index, snapIdx)
		}
	}
	ci1.Stop()

	// --- Second incarnation over the same data dir, fresh store. ---
	store2 := newTestZoneStore()
	ci2, err := NewClusterIntegration("n1", nil, nil, freeTCPAddr(t), dir, "", "", nil, util.DefaultLogger())
	if err != nil {
		t.Fatalf("ci2: %v", err)
	}
	ci2.SetApplyHook(func(c ZoneCommand) { store2.apply(c) })
	ci2.SetSnapshotFns(store2.snapshot, store2.restore)
	if err := ci2.Start(); err != nil {
		t.Fatalf("start ci2: %v", err)
	}
	defer ci2.Stop()

	// bootstrapState restores the snapshot synchronously during Start, so the
	// record must be present immediately — proving boot-from-snapshot rather
	// than a full WAL replay (the WAL prefix was compacted away).
	if v, ok := store2.get(recordKey); !ok || v != "192.0.2.10" {
		t.Fatalf("boot-from-snapshot did not restore the record (present=%v val=%q)", ok, v)
	}
	// And the restored applied index should match the snapshot.
	ci2.node.mu.Lock()
	la := ci2.node.lastApplied
	ls := ci2.node.lastSnapshot
	ci2.node.mu.Unlock()
	if ls != snapIdx || la != snapIdx {
		t.Fatalf("restored indices wrong: lastSnapshot=%d lastApplied=%d want %d", ls, la, snapIdx)
	}
}
