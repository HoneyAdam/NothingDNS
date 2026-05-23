package raft

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Snapshot contains the state machine state at a point in time.
type Snapshot struct {
	Index      Index
	Term       Term
	LastIndex  Index // Highest index in snapshot
	LastTerm   Term  // Term of last index
	Data       []byte
	Membership []NodeID // Peers in the cluster at snapshot time
}

// Snapshotter manages snapshots for log compaction.
type Snapshotter struct {
	mu           sync.RWMutex
	snapshotsDir string
}

// NewSnapshotter creates a new snapshotter.
func NewSnapshotter(dir string) (*Snapshotter, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}
	return &Snapshotter{
		snapshotsDir: dir,
	}, nil
}

// Save saves a snapshot to disk.
//
// Durability: fsync the temp file before rename and fsync the
// snapshots directory after rename so the new file's dirent
// reaches stable storage. Without either, a crash between the
// write and the directory flush could leave Raft believing it
// has a durable snapshot at index N while the file is empty,
// truncated, or absent on next start — and Raft uses the
// snapshot to decide which WAL segments are safe to truncate,
// so a missing snapshot turns into permanent log loss.
func (s *Snapshotter) Save(snap *Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filename := filepath.Join(s.snapshotsDir, snapFilename(snap.Index))
	tmpFile := filename + ".tmp"

	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	if err := s.writeSnapshot(f, snap); err != nil {
		f.Close()
		os.Remove(tmpFile)
		return err
	}

	// fsync the file's data and metadata before rename — closing
	// alone flushes user-space buffers but does NOT guarantee the
	// bytes reach the disk platter.
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpFile)
		return fmt.Errorf("sync: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("close: %w", err)
	}

	if err := os.Rename(tmpFile, filename); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("rename: %w", err)
	}

	// fsync the directory so the rename's dirent commit reaches
	// stable storage. Best-effort: tmpfs and a few exotic FSes
	// don't support dir fsync, so log-and-ignore an error here.
	if dirFd, derr := os.Open(s.snapshotsDir); derr == nil {
		_ = dirFd.Sync()
		_ = dirFd.Close()
	}

	return nil
}

// Load loads the latest snapshot from disk.
func (s *Snapshotter) Load() (*Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find latest snapshot file
	files, err := os.ReadDir(s.snapshotsDir)
	if err != nil {
		return nil, fmt.Errorf("readdir: %w", err)
	}

	var latest string
	var latestIndex Index
	for _, f := range files {
		if f.IsDir() || len(f.Name()) < 6 {
			continue
		}
		var idx Index
		if _, err := fmt.Sscanf(f.Name(), "snapshot-%d", &idx); err == nil {
			if idx > latestIndex {
				latestIndex = idx
				latest = f.Name()
			}
		}
	}

	if latest == "" {
		return nil, nil
	}

	snapPath := filepath.Join(s.snapshotsDir, latest)
	f, err := os.Open(snapPath)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	return s.readSnapshot(f)
}

// writeSnapshot writes a snapshot to a writer.
func (s *Snapshotter) writeSnapshot(w io.Writer, snap *Snapshot) error {
	// Format: Index(8) + Term(8) + LastIndex(8) + LastTerm(8) + DataLen(8) + Data + MembershipLen(4) + Membership
	buf := make([]byte, 8)

	// Index
	binary.BigEndian.PutUint64(buf, uint64(snap.Index))
	if _, err := w.Write(buf); err != nil {
		return err
	}

	// Term
	binary.BigEndian.PutUint64(buf, uint64(snap.Term))
	if _, err := w.Write(buf); err != nil {
		return err
	}

	// LastIndex
	binary.BigEndian.PutUint64(buf, uint64(snap.LastIndex))
	if _, err := w.Write(buf); err != nil {
		return err
	}

	// LastTerm
	binary.BigEndian.PutUint64(buf, uint64(snap.LastTerm))
	if _, err := w.Write(buf); err != nil {
		return err
	}

	// Data
	binary.BigEndian.PutUint64(buf, uint64(len(snap.Data)))
	if _, err := w.Write(buf); err != nil {
		return err
	}
	if _, err := w.Write(snap.Data); err != nil {
		return err
	}

	// Membership
	membershipLen := make([]byte, 4)
	binary.BigEndian.PutUint32(membershipLen, uint32(len(snap.Membership)))
	if _, err := w.Write(membershipLen); err != nil {
		return err
	}
	for _, peerID := range snap.Membership {
		peerBytes := []byte(peerID)
		lenBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBytes, uint32(len(peerBytes)))
		if _, err := w.Write(lenBytes); err != nil {
			return err
		}
		if _, err := w.Write(peerBytes); err != nil {
			return err
		}
	}

	return nil
}

// Snapshot wire-format limits. These cap untrusted on-disk fields so
// a corrupt or attacker-planted snapshot file can't drive
// runaway allocations during Load.
//
//   - maxSnapshotDataBytes: state-machine payload. 1 GiB is well
//     above any realistic DNS zone aggregate; well below the
//     uint64 ceiling where make() would OOM the process.
//   - maxSnapshotMembership: number of NodeIDs. 1024 peers is
//     several orders of magnitude beyond any practical Raft cluster.
//   - maxNodeIDBytes: per-NodeID byte length. NodeIDs are short
//     identifiers; 256 bytes is generous.
const (
	maxSnapshotDataBytes  = 1 << 30 // 1 GiB
	maxSnapshotMembership = 1024
	maxNodeIDBytes        = 256
)

// readSnapshot reads a snapshot from a reader.
func (s *Snapshotter) readSnapshot(r io.Reader) (*Snapshot, error) {
	snap := &Snapshot{}

	buf := make([]byte, 8)

	// Index
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read index: %w", err)
	}
	snap.Index = Index(binary.BigEndian.Uint64(buf))

	// Term
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read term: %w", err)
	}
	snap.Term = Term(binary.BigEndian.Uint64(buf))

	// LastIndex
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read lastindex: %w", err)
	}
	snap.LastIndex = Index(binary.BigEndian.Uint64(buf))

	// LastTerm
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read lastterm: %w", err)
	}
	snap.LastTerm = Term(binary.BigEndian.Uint64(buf))

	// Data
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read datalen: %w", err)
	}
	dataLen := binary.BigEndian.Uint64(buf)
	if dataLen > maxSnapshotDataBytes {
		return nil, fmt.Errorf("snapshot dataLen %d exceeds max %d", dataLen, maxSnapshotDataBytes)
	}
	snap.Data = make([]byte, dataLen)
	if _, err := io.ReadFull(r, snap.Data); err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}

	// Membership
	membershipLen := make([]byte, 4)
	if _, err := io.ReadFull(r, membershipLen); err != nil {
		return nil, fmt.Errorf("read membershiplen: %w", err)
	}
	mCount := binary.BigEndian.Uint32(membershipLen)
	if mCount > maxSnapshotMembership {
		return nil, fmt.Errorf("snapshot membership count %d exceeds max %d", mCount, maxSnapshotMembership)
	}
	for i := uint32(0); i < mCount; i++ {
		lenBytes := make([]byte, 4)
		if _, err := io.ReadFull(r, lenBytes); err != nil {
			return nil, fmt.Errorf("read peerlen: %w", err)
		}
		peerLen := binary.BigEndian.Uint32(lenBytes)
		if peerLen > maxNodeIDBytes {
			return nil, fmt.Errorf("snapshot peerLen %d exceeds max %d", peerLen, maxNodeIDBytes)
		}
		peerBytes := make([]byte, peerLen)
		if _, err := io.ReadFull(r, peerBytes); err != nil {
			return nil, fmt.Errorf("read peer: %w", err)
		}
		snap.Membership = append(snap.Membership, NodeID(peerBytes))
	}

	return snap, nil
}

// snapFilename returns the filename for a snapshot index.
func snapFilename(index Index) string {
	return fmt.Sprintf("snapshot-%d", index)
}
