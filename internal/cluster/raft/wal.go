package raft

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"sync"

	"github.com/nothingdns/nothingdns/internal/util"
)

// maxWALCommandBytes caps the size of any single WAL command entry.
// This prevents a corrupt or attacker-controlled WAL from causing unbounded
// allocation during log replay (VULN-047).
const maxWALCommandBytes = 64 * 1024 * 1024 // 64 MiB

// WAL is the Write-Ahead Log for Raft log entries.
// It provides durability for uncommitted log entries.
type WAL struct {
	mu      sync.Mutex
	logFile *os.File
	dir     string
}

// NewWAL creates a new WAL.
func NewWAL(dir string) (*WAL, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}

	logPath := path.Join(dir, "raft-wal.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}

	return &WAL{
		logFile: f,
		dir:     dir,
	}, nil
}

// Write writes an entry to the WAL.
func (w *WAL) Write(e entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeLocked(e)
}

// encodeWALEntry serializes one entry to its on-disk record format:
// Index(8) + Term(8) + CommandLen(8) + Command + Type(1).
func encodeWALEntry(e entry) []byte {
	dataLen := 8 + 8 + 8 + len(e.Command) + 1
	buf := make([]byte, dataLen)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:], uint64(e.Index))
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:], uint64(e.Term))
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:], uint64(len(e.Command)))
	offset += 8

	copy(buf[offset:], e.Command)
	offset += len(e.Command)

	buf[offset] = byte(e.Type)
	return buf
}

// writeLocked appends one entry. Caller must hold w.mu.
func (w *WAL) writeLocked(e entry) error {
	return util.WriteFull(w.logFile, encodeWALEntry(e))
}

// logPath returns the WAL's backing file path.
func (w *WAL) logPath() string {
	return path.Join(w.dir, "raft-wal.log")
}

// rewriteLocked atomically replaces the WAL contents with kept. It writes the
// kept entries to a temp file, fsyncs it, renames it over the live log, and
// fsyncs the directory so the rename is durable, then reopens the log for
// appending. A crash at any point leaves either the complete old log or the
// complete new log on disk — never a truncated one. This replaces the previous
// Truncate(0)+re-append, where a crash mid-rewrite lost committed entries.
// Caller must hold w.mu.
func (w *WAL) rewriteLocked(kept []entry) error {
	logPath := w.logPath()

	tmp, err := os.CreateTemp(w.dir, "raft-wal-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp WAL: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := os.Chmod(tmpName, 0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp WAL: %w", err)
	}
	for _, e := range kept {
		if err := util.WriteFull(tmp, encodeWALEntry(e)); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("write temp WAL: %w", err)
		}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp WAL: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp WAL: %w", err)
	}

	if err := os.Rename(tmpName, logPath); err != nil {
		return fmt.Errorf("rename WAL: %w", err)
	}
	cleanup = false

	if err := syncHardStateParentDir(w.dir); err != nil {
		return fmt.Errorf("fsync WAL dir: %w", err)
	}

	// Swap in a fresh append handle for the renamed file.
	if err := w.logFile.Close(); err != nil {
		return fmt.Errorf("close old WAL handle: %w", err)
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("reopen WAL: %w", err)
	}
	w.logFile = f
	return nil
}

// TruncateAfter removes every entry whose Index is greater than keepThrough,
// rewriting the log file in place. Used when a follower's log conflicts with
// the leader's and the tail must be discarded before the correct entries are
// appended — without this the WAL would keep replaying stale, overwritten
// entries on the next restart.
func (w *WAL) TruncateAfter(keepThrough Index) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	all, err := w.readAllLocked()
	if err != nil {
		return err
	}
	kept := all[:0]
	for _, e := range all {
		if e.Index <= keepThrough {
			kept = append(kept, e)
		}
	}

	return w.rewriteLocked(kept)
}

// CompactBefore removes every entry whose Index is <= through, keeping the
// suffix, and rewrites the file in place. Called after a snapshot subsumes the
// log prefix so the WAL stays bounded and a restart replays only the
// post-snapshot tail.
func (w *WAL) CompactBefore(through Index) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	all, err := w.readAllLocked()
	if err != nil {
		return err
	}
	kept := all[:0]
	for _, e := range all {
		if e.Index > through {
			kept = append(kept, e)
		}
	}

	return w.rewriteLocked(kept)
}

// ReadAll reads all entries from the WAL.
func (w *WAL) ReadAll() ([]entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.readAllLocked()
}

// readAllLocked reads every entry from the start of the file. Caller must
// hold w.mu.
func (w *WAL) readAllLocked() ([]entry, error) {
	if _, err := w.logFile.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	var entries []entry
	buf := make([]byte, 1024) // Reusable buffer

	for {
		// Read index, term, and cmdLen all at once to validate record boundary.
		// Use io.ReadFull so a short read (e.g., partial write from crash) returns
		// an error rather than silently reading the next record's bytes as this record's data.
		header := make([]byte, 24) // 8 bytes index + 8 bytes term + 8 bytes cmdLen
		if _, err := io.ReadFull(w.logFile, header); err != nil {
			if err == io.EOF {
				break // Clean end of WAL
			}
			return nil, fmt.Errorf("read WAL header: %w", err)
		}
		e := entry{}
		e.Index = Index(binary.BigEndian.Uint64(header[0:8]))
		e.Term = Term(binary.BigEndian.Uint64(header[8:16]))
		cmdLen := binary.BigEndian.Uint64(header[16:24])

		// VULN-047: cap command length to prevent unbounded allocation from corrupt WAL.
		// A crafted WAL with a large cmdLen could exhaust memory during replay.
		if cmdLen > maxWALCommandBytes {
			return nil, fmt.Errorf("WAL cmdLen %d exceeds max %d — corrupt or attacker-crafted WAL", cmdLen, maxWALCommandBytes)
		}

		// Read command
		if cmdLen > 0 {
			if uint64(len(buf)) < cmdLen {
				buf = make([]byte, cmdLen)
			}
			if _, err := io.ReadFull(w.logFile, buf[:cmdLen]); err != nil {
				return nil, fmt.Errorf("read WAL cmd (%d bytes): %w", cmdLen, err)
			}
			e.Command = make([]byte, cmdLen)
			copy(e.Command, buf[:cmdLen])
		}

		// Read type
		var typBuf [1]byte
		if _, err := io.ReadFull(w.logFile, typBuf[:]); err != nil {
			return nil, fmt.Errorf("read WAL type: %w", err)
		}
		e.Type = EntryType(typBuf[0])

		entries = append(entries, e)
	}

	return entries, nil
}

// Close closes the WAL.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.logFile.Close()
}

// Sync forces the WAL to disk.
func (w *WAL) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.logFile.Sync()
}
