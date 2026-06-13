package util

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// chunkWriter writes at most maxWrite bytes per Write call.
type chunkWriter struct {
	buf      bytes.Buffer
	maxWrite int
	calls    int
}

func (w *chunkWriter) Write(p []byte) (int, error) {
	w.calls++
	if len(p) > w.maxWrite {
		p = p[:w.maxWrite]
	}
	return w.buf.Write(p)
}

// failAfterWriter accepts the first maxWrite bytes, then fails.
type failAfterWriter struct {
	buf      bytes.Buffer
	maxWrite int
	err      error
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	remaining := w.maxWrite - w.buf.Len()
	if remaining <= 0 {
		return 0, w.err
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	return w.buf.Write(p)
}

// zeroProgressWriter reports a successful write of zero bytes.
type zeroProgressWriter struct{}

func (zeroProgressWriter) Write(p []byte) (int, error) {
	return 0, nil
}

func TestWriteFull_FullWrite(t *testing.T) {
	var buf bytes.Buffer
	data := []byte("hello, write full")

	if err := WriteFull(&buf, data); err != nil {
		t.Fatalf("WriteFull error: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), data) {
		t.Fatalf("written = %q, want %q", buf.Bytes(), data)
	}
}

func TestWriteFull_EmptyPayload(t *testing.T) {
	w := &chunkWriter{maxWrite: 1}
	if err := WriteFull(w, nil); err != nil {
		t.Fatalf("WriteFull(nil) error: %v", err)
	}
	if w.calls != 0 {
		t.Fatalf("WriteFull(nil) made %d Write calls, want 0", w.calls)
	}
}

func TestWriteFull_ShortWriteRetry(t *testing.T) {
	w := &chunkWriter{maxWrite: 1}
	data := []byte{1, 2, 3, 4, 5}

	if err := WriteFull(w, data); err != nil {
		t.Fatalf("WriteFull error: %v", err)
	}
	if !bytes.Equal(w.buf.Bytes(), data) {
		t.Fatalf("written = %v, want %v", w.buf.Bytes(), data)
	}
	if w.calls != len(data) {
		t.Fatalf("Write calls = %d, want %d (one byte per call)", w.calls, len(data))
	}
}

func TestWriteFull_ErrorPropagation(t *testing.T) {
	wantErr := errors.New("pipe broken")
	w := &failAfterWriter{maxWrite: 3, err: wantErr}
	data := []byte{1, 2, 3, 4, 5}

	err := WriteFull(w, data)
	if !errors.Is(err, wantErr) {
		t.Fatalf("WriteFull error = %v, want %v", err, wantErr)
	}
	if !bytes.Equal(w.buf.Bytes(), data[:3]) {
		t.Fatalf("partial written = %v, want %v", w.buf.Bytes(), data[:3])
	}
}

func TestWriteFull_ZeroProgressGuard(t *testing.T) {
	err := WriteFull(zeroProgressWriter{}, []byte{1, 2, 3})
	if !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("WriteFull error = %v, want %v", err, io.ErrNoProgress)
	}
}
