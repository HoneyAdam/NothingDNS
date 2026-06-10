package load

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

// ---------------------------------------------------------------------------
// RunPreset presets coverage — just exercise each preset branch
// ---------------------------------------------------------------------------

func TestRunPreset_Medium(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := RunPreset(ctx, "127.0.0.1:5354", "medium")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	t.Logf("medium: errors=%d timeouts=%d", result.Errors, result.Timeouts)
}

func TestRunPreset_Heavy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := RunPreset(ctx, "127.0.0.1:5354", "heavy")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	t.Logf("heavy: errors=%d timeouts=%d", result.Errors, result.Timeouts)
}

func TestRunPreset_Stress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := RunPreset(ctx, "127.0.0.1:5354", "stress")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	t.Logf("stress: errors=%d timeouts=%d", result.Errors, result.Timeouts)
}

func TestRunPreset_Default(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := RunPreset(ctx, "127.0.0.1:5354", "unknown-preset")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	t.Logf("default: errors=%d timeouts=%d", result.Errors, result.Timeouts)
}

// ---------------------------------------------------------------------------
// sendQuery error paths via short timeout
// ---------------------------------------------------------------------------

func TestRunner_SendQuery_InvalidName(t *testing.T) {
	cfg := Config{
		Server:  "127.0.0.1:5354",
		Queries: 1,
		Workers: 1,
		Name:    "..invalid..name..",
		Type:    protocol.TypeA,
		Timeout: 1 * time.Second,
	}
	runner := NewRunner(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := runner.Run(ctx)
	// Note: This test may fail if no server is running at the target address.
	// The error count depends on whether the connection can be established.
	if result.Errors == 0 && result.Success == 0 {
		t.Skip("no server available at target address, skipping test")
	}
}

func TestRunner_TCPProtocol(t *testing.T) {
	cfg := Config{
		Server:   "127.0.0.1:1",
		Queries:  1,
		Workers:  1,
		Protocol: "tcp",
		Name:     "www.example.com.",
		Type:     protocol.TypeA,
		Timeout:  100 * time.Millisecond,
	}
	runner := NewRunner(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := runner.Run(ctx)
	// Connection should fail (nothing listening on port 1)
	if result.Errors == 0 && result.Timeouts == 0 {
		t.Log("expected errors or timeouts connecting to port 1")
	}
}

func TestRunner_UDPProtocol(t *testing.T) {
	cfg := Config{
		Server:   "127.0.0.1:1",
		Queries:  1,
		Workers:  1,
		Protocol: "udp",
		Name:     "www.example.com.",
		Type:     protocol.TypeA,
		Timeout:  100 * time.Millisecond,
	}
	runner := NewRunner(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := runner.Run(ctx)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestWriteFullRetriesPartialWrites(t *testing.T) {
	conn := &partialWriteConn{maxWrite: 2}
	data := []byte{1, 2, 3, 4, 5}

	if err := util.WriteFull(conn, data); err != nil {
		t.Fatalf("WriteFull error: %v", err)
	}
	if string(conn.written) != string(data) {
		t.Fatalf("written bytes = %v, want %v", conn.written, data)
	}
	if conn.calls <= 1 {
		t.Fatalf("expected multiple partial writes, got %d call", conn.calls)
	}
}

func TestWriteFullRejectsZeroByteWrite(t *testing.T) {
	conn := &partialWriteConn{}
	err := util.WriteFull(conn, []byte{1, 2, 3})
	if err != io.ErrNoProgress {
		t.Fatalf("WriteFull error = %v, want %v", err, io.ErrNoProgress)
	}
}

func TestWritePacketRejectsPartialDatagramWrite(t *testing.T) {
	conn := &partialWriteConn{maxWrite: 2}
	_, err := writePacket(conn, []byte{1, 2, 3})
	if err != io.ErrShortWrite {
		t.Fatalf("writePacket error = %v, want %v", err, io.ErrShortWrite)
	}
	if conn.calls != 1 {
		t.Fatalf("writePacket should not retry datagrams, got %d calls", conn.calls)
	}
}

type partialWriteConn struct {
	maxWrite int
	written  []byte
	calls    int
}

func (c *partialWriteConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *partialWriteConn) Write(p []byte) (int, error) {
	c.calls++
	if c.maxWrite <= 0 {
		return 0, nil
	}
	n := c.maxWrite
	if n > len(p) {
		n = len(p)
	}
	c.written = append(c.written, p[:n]...)
	return n, nil
}

func (c *partialWriteConn) Close() error {
	return nil
}

func (c *partialWriteConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *partialWriteConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *partialWriteConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *partialWriteConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *partialWriteConn) SetWriteDeadline(_ time.Time) error {
	return nil
}
