package upstream

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// ---------------------------------------------------------------------------
// circuitBreaker.shouldAllow — all states
// ---------------------------------------------------------------------------

func TestCircuitBreaker_ShouldAllow_Closed(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbClosed,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}
	if !cb.shouldAllow() {
		t.Error("expected shouldAllow=true when closed")
	}
}

func TestCircuitBreaker_ShouldAllow_HalfOpen(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbHalfOpen,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}
	if !cb.shouldAllow() {
		t.Error("expected shouldAllow=true when half-open")
	}
}

func TestCircuitBreaker_ShouldAllow_Open_WithinTimeout(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbOpen,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
		lastFailure:  time.Now(), // recent failure
	}
	if cb.shouldAllow() {
		t.Error("expected shouldAllow=false when open and within timeout")
	}
}

func TestCircuitBreaker_ShouldAllow_Open_AfterTimeout(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbOpen,
		failureLimit: 3,
		resetTimeout: 50 * time.Millisecond,
		lastFailure:  time.Now().Add(-100 * time.Millisecond), // expired
	}
	if !cb.shouldAllow() {
		t.Error("expected shouldAllow=true after reset timeout expired")
	}

	cb.mu.Lock()
	state := cb.state
	cb.mu.Unlock()

	if state != cbHalfOpen {
		t.Error("expected state to transition to half-open after timeout")
	}
}

func TestCircuitBreaker_ResetTimeoutReachedBoundary(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	resetTimeout := 30 * time.Second

	if circuitBreakerResetReachedAt(now.Add(-resetTimeout+time.Nanosecond), now, resetTimeout) {
		t.Error("reset timeout should not be reached before the boundary")
	}
	if !circuitBreakerResetReachedAt(now.Add(-resetTimeout), now, resetTimeout) {
		t.Error("reset timeout should be reached exactly at the boundary")
	}
	if !circuitBreakerResetReachedAt(now.Add(-resetTimeout-time.Nanosecond), now, resetTimeout) {
		t.Error("reset timeout should be reached after the boundary")
	}
}

func TestCircuitBreaker_ShouldAllow_UnknownState(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbState(99), // unknown state
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}
	if !cb.shouldAllow() {
		t.Error("expected shouldAllow=true for unknown state (default)")
	}
}

// ---------------------------------------------------------------------------
// circuitBreaker.recordSuccess
// ---------------------------------------------------------------------------

func TestCircuitBreaker_RecordSuccess(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbOpen,
		failures:     5,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}

	cb.recordSuccess()

	cb.mu.Lock()
	failures := cb.failures
	state := cb.state
	cb.mu.Unlock()

	if failures != 0 {
		t.Errorf("expected failures=0 after recordSuccess, got %d", failures)
	}
	if state != cbClosed {
		t.Errorf("expected state=cbClosed after recordSuccess, got %d", state)
	}
}

// ---------------------------------------------------------------------------
// circuitBreaker.recordFailure transitions
// ---------------------------------------------------------------------------

func TestCircuitBreaker_RecordFailure_BelowLimit(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbClosed,
		failures:     0,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}

	cb.recordFailure()

	cb.mu.Lock()
	failures := cb.failures
	state := cb.state
	cb.mu.Unlock()

	if failures != 1 {
		t.Errorf("expected failures=1, got %d", failures)
	}
	if state != cbClosed {
		t.Errorf("expected state=cbClosed (below limit), got %d", state)
	}
}

func TestCircuitBreaker_RecordFailure_TripsOpen(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbClosed,
		failures:     2,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}

	cb.recordFailure()

	cb.mu.Lock()
	state := cb.state
	cb.mu.Unlock()

	if state != cbOpen {
		t.Error("expected circuit breaker to be open after reaching failure limit")
	}
}

// ---------------------------------------------------------------------------
// tcpPool.put — overflow connection
// ---------------------------------------------------------------------------

func TestTCPPool_Put_OverflowConnection(t *testing.T) {
	// Create a pool
	pool := &tcpConnPool{
		maxIdle:  2,
		maxTotal: 5,
	}

	// Create a connection that belongs to a different pool
	otherPool := &tcpConnPool{}
	conn := &tcpConn{
		pool: otherPool,
		conn: &net.TCPConn{},
	}

	// put should close the overflow connection
	pool.put(conn)
	// Should not panic and should not add to idle
	if len(pool.idle) != 0 {
		t.Errorf("expected 0 idle conns, got %d", len(pool.idle))
	}
}

func TestTCPPool_Put_PoolClosed(t *testing.T) {
	pool := &tcpConnPool{
		maxIdle:  2,
		maxTotal: 5,
		closed:   true,
		active:   1,
	}

	conn := &tcpConn{
		pool: pool,
		conn: &net.TCPConn{},
	}
	conn.inUse.Store(true)

	pool.put(conn)

	if pool.active != 0 {
		t.Errorf("expected active=0 after put to closed pool, got %d", pool.active)
	}
}

func TestTCPPool_Put_TooManyIdle(t *testing.T) {
	pool := &tcpConnPool{
		maxIdle:  1,
		maxTotal: 5,
		idle:     make([]*tcpConn, 1),
		active:   2,
	}
	pool.idle[0] = &tcpConn{pool: pool}

	conn := &tcpConn{
		pool: pool,
		conn: &net.TCPConn{},
	}
	conn.inUse.Store(true)

	pool.put(conn)

	// Should close the connection because idle is full
	if len(pool.idle) != 1 {
		t.Errorf("expected 1 idle conn (max), got %d", len(pool.idle))
	}
	if pool.active != 1 {
		t.Errorf("expected active=1 after closing excess, got %d", pool.active)
	}
}

func TestTCPPool_Put_Success(t *testing.T) {
	pool := &tcpConnPool{
		maxIdle:  5,
		maxTotal: 10,
		idle:     []*tcpConn{},
		active:   1,
	}

	conn := &tcpConn{
		pool: pool,
		conn: &net.TCPConn{},
	}
	conn.inUse.Store(true)

	pool.put(conn)

	if len(pool.idle) != 1 {
		t.Errorf("expected 1 idle conn, got %d", len(pool.idle))
	}
	if conn.inUse.Load() {
		t.Error("expected inUse=false after put")
	}
}

func TestTCPPool_IdleTimeoutReachedBoundary(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	idleTimeout := 30 * time.Second

	if tcpIdleTimeoutReachedAt(now.Add(-idleTimeout+time.Nanosecond), now, idleTimeout) {
		t.Error("idle timeout should not be reached before the boundary")
	}
	if !tcpIdleTimeoutReachedAt(now.Add(-idleTimeout), now, idleTimeout) {
		t.Error("idle timeout should be reached exactly at the boundary")
	}
	if !tcpIdleTimeoutReachedAt(now.Add(-idleTimeout-time.Nanosecond), now, idleTimeout) {
		t.Error("idle timeout should be reached after the boundary")
	}
}

func TestTCPConn_Close_DecrementsPooledActiveOnce(t *testing.T) {
	pool := &tcpConnPool{
		maxIdle:  1,
		maxTotal: 1,
		active:   1,
	}

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	conn := &tcpConn{
		pool: pool,
		conn: clientConn,
	}
	conn.inUse.Store(true)

	if err := conn.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
	if pool.active != 0 {
		t.Fatalf("expected active=0 after close, got %d", pool.active)
	}

	_ = conn.close()
	if pool.active != 0 {
		t.Fatalf("expected second close to keep active=0, got %d", pool.active)
	}
}

func TestWriteFullRetriesPartialWrites(t *testing.T) {
	conn := &partialWriteConn{maxWrite: 2}
	data := []byte{1, 2, 3, 4, 5}

	if err := util.WriteFull(conn, data); err != nil {
		t.Fatalf("WriteFull failed: %v", err)
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
		t.Fatalf("writePacket should not retry partial datagrams, got %d calls", conn.calls)
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
	return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *partialWriteConn) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
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

func TestTCPPool_CloseAll_DecrementsIdleActive(t *testing.T) {
	pool := &tcpConnPool{
		maxIdle:  2,
		maxTotal: 2,
		active:   2,
	}

	clientConn1, serverConn1 := net.Pipe()
	defer serverConn1.Close()
	clientConn2, serverConn2 := net.Pipe()
	defer serverConn2.Close()

	pool.idle = []*tcpConn{
		{pool: pool, conn: clientConn1},
		{pool: pool, conn: clientConn2},
	}

	pool.closeAll()

	if pool.active != 0 {
		t.Fatalf("expected active=0 after closeAll, got %d", pool.active)
	}
	if len(pool.idle) != 0 {
		t.Fatalf("expected idle list to be cleared, got %d", len(pool.idle))
	}
}

func TestTCPPool_GetRejectsClosedPool(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
		close(accepted)
	}()

	pool := newTCPConnPool(ln.Addr().String(), 1, 1, time.Second, time.Second)
	pool.closeAll()

	tc, err := pool.get()
	if err == nil {
		if tc != nil {
			_ = tc.close()
		}
		t.Fatal("expected closed pool to reject get")
	}
	if tc != nil {
		t.Fatalf("expected nil conn from closed pool, got %#v", tc)
	}
	if pool.active != 0 {
		t.Fatalf("expected active=0 after rejected get, got %d", pool.active)
	}

	select {
	case conn := <-accepted:
		if conn != nil {
			_ = conn.Close()
			t.Fatal("closed pool unexpectedly opened a TCP connection")
		}
	case <-time.After(50 * time.Millisecond):
	}
}
