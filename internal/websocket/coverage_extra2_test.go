package websocket

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// isOriginAllowed
// ============================================================================

func TestIsOriginAllowed_ExactMatch(t *testing.T) {
	allowed := []string{"https://example.com", "https://other.com"}
	if !isOriginAllowed("https://example.com", allowed) {
		t.Error("expected exact match for 'https://example.com'")
	}
	if !isOriginAllowed("https://other.com", allowed) {
		t.Error("expected exact match for 'https://other.com'")
	}
}

func TestIsOriginAllowed_NoMatch(t *testing.T) {
	allowed := []string{"https://example.com", "https://other.com"}
	if isOriginAllowed("https://evil.com", allowed) {
		t.Error("expected no match for 'https://evil.com'")
	}
}

func TestIsOriginAllowed_CaseSensitive(t *testing.T) {
	allowed := []string{"https://Example.com"}
	// isOriginAllowed uses direct string comparison, so it is case-sensitive
	if isOriginAllowed("https://example.com", allowed) {
		t.Error("expected case-sensitive mismatch")
	}
	if !isOriginAllowed("https://Example.com", allowed) {
		t.Error("expected exact case-sensitive match")
	}
}

func TestIsOriginAllowed_EmptyAllowedList(t *testing.T) {
	if isOriginAllowed("https://example.com", nil) {
		t.Error("expected false with nil allowed list")
	}
	if isOriginAllowed("https://example.com", []string{}) {
		t.Error("expected false with empty allowed list")
	}
}

func TestIsOriginAllowed_WildcardNotSpecial(t *testing.T) {
	// The wildcard "*" is not treated specially — it must be an exact match
	allowed := []string{"*"}
	if !isOriginAllowed("*", allowed) {
		t.Error("expected exact match for literal '*'")
	}
	if isOriginAllowed("https://example.com", allowed) {
		t.Error("expected no match — '*' is not a wildcard")
	}
}

func TestIsOriginAllowed_SingleOrigin(t *testing.T) {
	allowed := []string{"https://myapp.local"}
	if !isOriginAllowed("https://myapp.local", allowed) {
		t.Error("expected match for single allowed origin")
	}
	if isOriginAllowed("https://myapp.local.evil.com", allowed) {
		t.Error("expected no match for similar but different origin")
	}
}

// ============================================================================
// SetRateLimit + checkRateLimit
// ============================================================================

func TestSetRateLimit_WithinLimit(t *testing.T) {
	c := newConn(nil)
	c.SetRateLimit(5, time.Second)

	for i := 0; i < 5; i++ {
		if !c.checkRateLimit() {
			t.Errorf("expected rate limit to pass on message %d", i+1)
		}
	}
}

func TestSetRateLimit_ExceedsLimit(t *testing.T) {
	c := newConn(nil)
	c.SetRateLimit(3, time.Second)

	// First 3 should pass
	for i := 0; i < 3; i++ {
		if !c.checkRateLimit() {
			t.Errorf("expected rate limit to pass on message %d", i+1)
		}
	}
	// 4th should fail
	if c.checkRateLimit() {
		t.Error("expected rate limit to be exceeded on message 4")
	}
}

func TestSetRateLimit_WindowReset(t *testing.T) {
	c := newConn(nil)
	c.SetRateLimit(3, 50*time.Millisecond) // short window for testing

	// Consume all allowed messages
	for i := 0; i < 3; i++ {
		if !c.checkRateLimit() {
			t.Fatalf("expected pass on message %d", i+1)
		}
	}
	// Should be rate-limited now
	if c.checkRateLimit() {
		t.Error("expected rate limit to trigger")
	}

	// Wait for the window to expire
	time.Sleep(80 * time.Millisecond)

	// Window should have reset — first message in new window passes
	if !c.checkRateLimit() {
		t.Error("expected rate limit to reset after window expiry")
	}
}

func TestSetRateLimit_WindowExpiredBoundary(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	window := time.Second

	if wsRateWindowExpiredAt(now.Add(-window+time.Nanosecond), now, window) {
		t.Error("websocket rate window should not expire before the boundary")
	}
	if !wsRateWindowExpiredAt(now.Add(-window), now, window) {
		t.Error("websocket rate window should expire exactly at the boundary")
	}
	if !wsRateWindowExpiredAt(now.Add(-window-time.Nanosecond), now, window) {
		t.Error("websocket rate window should expire after the boundary")
	}
}

func TestSetRateLimit_Disabled(t *testing.T) {
	c := newConn(nil)
	// maxMessages <= 0 disables rate limiting
	c.SetRateLimit(0, time.Second)

	for i := 0; i < 200; i++ {
		if !c.checkRateLimit() {
			t.Errorf("expected rate limit disabled (pass on message %d)", i+1)
		}
	}
}

func TestSetRateLimit_DisabledNegative(t *testing.T) {
	c := newConn(nil)
	c.SetRateLimit(-5, time.Second)

	for i := 0; i < 200; i++ {
		if !c.checkRateLimit() {
			t.Errorf("expected rate limit disabled with negative max (message %d)", i+1)
		}
	}
}

func TestSetRateLimit_DefaultIsDisabled(t *testing.T) {
	// New connection has no rate limit configured (rateMax == 0)
	c := newConn(nil)
	for i := 0; i < 100; i++ {
		if !c.checkRateLimit() {
			t.Errorf("expected no rate limit by default (message %d)", i+1)
		}
	}
}

func TestSetRateLimit_Reconfigure(t *testing.T) {
	c := newConn(nil)

	// First configure with limit of 2
	c.SetRateLimit(2, time.Second)
	if !c.checkRateLimit() {
		t.Error("expected pass 1")
	}
	if !c.checkRateLimit() {
		t.Error("expected pass 2")
	}
	if c.checkRateLimit() {
		t.Error("expected rate limit on message 3")
	}

	// Reconfigure with higher limit — should reset counters
	c.SetRateLimit(10, time.Second)
	for i := 0; i < 10; i++ {
		if !c.checkRateLimit() {
			t.Errorf("expected pass after reconfigure (message %d)", i+1)
		}
	}
	if c.checkRateLimit() {
		t.Error("expected rate limit on message 11 after reconfigure")
	}
}

// ============================================================================
// writeClose (tested indirectly via rate limit trigger in ReadMessage)
// ============================================================================

func TestWriteClose_FrameWritten(t *testing.T) {
	// Set a very low rate limit and trigger it via ReadMessage
	// to verify writeClose sends a properly formatted close frame
	c := newConn(nil)
	c.SetRateLimit(1, time.Second)

	// First frame is a text message — should pass rate limit
	textFrame1 := buildFrame(0x1, true, true, []byte{0x11, 0x22, 0x33, 0x44}, []byte("ok"))
	// Second frame — this will cause rate limit to trigger
	textFrame2 := buildFrame(0x1, true, true, []byte{0x55, 0x66, 0x77, 0x88}, []byte("over"))
	c.conn.(*bufferConn).reader = bytes.NewReader(append(textFrame1, textFrame2...))

	// Read first message — should succeed
	msgType, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("first message: unexpected error: %v", err)
	}
	if msgType != 1 || string(data) != "ok" {
		t.Errorf("first message: expected type=1 data='ok', got type=%d data=%q", msgType, data)
	}

	// Read second message — should trigger rate limit
	_, _, err = c.ReadMessage()
	if err == nil {
		t.Fatal("expected rate limit error on second message")
	}
	if err.Error() != "websocket: rate limit exceeded" {
		t.Errorf("expected 'websocket: rate limit exceeded', got %q", err.Error())
	}

	// Verify that writeClose wrote a close frame to the underlying connection
	bc := c.conn.(*bufferConn)
	written := bc.writer.Bytes()
	if len(written) < 2 {
		t.Fatalf("expected close frame written, got %d bytes", len(written))
	}

	// First byte: FIN + close opcode (0x88)
	if written[0] != 0x88 {
		t.Errorf("expected close frame first byte 0x88, got 0x%02x", written[0])
	}

	// The payload should start with the close code 1008 (0x03F0)
	payloadLen := int(written[1])
	if payloadLen < 2 {
		t.Errorf("expected at least 2 bytes of close payload, got %d", payloadLen)
	}
	closeCode := binary.BigEndian.Uint16(written[2:4])
	if closeCode != 1008 {
		t.Errorf("expected close code 1008, got %d", closeCode)
	}

	// The reason string should be "rate limit exceeded"
	reason := string(written[4 : 2+payloadLen])
	if reason != "rate limit exceeded" {
		t.Errorf("expected reason 'rate limit exceeded', got %q", reason)
	}
}

// ============================================================================
// SetWriteDeadline
// ============================================================================

func TestSetWriteDeadline_NoNetConn(t *testing.T) {
	// bufferConn does not implement net.Conn, so SetWriteDeadline should fail
	c := newConn([]byte{})
	err := c.SetWriteDeadline(time.Now().Add(time.Second))
	if err == nil {
		t.Error("expected error when underlying conn does not support deadlines")
	}
	if err != nil && err.Error() != "websocket: underlying connection does not support deadlines" {
		t.Errorf("unexpected error: %v", err)
	}
}

// ============================================================================
// Rate limit via ReadMessage — fragmented message
// ============================================================================

func TestReadMessage_FragmentedRateLimit(t *testing.T) {
	// Test that rate limiting works for reassembled fragmented messages
	c := newConn(nil)
	c.SetRateLimit(1, time.Second)

	// First message: fragmented text in two frames
	frag1 := buildFrame(0x1, false, true, []byte{0xAA, 0xBB, 0xCC, 0xDD}, []byte("hel"))
	frag2 := buildFrame(0x0, true, true, []byte{0x11, 0x22, 0x33, 0x44}, []byte("lo"))
	// Second complete message — will exceed rate limit
	textFrame := buildFrame(0x1, true, true, []byte{0x55, 0x66, 0x77, 0x88}, []byte("extra"))
	all := append(append(frag1, frag2...), textFrame...)
	c.conn.(*bufferConn).reader = bytes.NewReader(all)

	// First message (fragmented "hello") should succeed
	msgType, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("fragmented message: unexpected error: %v", err)
	}
	if msgType != 1 || string(data) != "hello" {
		t.Errorf("fragmented message: expected type=1 data='hello', got type=%d data=%q", msgType, data)
	}

	// Second message should trigger rate limit
	_, _, err = c.ReadMessage()
	if err == nil || err.Error() != "websocket: rate limit exceeded" {
		t.Errorf("expected rate limit error, got %v", err)
	}
}

// ============================================================================
// writeClose — direct unit test
// ============================================================================

func TestWriteClose_DirectCall(t *testing.T) {
	buf := &bytes.Buffer{}
	c := &Conn{conn: &bufferConn{
		reader: strings.NewReader(""),
		writer: buf,
	}}

	c.writeClose(1000, "normal closure")

	written := buf.Bytes()
	if len(written) < 4 {
		t.Fatalf("expected close frame, got %d bytes: %x", len(written), written)
	}

	// FIN + close opcode
	if written[0] != 0x88 {
		t.Errorf("expected first byte 0x88, got 0x%02x", written[0])
	}

	// Payload length
	payloadLen := int(written[1])
	expectedPayload := 2 + len("normal closure")
	if payloadLen != expectedPayload {
		t.Errorf("expected payload length %d, got %d", expectedPayload, payloadLen)
	}

	// Close code
	code := binary.BigEndian.Uint16(written[2:4])
	if code != 1000 {
		t.Errorf("expected close code 1000, got %d", code)
	}

	// Reason
	reason := string(written[4 : 2+payloadLen])
	if reason != "normal closure" {
		t.Errorf("expected reason 'normal closure', got %q", reason)
	}
}

func TestWriteClose_InvalidCodeRejected(t *testing.T) {
	buf := &bytes.Buffer{}
	c := &Conn{conn: &bufferConn{
		reader: strings.NewReader(""),
		writer: buf,
	}}

	err := c.writeClose(1006, "")
	if err == nil || err.Error() != "websocket: invalid close code" {
		t.Fatalf("expected invalid close code error, got %v", err)
	}

	if written := buf.Bytes(); len(written) != 0 {
		t.Fatalf("expected no close frame for invalid code, got %x", written)
	}
}

func TestWriteClose_InvalidReasonRejected(t *testing.T) {
	buf := &bytes.Buffer{}
	c := &Conn{conn: &bufferConn{
		reader: strings.NewReader(""),
		writer: buf,
	}}

	err := c.writeClose(1000, string([]byte{0xFF}))
	if err == nil || err.Error() != "websocket: invalid close reason" {
		t.Fatalf("expected invalid close reason error, got %v", err)
	}

	if written := buf.Bytes(); len(written) != 0 {
		t.Fatalf("expected no close frame for invalid reason, got %x", written)
	}
}

func TestWriteClose_LongReason(t *testing.T) {
	buf := &bytes.Buffer{}
	c := &Conn{conn: &bufferConn{
		reader: strings.NewReader(""),
		writer: buf,
	}}

	// Close frames are control frames; RFC 6455 limits control payloads to
	// 125 bytes, including the 2-byte close code.
	longReason := strings.Repeat("x", 200)
	c.writeClose(1011, longReason)

	written := buf.Bytes()
	if written[0] != 0x88 {
		t.Errorf("expected close opcode, got 0x%02x", written[0])
	}
	if written[1] != 125 {
		t.Errorf("expected control payload length 125, got %d", written[1])
	}
	code := binary.BigEndian.Uint16(written[2:4])
	if code != 1011 {
		t.Errorf("expected close code 1011, got %d", code)
	}
	reason := string(written[4:])
	if reason != strings.Repeat("x", 123) {
		t.Errorf("reason length = %d, want 123-byte truncation", len(reason))
	}
}

// ============================================================================
// Conn fragmented message reassembly (no rate limit)
// ============================================================================

func TestReadMessage_FragmentedText(t *testing.T) {
	// Two-fragment text message
	frag1 := buildClientFrame(0x1, false, []byte("foo"))
	frag2 := buildClientFrame(0x0, true, []byte("bar"))
	c := newConn(append(frag1, frag2...))

	msgType, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != 1 {
		t.Errorf("expected text type 1, got %d", msgType)
	}
	if string(data) != "foobar" {
		t.Errorf("expected 'foobar', got %q", string(data))
	}
}

func TestReadMessage_FragmentedInvalidTextRejected(t *testing.T) {
	frag1 := buildClientFrame(0x1, false, []byte("ok"))
	frag2 := buildClientFrame(0x0, true, []byte{0xFF})
	c := newConn(append(frag1, frag2...))

	_, _, err := c.ReadMessage()
	if err == nil || !strings.Contains(err.Error(), "invalid text payload") {
		t.Fatalf("ReadMessage error = %v, want invalid text payload", err)
	}

	bc := c.conn.(*bufferConn)
	written := bc.writer.Bytes()
	if len(written) < 4 {
		t.Fatalf("expected invalid-payload close frame, got %d bytes: %x", len(written), written)
	}
	if written[0] != 0x88 {
		t.Fatalf("expected close opcode, got 0x%02x", written[0])
	}
	if code := binary.BigEndian.Uint16(written[2:4]); code != 1007 {
		t.Fatalf("close code = %d, want 1007", code)
	}
}

func TestReadMessage_FragmentedBinary(t *testing.T) {
	// Two-fragment binary message
	frag1 := buildFrame(0x2, false, true, []byte{0xDE, 0xAD, 0xBE, 0xEF}, []byte{0x01, 0x02})
	frag2 := buildFrame(0x0, true, true, []byte{0xCA, 0xFE, 0xBA, 0xBE}, []byte{0x03, 0x04})
	c := newConn(append(frag1, frag2...))

	msgType, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != 2 {
		t.Errorf("expected binary type 2, got %d", msgType)
	}
	if !bytes.Equal(data, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Errorf("expected [1 2 3 4], got %v", data)
	}
}

func TestReadMessage_ThreeFragmentMessage(t *testing.T) {
	frag1 := buildClientFrame(0x1, false, []byte("a"))
	frag2 := buildClientFrame(0x0, false, []byte("b"))
	frag3 := buildClientFrame(0x0, true, []byte("c"))
	c := newConn(append(append(frag1, frag2...), frag3...))

	msgType, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != 1 {
		t.Errorf("expected type 1, got %d", msgType)
	}
	if string(data) != "abc" {
		t.Errorf("expected 'abc', got %q", string(data))
	}
}

// ============================================================================
// ReadMessage — continuation without prior fragment (protocol error)
// ============================================================================

func TestReadMessage_ContinuationWithoutPriorFragment(t *testing.T) {
	// A continuation frame arriving without a prior start frame is a protocol error.
	cont := buildClientFrame(0x0, true, []byte("orphan"))
	c := newConn(cont)

	_, _, err := c.ReadMessage()
	if err == nil || !strings.Contains(err.Error(), "unexpected continuation frame") {
		t.Fatalf("ReadMessage error = %v, want unexpected continuation frame", err)
	}

	bc := c.conn.(*bufferConn)
	written := bc.writer.Bytes()
	if len(written) < 4 {
		t.Fatalf("expected protocol-error close frame, got %d bytes: %x", len(written), written)
	}
	if written[0] != 0x88 {
		t.Fatalf("expected close opcode, got 0x%02x", written[0])
	}
	if code := binary.BigEndian.Uint16(written[2:4]); code != 1002 {
		t.Fatalf("close code = %d, want 1002", code)
	}
}

// ============================================================================
// ReadMessage — new data frame while already fragmenting (protocol error)
// ============================================================================

func TestReadMessage_NewFragmentStartWhileFragmenting(t *testing.T) {
	tests := []struct {
		name   string
		opcode byte
	}{
		{name: "text", opcode: 0x1},
		{name: "binary", opcode: 0x2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frag1 := buildClientFrame(0x1, false, []byte("dead"))
			frag2 := buildClientFrame(tt.opcode, true, []byte("live"))
			c := newConn(append(frag1, frag2...))

			_, _, err := c.ReadMessage()
			if err == nil || !strings.Contains(err.Error(), "fragmented message complete") {
				t.Fatalf("ReadMessage error = %v, want fragmented message complete", err)
			}

			bc := c.conn.(*bufferConn)
			written := bc.writer.Bytes()
			if len(written) < 4 {
				t.Fatalf("expected protocol-error close frame, got %d bytes: %x", len(written), written)
			}
			if written[0] != 0x88 {
				t.Fatalf("expected close opcode, got 0x%02x", written[0])
			}
			if code := binary.BigEndian.Uint16(written[2:4]); code != 1002 {
				t.Fatalf("close code = %d, want 1002", code)
			}
		})
	}
}

// ============================================================================
// Edge cases: readFrame with extended lengths
// ============================================================================

func TestReadFrame_16BitLength(t *testing.T) {
	// Build a frame with exactly 126 bytes payload (triggers 16-bit extended length)
	payload := make([]byte, 126)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	frame := buildClientFrame(0x2, true, payload)
	c := newConn(frame)

	_, opcode, data, err := c.readFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opcode != 0x2 {
		t.Errorf("expected opcode 0x2, got 0x%x", opcode)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("payload mismatch: expected %d bytes, got %d", len(payload), len(data))
	}
}

func TestReadFrame_64BitLength(t *testing.T) {
	// Build a frame that uses 64-bit extended length encoding
	// Use exactly 65536 bytes — the buildFrame helper will use 8-byte length
	payload := make([]byte, 65536)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	frame := buildClientFrame(0x1, true, payload)

	// This should exceed the 16KB max frame limit
	c := newConn(frame)
	_, _, _, err := c.readFrame()
	if err == nil || err.Error() != "websocket: frame too large" {
		t.Errorf("expected frame too large error for 64KB payload, got %v", err)
	}
}

// ============================================================================
// Rate limit + binary message
// ============================================================================

func TestReadMessage_BinaryRateLimit(t *testing.T) {
	c := newConn(nil)
	c.SetRateLimit(1, time.Second)

	bin1 := buildFrame(0x2, true, true, []byte{0x10, 0x20, 0x30, 0x40}, []byte{0xAA, 0xBB})
	bin2 := buildFrame(0x2, true, true, []byte{0x50, 0x60, 0x70, 0x80}, []byte{0xCC, 0xDD})
	c.conn.(*bufferConn).reader = bytes.NewReader(append(bin1, bin2...))

	msgType, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("first binary: unexpected error: %v", err)
	}
	if msgType != 2 || !bytes.Equal(data, []byte{0xAA, 0xBB}) {
		t.Errorf("first binary: unexpected result type=%d data=%v", msgType, data)
	}

	_, _, err = c.ReadMessage()
	if err == nil || err.Error() != "websocket: rate limit exceeded" {
		t.Errorf("expected rate limit error, got %v", err)
	}
}

// ============================================================================
// Handshake — origin validation via isOriginAllowed
// ============================================================================

func TestHandshake_OriginAllowed(t *testing.T) {
	// We can't fully test Handshake with a real hijack in a unit test,
	// but we can test the origin check paths that use isOriginAllowed.
	// The existing tests cover the rejection paths; verify that the
	// isOriginAllowed function is exercised through its unit tests above.

	// Additional integration: verify that Handshake rejects unknown origins
	// when an allowed list is configured (this uses isOriginAllowed internally).
	// Note: Handshake will fail before getting to origin check because the
	// httptest.ResponseRecorder doesn't support Hijack, but for the origin
	// path we need the WebSocket headers set first.
	// The existing test TestHandshake_NotWebSocketRequest covers the early return.
	// Here we test the origin rejection path specifically:
	t.Run("origin_rejected_with_allowed_list", func(t *testing.T) {
		// This test verifies the path through Handshake where:
		// 1. Request IS a WebSocket request (passes IsWebSocketRequest)
		// 2. Origin header IS set
		// 3. Allowed origins ARE configured
		// 4. Origin does NOT match → isOriginAllowed returns false
		// The test will fail at the Hijack step but AFTER the origin check.
		// However, since the error from origin check returns before Hijack,
		// we should see the origin error.
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/ws", nil)
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		r.Header.Set("Sec-WebSocket-Version", "13")
		r.Header.Set("Origin", "https://evil.com")

		conn, err := Handshake(w, r, "https://good.com")
		if conn != nil {
			t.Error("expected nil conn")
		}
		if err == nil {
			t.Error("expected error for mismatched origin")
		}
		if !strings.Contains(err.Error(), "origin not allowed") {
			t.Errorf("expected origin error, got: %v", err)
		}
		if w.Code != 403 {
			t.Errorf("expected 403, got %d", w.Code)
		}
	})
}

func TestHandshake_OriginAllowedExact(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Origin", "https://good.com")

	// Origin matches — but Handshake will fail at Hijack since
	// httptest.ResponseRecorder doesn't implement http.Hijacker.
	// The origin check should pass, so we should get a different error.
	conn, err := Handshake(w, r, "https://good.com")
	if conn != nil {
		t.Error("expected nil conn (no hijack support)")
	}
	// Error should be about hijack, not about origin
	if err == nil {
		t.Error("expected error (no hijack support)")
	}
	if err != nil && strings.Contains(err.Error(), "origin") {
		t.Errorf("origin should have passed, but got origin error: %v", err)
	}
}

// ============================================================================
// Conn.SetReadDeadline and SetWriteDeadline consistency
// ============================================================================

func TestSetReadDeadline_ErrorMessage(t *testing.T) {
	c := newConn([]byte{})
	err := c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err == nil {
		t.Error("expected error for non-net.Conn underlying connection")
	}
	expected := "websocket: underlying connection does not support deadlines"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestSetWriteDeadline_ErrorMessage(t *testing.T) {
	c := newConn([]byte{})
	err := c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err == nil {
		t.Error("expected error for non-net.Conn underlying connection")
	}
	expected := "websocket: underlying connection does not support deadlines"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

// ============================================================================
// Handshake — no allowed origins configured, cross-origin present (fail-closed)
// ============================================================================

func TestHandshake_NoAllowedOriginsWithOriginHeader(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Origin", "https://example.com")

	conn, err := Handshake(w, r) // no allowed origins
	if conn != nil {
		t.Error("expected nil conn")
	}
	if err == nil {
		t.Error("expected error for cross-origin request")
	}
	if !strings.Contains(err.Error(), "origin not allowed") {
		t.Errorf("expected 'origin not allowed' error, got: %v", err)
	}
	if w.Code != 403 {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestHandshake_NoAllowedOriginsSameOriginHeader(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://example.com/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Origin", "http://example.com")

	conn, err := Handshake(w, r) // no allowed origins
	if conn != nil {
		t.Error("expected nil conn (no hijack)")
	}
	if err != nil && strings.Contains(err.Error(), "origin") {
		t.Errorf("same-origin request should pass origin check, got: %v", err)
	}
}

// ============================================================================
// Handshake — no Origin header (allowed to proceed)
// ============================================================================

func TestHandshake_NoOriginHeader(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	r.Header.Set("Sec-WebSocket-Version", "13")
	// No Origin header — should proceed past origin check

	conn, err := Handshake(w, r)
	if conn != nil {
		t.Error("expected nil conn (no hijack)")
	}
	// Should fail at hijack, not at origin
	if err != nil && strings.Contains(err.Error(), "origin") {
		t.Errorf("origin check should have been skipped, got: %v", err)
	}
}

// ============================================================================
// Errors package consistency
// ============================================================================

func TestErrNotWebSocket(t *testing.T) {
	if !errors.Is(ErrNotWebSocket, ErrNotWebSocket) {
		t.Error("ErrNotWebSocket should be detectable via errors.Is")
	}
	if ErrNotWebSocket.Error() != "websocket: not a websocket request" {
		t.Errorf("unexpected error string: %q", ErrNotWebSocket.Error())
	}
}
