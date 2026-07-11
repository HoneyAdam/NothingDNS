package websocket

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// IsWebSocketRequest
// ============================================================================

func TestIsWebSocketRequest_Valid(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	if !IsWebSocketRequest(r) {
		t.Error("expected valid WebSocket request")
	}
}

func TestIsWebSocketRequest_CaseInsensitive(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "WebSocket")
	r.Header.Set("Connection", "keep-alive, upgrade")
	if !IsWebSocketRequest(r) {
		t.Error("expected case-insensitive match")
	}
}

func TestIsWebSocketRequest_ConnectionTokenExactMatch(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "keep-alive, notupgrade")
	if IsWebSocketRequest(r) {
		t.Error("expected false when Connection lacks exact upgrade token")
	}
}

func TestIsWebSocketRequest_RequiresGET(t *testing.T) {
	r := httptest.NewRequest("POST", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	if IsWebSocketRequest(r) {
		t.Error("expected false for non-GET WebSocket request")
	}
}

func TestIsWebSocketRequest_MissingUpgrade(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Connection", "Upgrade")
	if IsWebSocketRequest(r) {
		t.Error("expected false with missing Upgrade header")
	}
}

func TestIsWebSocketRequest_MissingConnection(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	if IsWebSocketRequest(r) {
		t.Error("expected false with missing Connection header")
	}
}

func TestIsWebSocketRequest_Neither(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws", nil)
	if IsWebSocketRequest(r) {
		t.Error("expected false with no relevant headers")
	}
}

// ============================================================================
// readFrame / ReadMessage — frame parsing
// ============================================================================

// buildFrame constructs a WebSocket frame. If masked, applies XOR mask.
func buildFrame(opcode byte, fin bool, mask bool, maskKey []byte, payload []byte) []byte {
	var buf []byte
	firstByte := opcode & 0x0F
	if fin {
		firstByte |= 0x80
	}
	buf = append(buf, firstByte)

	length := len(payload)
	secondByte := byte(0)
	if mask {
		secondByte |= 0x80
	}

	switch {
	case length <= 125:
		buf = append(buf, secondByte|byte(length))
	case length <= 65535:
		buf = append(buf, secondByte|126)
		buf = append(buf, byte(length>>8), byte(length))
	default:
		buf = append(buf, secondByte|127)
		for i := 7; i >= 0; i-- {
			buf = append(buf, byte(length>>(i*8)))
		}
	}

	if mask {
		buf = append(buf, maskKey...)
		for i, b := range payload {
			buf = append(buf, b^maskKey[i%4])
		}
	} else {
		buf = append(buf, payload...)
	}

	return buf
}

func buildClientFrame(opcode byte, fin bool, payload []byte) []byte {
	return buildFrame(opcode, fin, true, []byte{0x01, 0x02, 0x03, 0x04}, payload)
}

type bufferConn struct {
	reader    io.Reader
	writer    *bytes.Buffer
	writeMax  int
	writeCall int
	writeErr  error
}

func (bc *bufferConn) Read(p []byte) (int, error) { return bc.reader.Read(p) }
func (bc *bufferConn) Write(p []byte) (int, error) {
	bc.writeCall++
	if bc.writeErr != nil {
		return 0, bc.writeErr
	}
	if bc.writeMax > 0 && bc.writeMax < len(p) {
		p = p[:bc.writeMax]
	}
	return bc.writer.Write(p)
}
func (bc *bufferConn) Close() error { return nil }

func newConn(data []byte) *Conn {
	return &Conn{conn: &bufferConn{
		reader: bytes.NewReader(data),
		writer: &bytes.Buffer{},
	}}
}

func TestReadFrame_SmallPayload(t *testing.T) {
	payload := []byte("hello")
	mask := []byte{0x37, 0xfa, 0x21, 0x3d}
	frame := buildFrame(0x1, true, true, mask, payload)
	c := newConn(frame)

	_, opcode, data, err := c.readFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opcode != 0x1 {
		t.Errorf("expected opcode 0x1, got 0x%x", opcode)
	}
	if string(data) != "hello" {
		t.Errorf("expected 'hello', got %q", string(data))
	}
}

func TestReadFrame_EmptyPayload(t *testing.T) {
	frame := buildClientFrame(0x1, true, []byte{})
	c := newConn(frame)

	_, opcode, data, err := c.readFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opcode != 0x1 {
		t.Errorf("expected opcode 0x1, got 0x%x", opcode)
	}
	if len(data) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(data))
	}
}

func TestReadFrame_ReservedBitsRejected(t *testing.T) {
	tests := []struct {
		name      string
		firstByte byte
	}{
		{name: "rsv1", firstByte: 0x80 | 0x40 | 0x1},
		{name: "rsv2", firstByte: 0x80 | 0x20 | 0x1},
		{name: "rsv3", firstByte: 0x80 | 0x10 | 0x1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := []byte{tt.firstByte, 0x80, 0x01, 0x02, 0x03, 0x04}
			c := newConn(frame)

			_, _, _, err := c.readFrame()
			if err == nil || err.Error() != "websocket: reserved bits set" {
				t.Fatalf("expected reserved bits set error, got %v", err)
			}
		})
	}
}

func TestReadFrame_MediumPayload(t *testing.T) {
	payload := make([]byte, 200)
	for i := range payload {
		payload[i] = byte(i)
	}
	frame := buildFrame(0x2, true, true, []byte{0xAA, 0xBB, 0xCC, 0xDD}, payload)
	c := newConn(frame)

	_, opcode, data, err := c.readFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opcode != 0x2 {
		t.Errorf("expected opcode 0x2, got 0x%x", opcode)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("payload mismatch: expected %d bytes, got %d bytes", len(payload), len(data))
	}
}

func TestReadFrame_NonMinimal16BitLengthRejected(t *testing.T) {
	mask := []byte{0x37, 0xfa, 0x21, 0x3d}
	payload := []byte("hello")
	frame := []byte{0x81, 0x80 | 126, 0x00, byte(len(payload))}
	frame = append(frame, mask...)
	for i, b := range payload {
		frame = append(frame, b^mask[i%4])
	}
	c := newConn(frame)

	_, _, _, err := c.readFrame()
	if err == nil || err.Error() != "websocket: non-minimal payload length" {
		t.Fatalf("expected non-minimal payload length error, got %v", err)
	}
}

func TestReadFrame_NonMinimal64BitLengthRejected(t *testing.T) {
	mask := []byte{0x37, 0xfa, 0x21, 0x3d}
	payload := make([]byte, 126)
	frame := []byte{0x82, 0x80 | 127, 0, 0, 0, 0, 0, 0, 0, byte(len(payload))}
	frame = append(frame, mask...)
	for i, b := range payload {
		frame = append(frame, b^mask[i%4])
	}
	c := newConn(frame)

	_, _, _, err := c.readFrame()
	if err == nil || err.Error() != "websocket: non-minimal payload length" {
		t.Fatalf("expected non-minimal payload length error, got %v", err)
	}
}

func TestReadFrame_LargePayload(t *testing.T) {
	// Test that a payload within the 16KB limit can be read
	payload := make([]byte, 15*1024) // 15KB — under the 16KB limit
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	frame := buildClientFrame(0x1, true, payload)
	c := newConn(frame)

	_, opcode, data, err := c.readFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opcode != 0x1 {
		t.Errorf("expected opcode 0x1, got 0x%x", opcode)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("payload mismatch")
	}
}

func TestReadFrame_TooLarge(t *testing.T) {
	// Build a frame claiming > 16KB payload
	buf := []byte{0x81, 0x80 | 0x7E} // FIN + text, masked, 126 = 16-bit length
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, 16*1024+1) // 16KB + 1
	buf = append(buf, lenBytes...)

	c := newConn(buf)
	_, _, _, err := c.readFrame()
	if err == nil || err.Error() != "websocket: frame too large" {
		t.Errorf("expected frame too large error, got %v", err)
	}
}

func TestReadFrame_TruncatedHeader(t *testing.T) {
	c := newConn([]byte{0x81}) // Only 1 byte, need 2
	_, _, _, err := c.readFrame()
	if err == nil {
		t.Error("expected error for truncated header")
	}
}

func TestReadFrame_UnmaskedPayload(t *testing.T) {
	payload := []byte("test data")
	frame := buildFrame(0x1, true, false, nil, payload)
	c := newConn(frame)

	_, _, _, err := c.readFrame()
	if err == nil || err.Error() != "websocket: client frame not masked" {
		t.Fatalf("expected client frame not masked error, got %v", err)
	}
}

func TestReadFrame_FragmentedControlFrameRejected(t *testing.T) {
	frame := buildClientFrame(0x9, false, []byte("ping"))
	c := newConn(frame)

	_, _, _, err := c.readFrame()
	if err == nil || err.Error() != "websocket: fragmented control frame" {
		t.Fatalf("expected fragmented control frame error, got %v", err)
	}
}

func TestReadFrame_OversizedControlFrameRejected(t *testing.T) {
	frame := buildClientFrame(0x8, true, bytes.Repeat([]byte("x"), 126))
	c := newConn(frame)

	_, _, _, err := c.readFrame()
	if err == nil || err.Error() != "websocket: control frame too large" {
		t.Fatalf("expected control frame too large error, got %v", err)
	}
}

func TestReadFrame_InvalidCloseFramePayloadRejected(t *testing.T) {
	frame := buildClientFrame(0x8, true, []byte{0x03})
	c := newConn(frame)

	_, _, _, err := c.readFrame()
	if err == nil || err.Error() != "websocket: invalid close frame payload" {
		t.Fatalf("expected invalid close frame payload error, got %v", err)
	}
}

func TestReadFrame_InvalidCloseCodeRejected(t *testing.T) {
	tests := []struct {
		name string
		code uint16
	}{
		{name: "below-range", code: 999},
		{name: "reserved-1004", code: 1004},
		{name: "no-status", code: 1005},
		{name: "abnormal-closure", code: 1006},
		{name: "tls-failure", code: 1015},
		{name: "reserved-extension-range", code: 2000},
		{name: "above-range", code: 5000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := make([]byte, 2)
			binary.BigEndian.PutUint16(payload, tt.code)
			frame := buildClientFrame(0x8, true, payload)
			c := newConn(frame)

			_, _, _, err := c.readFrame()
			if err == nil || err.Error() != "websocket: invalid close code" {
				t.Fatalf("expected invalid close code error, got %v", err)
			}
		})
	}
}

func TestReadFrame_InvalidCloseReasonRejected(t *testing.T) {
	payload := []byte{0x03, 0xE8, 0xFF}
	frame := buildClientFrame(0x8, true, payload)
	c := newConn(frame)

	_, _, _, err := c.readFrame()
	if err == nil || err.Error() != "websocket: invalid close reason" {
		t.Fatalf("expected invalid close reason error, got %v", err)
	}
}

// ============================================================================
// WriteMessage
// ============================================================================

func TestWriteMessage_SmallPayload(t *testing.T) {
	buf := &bytes.Buffer{}
	c := &Conn{conn: &bufferConn{reader: strings.NewReader(""), writer: buf}}

	err := c.WriteMessage(1, []byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data := buf.Bytes()
	// FIN + opcode 1
	if data[0] != 0x81 {
		t.Errorf("expected first byte 0x81, got 0x%x", data[0])
	}
	// Length = 5, no mask
	if data[1] != 5 {
		t.Errorf("expected length 5, got %d", data[1])
	}
	if string(data[2:]) != "hello" {
		t.Errorf("expected 'hello', got %q", string(data[2:]))
	}
}

func TestWriteMessage_MediumPayload(t *testing.T) {
	buf := &bytes.Buffer{}
	c := &Conn{conn: &bufferConn{reader: strings.NewReader(""), writer: buf}}

	payload := make([]byte, 200)
	err := c.WriteMessage(2, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data := buf.Bytes()
	// FIN + opcode 2
	if data[0] != 0x82 {
		t.Errorf("expected first byte 0x82, got 0x%x", data[0])
	}
	// Extended length marker
	if data[1] != 126 {
		t.Errorf("expected 126 length marker, got %d", data[1])
	}
	// 16-bit length
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length != 200 {
		t.Errorf("expected length 200, got %d", length)
	}
}

func TestWriteMessage_CompletesPartialWrites(t *testing.T) {
	buf := &bytes.Buffer{}
	conn := &bufferConn{reader: strings.NewReader(""), writer: buf, writeMax: 2}
	c := &Conn{conn: conn}

	if err := c.WriteMessage(1, []byte("hello")); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	if conn.writeCall < 2 {
		t.Fatalf("partial writer should require multiple writes, got %d", conn.writeCall)
	}

	data := buf.Bytes()
	if len(data) != 7 {
		t.Fatalf("wire length = %d, want 7", len(data))
	}
	if data[0] != 0x81 || data[1] != 5 || string(data[2:]) != "hello" {
		t.Fatalf("wire frame = %x, want text frame with hello", data)
	}
}

func TestWriteMessage_RejectsInvalidMessageTypes(t *testing.T) {
	tests := []struct {
		name        string
		messageType int
		payload     []byte
		want        string
	}{
		{name: "continuation", messageType: 0x0, want: "invalid message type"},
		{name: "reserved", messageType: 0x3, want: "invalid message type"},
		{name: "oversized control", messageType: 0x9, payload: make([]byte, 126), want: "control frame too large"},
		{name: "invalid close payload", messageType: 0x8, payload: []byte{0x03}, want: "invalid close frame payload"},
		{name: "invalid close code", messageType: 0x8, payload: []byte{0x03, 0xEE}, want: "invalid close code"},
		{name: "invalid close reason", messageType: 0x8, payload: []byte{0x03, 0xE8, 0xFF}, want: "invalid close reason"},
		{name: "invalid text payload", messageType: 0x1, payload: []byte{0xFF}, want: "invalid text payload"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			c := &Conn{conn: &bufferConn{reader: strings.NewReader(""), writer: buf}}

			err := c.WriteMessage(tt.messageType, tt.payload)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("WriteMessage error = %v, want %q", err, tt.want)
			}
			if buf.Len() != 0 {
				t.Fatalf("WriteMessage wrote %d bytes for invalid frame", buf.Len())
			}
		})
	}
}

func TestWriteMessage_LargePayload(t *testing.T) {
	buf := &bytes.Buffer{}
	c := &Conn{conn: &bufferConn{reader: strings.NewReader(""), writer: buf}}

	payload := make([]byte, 70000)
	err := c.WriteMessage(1, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data := buf.Bytes()
	if data[0] != 0x81 {
		t.Errorf("expected first byte 0x81, got 0x%x", data[0])
	}
	if data[1] != 127 {
		t.Errorf("expected 127 length marker, got %d", data[1])
	}
	length := int(binary.BigEndian.Uint64(data[2:10]))
	if length != 70000 {
		t.Errorf("expected length 70000, got %d", length)
	}
}

func TestWriteMessage_Empty(t *testing.T) {
	buf := &bytes.Buffer{}
	c := &Conn{conn: &bufferConn{reader: strings.NewReader(""), writer: buf}}

	err := c.WriteMessage(1, []byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data := buf.Bytes()
	if data[0] != 0x81 {
		t.Errorf("expected first byte 0x81, got 0x%x", data[0])
	}
	if data[1] != 0 {
		t.Errorf("expected length 0, got %d", data[1])
	}
	if len(data) != 2 {
		t.Errorf("expected 2 bytes total, got %d", len(data))
	}
}

// ============================================================================
// ReadMessage — control frame handling
// ============================================================================

func TestReadMessage_PingAutoPong(t *testing.T) {
	pingFrame := buildClientFrame(0x9, true, []byte("ping"))
	// Follow with a text frame so ReadMessage returns
	textFrame := buildFrame(0x1, true, true, []byte{1, 2, 3, 4}, []byte("data"))
	c := newConn(append(pingFrame, textFrame...))

	msgType, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != 1 {
		t.Errorf("expected text message type 1, got %d", msgType)
	}
	if string(data) != "data" {
		t.Errorf("expected 'data', got %q", string(data))
	}

	// Check that pong was written
	bc := c.conn.(*bufferConn)
	pong := bc.writer.Bytes()
	if len(pong) < 2 {
		t.Fatal("expected pong frame to be written")
	}
	if pong[0]&0x0F != 0xA {
		t.Errorf("expected pong opcode 0xA, got 0x%x", pong[0]&0x0F)
	}
}

func TestReadMessage_PingPongWriteError(t *testing.T) {
	pingFrame := buildClientFrame(0x9, true, []byte("ping"))
	writeErr := errors.New("pong write failed")
	c := &Conn{conn: &bufferConn{
		reader:   bytes.NewReader(pingFrame),
		writer:   &bytes.Buffer{},
		writeErr: writeErr,
	}}

	_, _, err := c.ReadMessage()
	if !errors.Is(err, writeErr) {
		t.Fatalf("ReadMessage error = %v, want %v", err, writeErr)
	}
}

func TestReadMessage_InvalidOpcodeRejected(t *testing.T) {
	frame := buildClientFrame(0x3, true, nil)
	c := newConn(frame)

	_, _, err := c.ReadMessage()
	if err == nil || !strings.Contains(err.Error(), "invalid opcode") {
		t.Fatalf("ReadMessage error = %v, want invalid opcode", err)
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

func TestReadMessage_InvalidTextPayloadRejected(t *testing.T) {
	frame := buildClientFrame(0x1, true, []byte{0xFF})
	c := newConn(frame)

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

func TestReadMessage_CloseWriteErrorIsReturned(t *testing.T) {
	frames := append(buildClientFrame(0x1, true, []byte("first")), buildClientFrame(0x1, true, []byte("second"))...)
	writeErr := errors.New("close write failed")
	c := &Conn{conn: &bufferConn{
		reader:   bytes.NewReader(frames),
		writer:   &bytes.Buffer{},
		writeErr: writeErr,
	}}
	c.SetRateLimit(1, time.Minute)

	if msgType, payload, err := c.ReadMessage(); err != nil || msgType != 1 || string(payload) != "first" {
		t.Fatalf("first ReadMessage = (%d, %q, %v), want text first", msgType, payload, err)
	}
	_, _, err := c.ReadMessage()
	if err == nil {
		t.Fatal("expected rate limit error")
	}
	if !strings.Contains(err.Error(), "rate limit exceeded") {
		t.Fatalf("ReadMessage error = %v, want rate limit context", err)
	}
	if !errors.Is(err, writeErr) {
		t.Fatalf("ReadMessage error = %v, want wrapped %v", err, writeErr)
	}
}

func TestReadMessage_PongDiscarded(t *testing.T) {
	pongFrame := buildClientFrame(0xA, true, []byte("pong"))
	textFrame := buildClientFrame(0x1, true, []byte("after"))
	c := newConn(append(pongFrame, textFrame...))

	msgType, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != 1 {
		t.Errorf("expected text message, got type %d", msgType)
	}
	if string(data) != "after" {
		t.Errorf("expected 'after', got %q", string(data))
	}
}

func TestReadMessage_CloseFrame(t *testing.T) {
	closeFrame := buildClientFrame(0x8, true, []byte{0x03, 0xE8}) // 1000
	c := newConn(closeFrame)

	msgType, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != 8 {
		t.Errorf("expected close type 8, got %d", msgType)
	}
	if len(data) != 2 {
		t.Errorf("expected 2-byte close payload, got %d", len(data))
	}
}

func TestReadMessage_BinaryMessage(t *testing.T) {
	payload := []byte{0x00, 0x01, 0x02, 0xFF}
	frame := buildClientFrame(0x2, true, payload)
	c := newConn(frame)

	msgType, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != 2 {
		t.Errorf("expected binary type 2, got %d", msgType)
	}
	if !bytes.Equal(data, payload) {
		t.Error("payload mismatch")
	}
}

// ============================================================================
// Round-trip: write then read
// ============================================================================

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	writer := &Conn{conn: &bufferConn{reader: strings.NewReader(""), writer: &buf}}

	original := []byte("round-trip test")
	if err := writer.WriteMessage(1, original); err != nil {
		t.Fatalf("write error: %v", err)
	}

	wireData := buf.Bytes()
	if len(wireData) < 2 {
		t.Fatalf("expected websocket frame, got %d bytes", len(wireData))
	}
	if wireData[0] != 0x81 {
		t.Errorf("expected FIN text frame 0x81, got 0x%x", wireData[0])
	}
	if wireData[1]&0x80 != 0 {
		t.Fatal("server-to-client frame must not be masked")
	}
	if int(wireData[1]&0x7F) != len(original) {
		t.Fatalf("expected payload length %d, got %d", len(original), wireData[1]&0x7F)
	}
	if !bytes.Equal(wireData[2:], original) {
		t.Errorf("expected %q, got %q", original, wireData[2:])
	}
}

// ============================================================================
// Masking edge cases
// ============================================================================

func TestMasking_NonAlignedPayload(t *testing.T) {
	// Payload length not multiple of 4 — tests mask wrapping
	payload := []byte{1, 2, 3, 4, 5, 6, 7} // 7 bytes
	mask := []byte{0xFF, 0x00, 0xFF, 0x00}

	frame := buildFrame(0x1, true, true, mask, payload)
	c := newConn(frame)

	_, _, data, err := c.readFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("masking roundtrip failed: expected %v, got %v", payload, data)
	}
}

// ============================================================================
// Handshake validation (without full HTTP hijack)
// ============================================================================

func TestHandshake_NotWebSocketRequest(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/ws", nil)

	conn, err := Handshake(w, r)
	if conn != nil {
		t.Error("expected nil conn")
	}
	if !errors.Is(err, ErrNotWebSocket) {
		t.Errorf("expected ErrNotWebSocket, got %v", err)
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandshake_MissingKey(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	// No Sec-WebSocket-Key

	conn, err := Handshake(w, r)
	if conn != nil {
		t.Error("expected nil conn")
	}
	if !errors.Is(err, ErrNotWebSocket) {
		t.Errorf("expected ErrNotWebSocket, got %v", err)
	}
}

func TestHandshake_InvalidKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{name: "not-base64", key: "not-base64"},
		{name: "wrong-length", key: base64.StdEncoding.EncodeToString([]byte("short"))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/ws", nil)
			r.Header.Set("Upgrade", "websocket")
			r.Header.Set("Connection", "Upgrade")
			r.Header.Set("Sec-WebSocket-Key", tt.key)

			conn, err := Handshake(w, r)
			if conn != nil {
				t.Error("expected nil conn")
			}
			if !errors.Is(err, ErrNotWebSocket) {
				t.Errorf("expected ErrNotWebSocket, got %v", err)
			}
			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", w.Code)
			}
		})
	}
}

func TestHandshake_InvalidVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{name: "missing", version: ""},
		{name: "unsupported", version: "12"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/ws", nil)
			r.Header.Set("Upgrade", "websocket")
			r.Header.Set("Connection", "Upgrade")
			r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			if tt.version != "" {
				r.Header.Set("Sec-WebSocket-Version", tt.version)
			}

			conn, err := Handshake(w, r)
			if conn != nil {
				t.Error("expected nil conn")
			}
			if !errors.Is(err, ErrNotWebSocket) {
				t.Errorf("expected ErrNotWebSocket, got %v", err)
			}
			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", w.Code)
			}
		})
	}
}

// ============================================================================
// Conn.Close
// ============================================================================

func TestConn_Close(t *testing.T) {
	c := newConn([]byte{})
	if err := c.Close(); err != nil {
		t.Errorf("unexpected close error: %v", err)
	}
}

// ============================================================================
// SetReadDeadline
// ============================================================================

func TestSetReadDeadline_NoNetConn(t *testing.T) {
	// bufferConn does not implement net.Conn, so SetReadDeadline should fail
	c := newConn([]byte{})
	err := c.SetReadDeadline(time.Now().Add(time.Second))
	if err == nil {
		t.Error("expected error when underlying conn does not support net.Conn")
	}
	if err != nil && err.Error() != "websocket: underlying connection does not support deadlines" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestReadFrame_ExtendedLength_RejectsHighBit regresses SECURITY-REPORT.md
// L-1. Frames with payload-length opcode 127 carry an 8-byte length;
// pre-fix readFrame did `payloadLen = int(binary.BigEndian.Uint64(ext))`
// which sign-flips negative on 64-bit platforms for any value ≥ 2^63.
// The downstream `if payloadLen > 16*1024` check then passes (negative
// is not greater than 16384) and `make([]byte, payloadLen)` panics
// "makeslice: len out of range" — a per-connection DoS that the
// outer http.Server recover would catch but still kill the WS.
//
// The fix bounds the raw uint64 against the frame cap BEFORE the
// int() narrowing, so any high-bit value (which RFC 6455 also
// requires be zero) is rejected cleanly with an error.
func TestReadFrame_ExtendedLength_RejectsHighBit(t *testing.T) {
	// Frame: FIN=1, opcode=binary, masked, length-marker=127,
	// extended length = 0x8000000000000001 (MSB set + small low byte
	// so that int(uint64) sign-flips to a small negative on 64-bit).
	frame := []byte{
		0x82,                                           // FIN + binary opcode
		0x80 | 127,                                     // length marker with mask bit
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // length = 2^63 + 1
	}
	c := newConn(frame)

	_, _, _, err := c.readFrame()
	if err == nil {
		t.Fatal("expected error for high-bit extended length, got nil")
	}
	if !strings.Contains(err.Error(), "frame too large") {
		t.Errorf("expected error to mention 'frame too large', got %v", err)
	}
}

func TestIsSameOrigin(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		tls    bool
		host   string
		want   bool
	}{
		{name: "http match", origin: "http://example.com", host: "example.com", want: true},
		{name: "https match", origin: "https://secure.com", tls: true, host: "secure.com", want: true},
		{name: "mismatch", origin: "http://evil.com", host: "example.com", want: false},
		{name: "port mismatch", origin: "http://example.com:8080", host: "example.com", want: false},
		{name: "https mismatch", origin: "http://example.com", tls: true, host: "example.com", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{Host: tc.host}
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			got := isSameOrigin(tc.origin, req)
			if got != tc.want {
				t.Errorf("isSameOrigin(%q) = %v, want %v", tc.origin, got, tc.want)
			}
		})
	}
}

func TestIsOriginAllowed(t *testing.T) {
	if !isOriginAllowed("http://example.com", []string{"http://example.com"}) {
		t.Error("should allow matching origin")
	}
	if isOriginAllowed("http://evil.com", []string{"http://example.com"}) {
		t.Error("should reject non-matching origin")
	}
	if isOriginAllowed("http://example.com", nil) {
		t.Error("should reject nil allowed list")
	}
	if isOriginAllowed("http://example.com", []string{}) {
		t.Error("should reject empty allowed list")
	}
	if !isOriginAllowed("http://example.com", []string{"http://other.com", "http://example.com"}) {
		t.Error("should allow origin in multi-entry list")
	}
}

func TestTruncateCloseReason(t *testing.T) {
	short := "normal close"
	got := truncateCloseReason(short)
	if got != short {
		t.Errorf("truncateCloseReason(%q) = %q, want %q", short, got, short)
	}
	if truncateCloseReason("") != "" {
		t.Error("truncateCloseReason('') should be empty")
	}
	long := string(make([]byte, 200))
	got = truncateCloseReason(long)
	if len(got) > 125 {
		t.Errorf("truncated len = %d, want <=125", len(got))
	}
}
