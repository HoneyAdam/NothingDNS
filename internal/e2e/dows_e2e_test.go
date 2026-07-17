package e2e

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/doh"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

// Minimal hand-rolled RFC 6455 WebSocket client for e2e testing.
// The internal/websocket package only implements the server side and the
// project forbids external dependencies, so the tests speak the wire
// protocol directly: HTTP/1.1 Upgrade handshake + masked client frames.

const wsTestGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type wsTestClient struct {
	conn net.Conn
	br   *bufio.Reader
}

// dialWSTest performs a TCP connect and RFC 6455 opening handshake against
// hostport/path, validating the 101 status and Sec-WebSocket-Accept value.
func dialWSTest(t *testing.T, hostport, path string) *wsTestClient {
	t.Helper()

	conn, err := net.DialTimeout("tcp", hostport, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", hostport, err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	request := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n",
		path, hostport, key)
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	br := bufio.NewReader(conn)
	tp := textproto.NewReader(br)

	statusLine, err := tp.ReadLine()
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("expected 101 Switching Protocols, got %q", statusLine)
	}

	headers, err := tp.ReadMIMEHeader()
	if err != nil {
		t.Fatalf("read handshake headers: %v", err)
	}
	if got := headers.Get("Upgrade"); !strings.EqualFold(got, "websocket") {
		t.Errorf("Upgrade header = %q, want websocket", got)
	}

	// RFC 6455 §4.2.2: Sec-WebSocket-Accept = base64(SHA1(key + GUID)).
	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte(wsTestGUID))
	wantAccept := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if got := headers.Get("Sec-Websocket-Accept"); got != wantAccept {
		t.Fatalf("Sec-WebSocket-Accept = %q, want %q", got, wantAccept)
	}

	return &wsTestClient{conn: conn, br: br}
}

// writeFrame sends a single masked client frame (RFC 6455 §5.2 requires all
// client-to-server frames to be masked).
func (c *wsTestClient) writeFrame(opcode byte, payload []byte) error {
	var header []byte
	switch {
	case len(payload) < 126:
		header = []byte{0x80 | opcode, 0x80 | byte(len(payload))}
	case len(payload) <= 0xffff:
		header = []byte{0x80 | opcode, 0x80 | 126, byte(len(payload) >> 8), byte(len(payload))}
	default:
		return fmt.Errorf("test frame too large: %d", len(payload))
	}

	mask := make([]byte, 4)
	if _, err := rand.Read(mask); err != nil {
		return err
	}
	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}

	frame := make([]byte, 0, len(header)+4+len(masked))
	frame = append(frame, header...)
	frame = append(frame, mask...)
	frame = append(frame, masked...)
	_, err := c.conn.Write(frame)
	return err
}

// readFrame reads a single unmasked server frame and returns opcode + payload.
func (c *wsTestClient) readFrame() (byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.br, header); err != nil {
		return 0, nil, err
	}
	if header[1]&0x80 != 0 {
		return 0, nil, fmt.Errorf("server frame must not be masked (RFC 6455 §5.1)")
	}
	opcode := header[0] & 0x0F
	payloadLen := int(header[1] & 0x7F)
	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(c.br, ext); err != nil {
			return 0, nil, err
		}
		payloadLen = int(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(c.br, ext); err != nil {
			return 0, nil, err
		}
		payloadLen = int(binary.BigEndian.Uint64(ext))
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return 0, nil, err
	}
	return opcode, payload, nil
}

// queryDNS sends a packed DNS query as a binary frame and returns the
// unpacked DNS response from the next binary frame.
func (c *wsTestClient) queryDNS(t *testing.T, query *protocol.Message) *protocol.Message {
	t.Helper()

	buf := make([]byte, query.WireLength())
	n, err := query.Pack(buf)
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	if err := c.writeFrame(2, buf[:n]); err != nil {
		t.Fatalf("write binary frame: %v", err)
	}

	if err := c.conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	opcode, payload, err := c.readFrame()
	if err != nil {
		t.Fatalf("read response frame: %v", err)
	}
	if opcode != 2 {
		t.Fatalf("expected binary frame (opcode 2), got opcode %d", opcode)
	}

	resp, err := protocol.UnpackMessage(payload)
	if err != nil {
		t.Fatalf("unpack DNS response: %v", err)
	}
	return resp
}

// startDoWSTestServer serves doh.NewWSHandler over a real httptest HTTP
// server and returns its host:port.
func startDoWSTestServer(t *testing.T, handler server.Handler) string {
	t.Helper()
	ts := httptest.NewServer(doh.NewWSHandler(handler, nil))
	t.Cleanup(ts.Close)
	return strings.TrimPrefix(ts.URL, "http://")
}

// TestDoWSEndToEnd exercises DNS-over-WebSocket end to end: a real RFC 6455
// opening handshake against doh.NewWSHandler, a masked binary frame carrying
// a DNS query, and a binary frame carrying the DNS response.
func TestDoWSEndToEnd(t *testing.T) {
	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: req.Questions,
		}
		if len(req.Questions) > 0 && req.Questions[0].QType == protocol.TypeA {
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  req.Questions[0].Name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 53}},
			})
		}
		w.Write(resp)
	})

	hostport := startDoWSTestServer(t, handler)
	client := dialWSTest(t, hostport, "/dns-query")

	query, err := protocol.NewQuery(0x77aa, "ws.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}

	resp := client.queryDNS(t, query)

	if resp.Header.ID != 0x77aa {
		t.Errorf("response ID = %#x, want 0x77aa", resp.Header.ID)
	}
	if !resp.Header.Flags.QR {
		t.Error("expected QR flag set in response")
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
	}
	a, ok := resp.Answers[0].Data.(*protocol.RDataA)
	if !ok {
		t.Fatalf("expected RDataA, got %T", resp.Answers[0].Data)
	}
	if a.Address != [4]byte{192, 0, 2, 53} {
		t.Errorf("A record = %v, want 192.0.2.53", a.Address)
	}

	// Clean close: masked close frame with status code 1000 (normal closure).
	closePayload := []byte{0x03, 0xE8}
	if err := client.writeFrame(8, closePayload); err != nil {
		t.Fatalf("write close frame: %v", err)
	}
}

// TestDoWSMultipleQueriesAndNonBinaryFrames verifies that a single WebSocket
// connection carries multiple DNS queries and that non-binary (text) frames
// are skipped by the DoWS handler rather than breaking the session.
func TestDoWSMultipleQueriesAndNonBinaryFrames(t *testing.T) {
	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: req.Questions,
		}
		if len(req.Questions) > 0 {
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  req.Questions[0].Name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   60,
				Data:  &protocol.RDataA{Address: [4]byte{198, 51, 100, 1}},
			})
		}
		w.Write(resp)
	})

	hostport := startDoWSTestServer(t, handler)
	client := dialWSTest(t, hostport, "/dns-query")

	// A text frame is not a DNS query; the handler must skip it.
	if err := client.writeFrame(1, []byte("not dns")); err != nil {
		t.Fatalf("write text frame: %v", err)
	}

	for i, domain := range []string{"one.example.com.", "two.example.com.", "three.example.com."} {
		id := uint16(0x1000 + i)
		query, err := protocol.NewQuery(id, domain, protocol.TypeA)
		if err != nil {
			t.Fatalf("NewQuery(%q): %v", domain, err)
		}
		resp := client.queryDNS(t, query)

		if resp.Header.ID != id {
			t.Errorf("%s: response ID = %#x, want %#x", domain, resp.Header.ID, id)
		}
		if len(resp.Questions) != 1 || resp.Questions[0].Name.String() != domain {
			t.Errorf("%s: question section not echoed correctly: %+v", domain, resp.Questions)
		}
		if len(resp.Answers) != 1 {
			t.Errorf("%s: expected 1 answer, got %d", domain, len(resp.Answers))
		}
	}
}
