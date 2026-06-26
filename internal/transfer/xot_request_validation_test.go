package transfer

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestXoTServerHandleAXFRRequestRejectsNilQuestionName(t *testing.T) {
	srv := &XoTServer{
		zones:             map[string]*zone.Zone{},
		zonesMu:           &sync.RWMutex{},
		requireClientCert: true, // pass the access gate to reach nil-name validation
	}
	conn := &xotValidationConn{remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}
	req := &protocol.Message{
		Header: protocol.Header{ID: 0x1201},
		Questions: []*protocol.Question{
			{QType: protocol.TypeAXFR, QClass: protocol.ClassIN},
		},
	}

	srv.handleAXFRRequest(conn, req, net.ParseIP("127.0.0.1"))

	assertXoTErrorResponse(t, conn.Bytes(), 0x1201, protocol.RcodeFormatError)
}

func TestXoTServerHandleIXFRRequestRejectsNilQuestionName(t *testing.T) {
	srv := &XoTServer{
		zones:             map[string]*zone.Zone{},
		zonesMu:           &sync.RWMutex{},
		requireClientCert: true, // pass the access gate to reach nil-name validation
	}
	conn := &xotValidationConn{remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}
	req := &protocol.Message{
		Header: protocol.Header{ID: 0x1202},
		Questions: []*protocol.Question{
			{QType: protocol.TypeIXFR, QClass: protocol.ClassIN},
		},
	}

	srv.handleIXFRRequest(conn, req, net.ParseIP("127.0.0.1"))

	assertXoTErrorResponse(t, conn.Bytes(), 0x1202, protocol.RcodeFormatError)
}

func TestXoTServerHandleAXFRRequestDeniesUnauthorizedClient(t *testing.T) {
	// Deny-by-default: a client neither mTLS-authenticated nor in the allowlist
	// must be REFUSED, never served zone data.
	_, allowed, _ := net.ParseCIDR("10.0.0.0/8")
	srv := &XoTServer{
		zones:     map[string]*zone.Zone{"example.com.": zone.NewZone("example.com.")},
		zonesMu:   &sync.RWMutex{},
		allowList: []net.IPNet{*allowed},
	}
	conn := &xotValidationConn{remote: &net.TCPAddr{IP: net.ParseIP("203.0.113.7")}}
	q, err := protocol.NewQuestion("example.com.", protocol.TypeAXFR, protocol.ClassIN)
	if err != nil {
		t.Fatalf("NewQuestion: %v", err)
	}
	req := &protocol.Message{
		Header:    protocol.Header{ID: 0x1301},
		Questions: []*protocol.Question{q},
	}

	srv.handleAXFRRequest(conn, req, net.ParseIP("203.0.113.7"))

	assertXoTErrorResponse(t, conn.Bytes(), 0x1301, protocol.RcodeRefused)
}

func TestXoTServerHandleMessageAcceptsNonTCPRemoteAddr(t *testing.T) {
	srv := &XoTServer{
		zones:   map[string]*zone.Zone{},
		zonesMu: &sync.RWMutex{},
	}
	conn := &xotValidationConn{remote: xotStringAddr("127.0.0.1:853")}
	msg := &protocol.Message{Header: protocol.Header{ID: 0x1203}}
	buf := make([]byte, 65535)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	srv.handleMessage(conn, buf[:n])

	assertXoTErrorResponse(t, conn.Bytes(), 0x1203, protocol.RcodeNotImplemented)
}

func TestXoTExtractIXFRClientSerialSkipsNilRecords(t *testing.T) {
	serial := extractIXFRClientSerial(&protocol.Message{
		Authorities: []*protocol.ResourceRecord{
			nil,
			{
				Type: protocol.TypeSOA,
				Data: &protocol.RDataSOA{
					Serial: 42,
				},
			},
		},
	})
	if serial != 42 {
		t.Fatalf("serial = %d, want 42", serial)
	}
}

func assertXoTErrorResponse(t *testing.T, frame []byte, wantID uint16, wantRCode uint8) {
	t.Helper()
	if len(frame) < 2 {
		t.Fatalf("frame len = %d, want at least length prefix", len(frame))
	}
	msgLen := int(binary.BigEndian.Uint16(frame[:2]))
	if msgLen != len(frame)-2 {
		t.Fatalf("message length = %d, want %d", msgLen, len(frame)-2)
	}
	msg, err := protocol.UnpackMessage(frame[2:])
	if err != nil {
		t.Fatalf("UnpackMessage: %v", err)
	}
	defer msg.Release()
	if msg.Header.ID != wantID {
		t.Fatalf("response ID = %#x, want %#x", msg.Header.ID, wantID)
	}
	if !msg.Header.Flags.QR {
		t.Fatal("response QR = false, want true")
	}
	if msg.Header.Flags.RCODE != wantRCode {
		t.Fatalf("response RCODE = %d, want %d", msg.Header.Flags.RCODE, wantRCode)
	}
}

type xotValidationConn struct {
	bytes.Buffer
	remote net.Addr
}

func (c *xotValidationConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (c *xotValidationConn) Close() error                     { return nil }
func (c *xotValidationConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *xotValidationConn) RemoteAddr() net.Addr             { return c.remote }
func (c *xotValidationConn) SetDeadline(time.Time) error      { return nil }
func (c *xotValidationConn) SetReadDeadline(time.Time) error  { return nil }
func (c *xotValidationConn) SetWriteDeadline(time.Time) error { return nil }

type xotStringAddr string

func (a xotStringAddr) Network() string { return "test" }
func (a xotStringAddr) String() string  { return string(a) }
