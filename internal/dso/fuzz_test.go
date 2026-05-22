package dso

// Fuzz the RFC 8490 DSO TLV parser. DSO bodies arrive over TCP/TLS
// from clients and may be attacker-shaped, so UnpackTLV and the
// end-to-end HandleDSORequest path must never panic.

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func FuzzUnpackTLV(f *testing.F) {
	// Seed: well-formed and degenerate TLVs.
	// Keepalive (type 1, length 8): inactivity=0, keepalive=0.
	f.Add([]byte{0x00, 0x01, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0}, 0)
	// MaximumPayload (type 2, length 2): payload=65535.
	f.Add([]byte{0x00, 0x02, 0x00, 0x02, 0xff, 0xff}, 0)
	// Padding (type 3, length 4): all zero.
	f.Add([]byte{0x00, 0x03, 0x00, 0x04, 0, 0, 0, 0}, 0)
	// Length larger than buffer.
	f.Add([]byte{0x00, 0x01, 0xff, 0xff, 0x01}, 0)
	// Empty.
	f.Add([]byte{}, 0)
	// Negative-ish offset (large positive value).
	f.Add([]byte{0x00, 0x01, 0x00, 0x00}, 1<<30)

	f.Fuzz(func(t *testing.T, buf []byte, off int) {
		if off < 0 || off > len(buf) {
			return // skip non-sensical offsets to keep the corpus realistic
		}
		_, _, _ = UnpackTLV(buf, off)
	})
}

func FuzzHandleDSORequest(f *testing.F) {
	// Seed with shapes the DSO handler should see in production.
	// Keepalive TLV body.
	f.Add([]byte{0x00, 0x01, 0x00, 0x08, 0, 0, 0x10, 0, 0, 0, 0x20, 0})
	// MaximumPayload.
	f.Add([]byte{0x00, 0x02, 0x00, 0x02, 0x04, 0x00})
	// Two TLVs back-to-back.
	f.Add([]byte{
		0x00, 0x01, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0,
		0x00, 0x02, 0x00, 0x02, 0xff, 0xff,
	})
	// Empty body.
	f.Add([]byte{})

	m := NewManager(DefaultConfig(), nil)

	f.Fuzz(func(t *testing.T, body []byte) {
		// Construct a DSO message wrapper.
		msg := &protocol.Message{
			Header: protocol.Header{
				ID:    0,
				Flags: protocol.Flags{Opcode: protocol.OpcodeDSO},
			},
			RawBody: append([]byte(nil), body...),
		}
		session := &Session{
			ID:     1,
			stopCh: make(chan struct{}),
			doneCh: make(chan struct{}),
		}
		// Must not panic. Errors and empty responses are fine.
		_, _ = m.HandleDSORequest(session, msg)
	})
}
