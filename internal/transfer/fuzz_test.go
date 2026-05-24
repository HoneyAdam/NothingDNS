package transfer

// Fuzz harnesses for transfer-package wire-format and on-disk
// decoders. Both DecodeJournalEntry and UnpackTSIGRecord consume
// adversarial input:
//
//   - DecodeJournalEntry reads IXFR journal entries from disk.
//     A container-escape or shared-mount attacker can plant a
//     crafted file; the decoder must fail-closed, not panic.
//   - UnpackTSIGRecord runs on the additional-section bytes of
//     every signed DNS query a peer sends. A malformed TSIG record
//     coming in over UDP/TCP must not crash the server.

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func FuzzDecodeJournalEntry(f *testing.F) {
	// Seed: empty, undersized, a valid round-trip entry.
	f.Add([]byte{})
	f.Add(make([]byte, 15)) // one byte short of the 16-byte minimum
	f.Add(EncodeJournalEntry(&IXFRJournalEntry{Serial: 42}))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeJournalEntry(data)
	})
}

func FuzzUnpackTSIGRecord(f *testing.F) {
	// Seed: empty, undersized, a real signed TSIG record bytes.
	f.Add([]byte{})
	f.Add(make([]byte, 9)) // one byte short of the 10-byte minimum

	// Build a valid TSIG record by signing a minimal message, then
	// pack the TSIG RR to wire and use that as a seed. This exercises
	// the happy path the fuzzer should preserve while mutating into
	// crash territory.
	key := &TSIGKey{
		Name:      "k.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("0123456789abcdef0123456789abcdef"),
	}
	name, _ := protocol.ParseName("example.com.")
	msg := &protocol.Message{
		Header: protocol.Header{ID: 1, QDCount: 1},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
	}
	if rr, err := SignMessage(msg, key, 300); err == nil {
		buf := make([]byte, 4096)
		if n, err := rr.Pack(buf, 0, nil); err == nil {
			f.Add(buf[:n])
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = UnpackTSIGRecord(data, 0)
	})
}

// FuzzVerifyMessage drives the full TSIG verify path with random
// message bytes. Tests "unpack message → find TSIG RR → verify MAC"
// flow which is what an attacker can hit by sending arbitrary signed
// queries. Uses a fixed key and ignores the silent "no TSIG present"
// success path.
func FuzzVerifyMessage(f *testing.F) {
	key := &TSIGKey{
		Name:      "fuzz.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("0123456789abcdef0123456789abcdef"),
	}

	// Seed: valid signed message.
	name, _ := protocol.ParseName("example.com.")
	msg := &protocol.Message{
		Header: protocol.Header{ID: 9, QDCount: 1},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
	}
	if rr, err := SignMessage(msg, key, 300); err == nil {
		msg.Additionals = append(msg.Additionals, rr)
		buf := make([]byte, 4096)
		if n, err := msg.Pack(buf); err == nil {
			f.Add(buf[:n])
		}
	}
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := protocol.UnpackMessage(data)
		if err != nil {
			return
		}
		_ = VerifyMessage(m, key, nil)
	})
}

var _ = net.IPv4zero // keep net imported in case future seeds need clientIP
