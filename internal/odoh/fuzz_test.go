package odoh

// Fuzz tests for the RFC 9230 wire-format parsers. ODoH messages are
// attacker-controlled bytes (anything the proxy forwards), so the
// parser must never panic on adversarial input.

import (
	"testing"
)

func FuzzParseODoHMessage(f *testing.F) {
	// Seed: valid query-shaped messages and intentionally bad ones.
	f.Add([]byte{})                             // empty
	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0x00}) // type=query, no key_id, no enc
	// Minimal valid query: type=1, keyIDLen=4, keyID=4*0x00, encLen=0
	f.Add([]byte{
		0x01,
		0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	})
	// Truncated mid-key_id.
	f.Add([]byte{0x01, 0x00, 0x10, 0x01, 0x02})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic. Errors are fine.
		_, _ = parseODoHMessage(data)
	})
}

func FuzzParseConfigContents(f *testing.F) {
	// Seed with a valid generated config and some malformed inputs.
	if kp, err := newODoHKeyPair(); err == nil {
		f.Add(kp.configBytes)
	}
	f.Add([]byte{})                                               // empty
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // zero suite IDs
	f.Add([]byte{
		0x00, 0x20, 0x00, 0x01, 0x00, 0x01, // valid suite IDs
		0x00, 0xff, // pkLen claims 255 but only 0 bytes follow
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = parseConfigContents(data)
	})
}

// FuzzDecryptQuery exercises the entire target-side decrypt path with
// adversarial wire bytes. Always uses the same target key pair so that
// individual fuzz iterations stay cheap; we're testing parser
// robustness, not authenticity.
func FuzzDecryptQuery(f *testing.F) {
	kp, err := newODoHKeyPair()
	if err != nil {
		f.Skip("newODoHKeyPair:", err)
	}

	// Seed with a real, valid query.
	if msgBytes, _, err := encryptQueryRFC9230(kp.configBytes, []byte{0x00, 0x00}); err == nil {
		f.Add(msgBytes)
	}
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x00, 0x20}) // truncated header

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = kp.decryptQuery(data)
	})
}
