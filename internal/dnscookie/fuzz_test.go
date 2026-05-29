package dnscookie

// Fuzz tests for DNS Cookie option parsing (RFC 7873). EDNS0 OPT data
// is attacker-controlled (anything the client puts in the additional
// section), so ParseCookieOption must never panic on adversarial
// input. ValidateServerCookie reads attacker-supplied server-cookie
// bytes through the same parse boundary; round-tripping random bytes
// through ParseCookieOption → ValidateServerCookie shakes out crashes
// in both the parser and the HMAC compare path.

import (
	"net"
	"testing"
)

func FuzzParseCookieOption(f *testing.F) {
	// Seeds: empty, exactly-min-length, valid client+server, oversize.
	f.Add([]byte{})
	f.Add(make([]byte, ClientCookieLen)) // client only, no server cookie
	f.Add(make([]byte, ClientCookieLen+MinServerCookieLen))
	f.Add(make([]byte, ClientCookieLen+MaxServerCookieLen+1)) // one byte over the cap

	// Round-trip a real generated cookie.
	jar, err := NewCookieJar(1 * 1e9) // 1 second
	if err == nil {
		var cc [ClientCookieLen]byte
		copy(cc[:], "deadbeef")
		sc := jar.GenerateServerCookie(cc, net.ParseIP("127.0.0.1"))
		f.Add(PackCookieOption(cc, sc))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCookieOption(data)
	})
}

// FuzzValidateServerCookie drives the validator with random server-
// cookie bytes against a fixed jar + client cookie + IP. The validator
// must always answer true/false, never panic, regardless of how
// truncated, oversized, or malformed the candidate cookie is.
func FuzzValidateServerCookie(f *testing.F) {
	jar, err := NewCookieJar(1 * 1e9)
	if err != nil {
		f.Skip("NewCookieJar:", err)
	}
	var cc [ClientCookieLen]byte
	copy(cc[:], "fuzzcli!")
	clientIP := net.ParseIP("127.0.0.1")

	// Seed: a real-and-valid server cookie + a couple of bad lengths.
	f.Add(jar.GenerateServerCookie(cc, clientIP))
	f.Add([]byte{})
	f.Add(make([]byte, MinServerCookieLen-1))
	f.Add(make([]byte, MaxServerCookieLen+1))

	f.Fuzz(func(t *testing.T, serverCookie []byte) {
		_ = jar.ValidateServerCookie(cc, serverCookie, clientIP)
	})
}
