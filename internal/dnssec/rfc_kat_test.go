package dnssec

// External known-answer tests (KATs) from published RFC test vectors.
//
// The existing crypto tests are generate-then-verify round-trips: they prove
// sign/verify are mutual inverses but cannot detect a shared deviation from
// the RFC 4034 §6 canonical form (e.g. a wrong RRSIG-RDATA prefix or owner
// name encoding would cancel out). These tests pin the implementation to
// signatures, hashes, and digests produced by *other* implementations, as
// published in:
//
//   - RFC 5702 §6.1/§6.2 — RSA/SHA-256 and RSA/SHA-512 DNSKEY + RRSIG over
//     www.example.net. A (verify-only KATs).
//   - RFC 8080 §6.1 — Ed25519 DNSKEYs, DS records, and RRSIGs over
//     example.com. MX. The RRSIGs use the corrected values from VERIFIED
//     Errata ID 4935 (the as-published RFC signatures had a wrong Labels
//     count of 3 and omitted the algorithm field; the errata signatures were
//     additionally re-derived here from the RFC's own private keys — Ed25519
//     is deterministic — and match byte-for-byte).
//   - RFC 5155 Appendix A — NSEC3 SHA-1 hash examples (12 names,
//     iterations=12, salt=AABBCCDD).
//   - RFC 4034 §5.4 / Appendix B — dskey.example.com. DNSKEY key tag (60485)
//     and DS SHA-1 digest example.
//
// Every base64/hex constant below was extracted mechanically from the RFC
// text (or the verified errata page) and cross-checked with an independent
// stdlib-only implementation before being committed.

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// katB64 decodes a base64 constant, failing the test on malformed input.
func katB64(t *testing.T, s string) []byte {
	t.Helper()
	d, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("bad base64 vector %q: %v", s, err)
	}
	return d
}

// katHex decodes a hex constant, failing the test on malformed input.
func katHex(t *testing.T, s string) []byte {
	t.Helper()
	d, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex vector %q: %v", s, err)
	}
	return d
}

// RFC 5702 §6.1: example.net. 256 3 8 ZSK (512-bit RSA), key tag 9033.
const rfc5702RSASHA256KeyB64 = "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk="

// RFC 5702 §6.1: RRSIG(A 8 3 3600 20300101000000 20000101000000 9033 example.net.)
// over "www.example.net. 3600 IN A 192.0.2.91".
const rfc5702RSASHA256SigB64 = "kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEacFYK/lPtPiVYP4bwg=="

// RFC 5702 §6.2: example.net. 256 3 10 ZSK (1024-bit RSA), key tag 3740.
const rfc5702RSASHA512KeyB64 = "AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFDxj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL"

// RFC 5702 §6.2: RRSIG(A 10 3 3600 20300101000000 20000101000000 3740 example.net.)
// over "www.example.net. 3600 IN A 192.0.2.91".
const rfc5702RSASHA512SigB64 = "tsb4wnjRUDnB1BUi+t6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRaeUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOLDiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw="

const (
	// 20000101000000 and 20300101000000 (RFC 5702 §6) as Unix timestamps.
	rfc5702Inception  = 946684800
	rfc5702Expiration = 1893456000
)

// rfc5702RRSet returns the single-record RRset signed in RFC 5702 §6:
// "www.example.net. 3600 IN A 192.0.2.91".
func rfc5702RRSet(t *testing.T) []*protocol.ResourceRecord {
	t.Helper()
	return []*protocol.ResourceRecord{{
		Name:  mustName(t, "www.example.net."),
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   3600,
		Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 91}},
	}}
}

// katValidator returns a Validator suitable for KAT signature checks.
// IgnoreTime is set because the RFC 8080 example signatures expired in 2015
// (and the RFC 5702 ones expire in 2030); the KAT pins the cryptography and
// canonicalization, not the clock.
func katValidator() *Validator {
	return NewValidator(ValidatorConfig{Enabled: true, IgnoreTime: true}, nil, nil)
}

// verifyKATRRSIG runs one RRSIG vector through the production pipeline twice:
// once decomposed (canonicalizeRRSet + ParseDNSKEYPublicKey + VerifySignature)
// so a failure pinpoints the stage, and once through validateRRSIG, the path
// the validator actually takes (includes key tag matching). It then flips one
// bit of the signature and requires verification to fail (no fail-open).
func verifyKATRRSIG(t *testing.T, rrSet []*protocol.ResourceRecord, rrsig *protocol.RDataRRSIG, dnskey *protocol.RDataDNSKEY, zone string) {
	t.Helper()
	v := katValidator()

	signedData, err := v.canonicalizeRRSet(rrSet, rrsig)
	if err != nil {
		t.Fatalf("canonicalizeRRSet: %v", err)
	}
	pub, err := ParseDNSKEYPublicKey(dnskey.Algorithm, dnskey.PublicKey)
	if err != nil {
		t.Fatalf("ParseDNSKEYPublicKey: %v", err)
	}
	if err := VerifySignature(rrsig, signedData, pub); err != nil {
		t.Errorf("RFC vector signature did not verify against production canonical form: %v", err)
	}

	keyRRs := []*protocol.ResourceRecord{{
		Name:  mustName(t, zone),
		Type:  protocol.TypeDNSKEY,
		Class: protocol.ClassIN,
		TTL:   3600,
		Data:  dnskey,
	}}
	if !v.validateRRSIG(rrSet, rrsig, keyRRs) {
		t.Errorf("validateRRSIG rejected RFC vector")
	}

	// Negative control: a corrupted signature must not verify.
	badSig := *rrsig
	badSig.Signature = append([]byte(nil), rrsig.Signature...)
	badSig.Signature[0] ^= 0x01
	if v.validateRRSIG(rrSet, &badSig, keyRRs) {
		t.Errorf("validateRRSIG accepted corrupted signature (fail-open)")
	}
}

// allowSmallRSAKeys opts this test out of Go 1.24+'s crypto/rsa minimum key
// size (GODEBUG rsa1024min): the RFC 5702 §6.1 example key is 512 bits.
// crypto/rsa reads GODEBUG dynamically, so t.Setenv takes effect immediately
// and is restored when the test ends.
func allowSmallRSAKeys(t *testing.T) {
	t.Helper()
	v := "rsa1024min=0"
	if old := os.Getenv("GODEBUG"); old != "" {
		v = old + "," + v
	}
	t.Setenv("GODEBUG", v)
}

// TestKAT_RFC5702_RSASHA256 verifies the RSA/SHA-256 example signature from
// RFC 5702 §6.1 against the production canonicalization and verification code.
func TestKAT_RFC5702_RSASHA256(t *testing.T) {
	allowSmallRSAKeys(t)

	key := katB64(t, rfc5702RSASHA256KeyB64)
	dnskey := &protocol.RDataDNSKEY{Flags: 256, Protocol: 3, Algorithm: protocol.AlgorithmRSASHA256, PublicKey: key}
	if tag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey); tag != 9033 {
		t.Fatalf("key tag = %d, want 9033 (RFC 5702 §6.1)", tag)
	}

	rrsig := &protocol.RDataRRSIG{
		TypeCovered: protocol.TypeA,
		Algorithm:   protocol.AlgorithmRSASHA256,
		Labels:      3,
		OriginalTTL: 3600,
		Expiration:  rfc5702Expiration,
		Inception:   rfc5702Inception,
		KeyTag:      9033,
		SignerName:  mustName(t, "example.net."),
		Signature:   katB64(t, rfc5702RSASHA256SigB64),
	}
	verifyKATRRSIG(t, rfc5702RRSet(t), rrsig, dnskey, "example.net.")
}

// TestKAT_RFC5702_RSASHA512 verifies the RSA/SHA-512 example signature from
// RFC 5702 §6.2.
func TestKAT_RFC5702_RSASHA512(t *testing.T) {
	key := katB64(t, rfc5702RSASHA512KeyB64)
	dnskey := &protocol.RDataDNSKEY{Flags: 256, Protocol: 3, Algorithm: protocol.AlgorithmRSASHA512, PublicKey: key}
	if tag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey); tag != 3740 {
		t.Fatalf("key tag = %d, want 3740 (RFC 5702 §6.2)", tag)
	}

	rrsig := &protocol.RDataRRSIG{
		TypeCovered: protocol.TypeA,
		Algorithm:   protocol.AlgorithmRSASHA512,
		Labels:      3,
		OriginalTTL: 3600,
		Expiration:  rfc5702Expiration,
		Inception:   rfc5702Inception,
		KeyTag:      3740,
		SignerName:  mustName(t, "example.net."),
		Signature:   katB64(t, rfc5702RSASHA512SigB64),
	}
	verifyKATRRSIG(t, rfc5702RRSet(t), rrsig, dnskey, "example.net.")
}

// rfc8080Ed25519Vectors are the two Ed25519 examples from RFC 8080 §6.1 with
// the RRSIG values corrected per verified Errata ID 4935 (Labels=2, algorithm
// 15). The DS records were not affected by the errata. Both signatures were
// re-derived from the RFC's published private keys (Ed25519 signing is
// deterministic) and match the errata byte-for-byte.
var rfc8080Ed25519Vectors = []struct {
	name        string
	dnskeyB64   string // example.com. 3600 IN DNSKEY 257 3 15 (...)
	keyTag      uint16
	sigB64      string // RRSIG MX 15 2 3600 1440021600 1438207200 <tag> example.com.
	dsDigestHex string // example.com. DS <tag> 15 2 (...)
}{
	{
		name:        "key1_tag3613",
		dnskeyB64:   "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",
		keyTag:      3613,
		sigB64:      "oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg==",
		dsDigestHex: "3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b",
	},
	{
		name:        "key2_tag35217",
		dnskeyB64:   "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=",
		keyTag:      35217,
		sigB64:      "zXQ0bkYgQTEFyfLyi9QoiY6D8ZdYo4wyUhVioYZXFdT410QPRITQSqJSnzQoSm5poJ7gD7AQR0O7KuI5k2pcBg==",
		dsDigestHex: "401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c6614c",
	},
}

// TestKAT_RFC8080_Ed25519 verifies the Ed25519 example signatures from
// RFC 8080 §6.1 (as corrected by verified Errata ID 4935) over
// "example.com. 3600 IN MX 10 mail.example.com.".
func TestKAT_RFC8080_Ed25519(t *testing.T) {
	for _, vec := range rfc8080Ed25519Vectors {
		t.Run(vec.name, func(t *testing.T) {
			key := katB64(t, vec.dnskeyB64)
			dnskey := &protocol.RDataDNSKEY{Flags: 257, Protocol: 3, Algorithm: protocol.AlgorithmED25519, PublicKey: key}
			if tag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey); tag != vec.keyTag {
				t.Fatalf("key tag = %d, want %d (RFC 8080 §6.1)", tag, vec.keyTag)
			}

			rrSet := []*protocol.ResourceRecord{{
				Name:  mustName(t, "example.com."),
				Type:  protocol.TypeMX,
				Class: protocol.ClassIN,
				TTL:   3600,
				Data: &protocol.RDataMX{
					Preference: 10,
					Exchange:   mustName(t, "mail.example.com."),
				},
			}}
			rrsig := &protocol.RDataRRSIG{
				TypeCovered: protocol.TypeMX,
				Algorithm:   protocol.AlgorithmED25519,
				Labels:      2,
				OriginalTTL: 3600,
				Expiration:  1440021600,
				Inception:   1438207200,
				KeyTag:      vec.keyTag,
				SignerName:  mustName(t, "example.com."),
				Signature:   katB64(t, vec.sigB64),
			}
			verifyKATRRSIG(t, rrSet, rrsig, dnskey, "example.com.")
		})
	}
}

// TestKAT_RFC8080_DSDigestSHA256 checks the SHA-256 DS digests published for
// the RFC 8080 §6.1 Ed25519 DNSKEYs (e.g. "example.com. 3600 IN DS 3613 15 2
// 3aa5ab37...").
func TestKAT_RFC8080_DSDigestSHA256(t *testing.T) {
	for _, vec := range rfc8080Ed25519Vectors {
		t.Run(vec.name, func(t *testing.T) {
			dnskey := &protocol.RDataDNSKEY{Flags: 257, Protocol: 3, Algorithm: protocol.AlgorithmED25519, PublicKey: katB64(t, vec.dnskeyB64)}
			got := calculateDSDigestFromDNSKEY("example.com.", dnskey, 2)
			if hex.EncodeToString(got) != vec.dsDigestHex {
				t.Errorf("DS SHA-256 digest = %x, want %s", got, vec.dsDigestHex)
			}
		})
	}
}

// TestKAT_RFC4034_DSExample checks the DS example from RFC 4034 §5.4:
// the dskey.example.com. DNSKEY (256 3 5) has key tag 60485 (Appendix B
// algorithm) and DS SHA-1 digest 2BB183AF5F22588179A53B0A98631FAD1A292118.
// Key tag and DS digest computation are algorithm-agnostic, so the RSA/SHA-1
// key exercises the same code paths used for modern algorithms.
func TestKAT_RFC4034_DSExample(t *testing.T) {
	const dnskeyB64 = "AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw=="
	key := katB64(t, dnskeyB64)

	// RFC 4034 Appendix B key tag ("key id = 60485").
	if tag := protocol.CalculateKeyTag(256, 5, key); tag != 60485 {
		t.Errorf("key tag = %d, want 60485 (RFC 4034 §5.4 / Appendix B)", tag)
	}

	// RFC 4034 §5.4 DS SHA-1 digest.
	dnskey := &protocol.RDataDNSKEY{Flags: 256, Protocol: 3, Algorithm: 5, PublicKey: key}
	want := katHex(t, "2bb183af5f22588179a53b0a98631fad1a292118")
	got := calculateDSDigestFromDNSKEY("dskey.example.com.", dnskey, 1)
	if !bytesEqual(got, want) {
		t.Errorf("DS SHA-1 digest = %x, want %x", got, want)
	}

	// Owner-name case must not change the digest (RFC 4034 §6.2 canonical
	// owner name is lowercase).
	gotUpper := calculateDSDigestFromDNSKEY("DSKEY.Example.COM.", dnskey, 1)
	if !bytesEqual(gotUpper, want) {
		t.Errorf("DS digest with mixed-case owner = %x, want %x (owner not canonicalized)", gotUpper, want)
	}
}

// TestKAT_RFC5155_NSEC3Hash checks the NSEC3 hash examples from RFC 5155
// Appendix A: SHA-1, 12 additional iterations, salt AABBCCDD, results in
// lowercase base32hex.
func TestKAT_RFC5155_NSEC3Hash(t *testing.T) {
	salt := katHex(t, "aabbccdd")
	vectors := []struct {
		fqdn string
		hash string
	}{
		{"example", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"},
		{"a.example", "35mthgpgcu1qg68fab165klnsnk3dpvl"},
		{"ai.example", "gjeqe526plbf1g8mklp59enfd789njgi"},
		{"ns1.example", "2t7b4g4vsa5smi47k61mv5bv1a22bojr"},
		{"ns2.example", "q04jkcevqvmu85r014c7dkba38o0ji5r"},
		{"w.example", "k8udemvp1j2f7eg6jebps17vp3n8i58h"},
		{"*.w.example", "r53bq7cc2uvmubfu5ocmm6pers9tk9en"},
		{"x.w.example", "b4um86eghhds6nea196smvmlo4ors995"},
		{"y.w.example", "ji6neoaepv8b5o6k4ev33abha8ht9fgc"},
		{"x.y.w.example", "2vptu5timamqttgl4luu9kg21e0aor3s"},
		{"xx.example", "t644ebqk9bibcna874givr6joj62mlhv"},
		{"2t7b4g4vsa5smi47k61mv5bv1a22bojr.example", "kohar7mbb8dc2ce8a9qvl8hon4k53uhi"},
	}
	for _, vec := range vectors {
		raw, err := NSEC3Hash(vec.fqdn, 1, 12, salt)
		if err != nil {
			t.Errorf("NSEC3Hash(%q): %v", vec.fqdn, err)
			continue
		}
		got := strings.ToLower(base32.HexEncoding.EncodeToString(raw))
		if got != vec.hash {
			t.Errorf("NSEC3Hash(%q) = %s, want %s (RFC 5155 Appendix A)", vec.fqdn, got, vec.hash)
		}
	}

	// Case-insensitivity: hashing must canonicalize the owner name to
	// lowercase first (RFC 5155 §5).
	raw, err := NSEC3Hash("A.EXAMPLE", 1, 12, salt)
	if err != nil {
		t.Fatalf("NSEC3Hash uppercase: %v", err)
	}
	if got := strings.ToLower(base32.HexEncoding.EncodeToString(raw)); got != "35mthgpgcu1qg68fab165klnsnk3dpvl" {
		t.Errorf("NSEC3Hash(A.EXAMPLE) = %s, want 35mthgpgcu1qg68fab165klnsnk3dpvl (name not lowercased)", got)
	}
}
