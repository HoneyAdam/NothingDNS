package protocol

// Property-based round-trip tests using testing/quick. Where the fuzz
// harnesses in fuzz_test.go only check that the parser doesn't panic
// on adversarial input, these tests build *valid* inputs randomly and
// assert that Pack→Unpack preserves their structure exactly.
//
// Stronger than fuzz, narrower than spec-conformance — these catch
// regressions where a parser/serializer drift apart on inputs neither
// the fuzz corpus nor the fixed test table happens to cover.

import (
	"math/rand"
	"net"
	"testing"
	"testing/quick"
)

// genName generates a random valid DNS name with 0-4 labels, each
// 1-20 lowercase-letter chars. Always returns a fully-qualified name
// (Labels + FQDN = true).
func genName(r *rand.Rand) *Name {
	nLabels := r.Intn(5) // 0..4
	labels := make([]string, nLabels)
	for i := range labels {
		labelLen := 1 + r.Intn(20)
		buf := make([]byte, labelLen)
		for j := range buf {
			buf[j] = byte('a' + r.Intn(26))
		}
		labels[i] = string(buf)
	}
	return NewName(labels, true)
}

func TestProperty_NameRoundTrip(t *testing.T) {
	// 200 random names; each must survive Pack → Unpack unchanged.
	f := func(seed int64) bool {
		r := rand.New(rand.NewSource(seed))
		orig := genName(r)

		buf := make([]byte, 512)
		n, err := PackName(orig, buf, 0, nil)
		if err != nil {
			t.Logf("PackName error on seed %d: %v", seed, err)
			return false
		}
		unpacked, consumed, err := UnpackName(buf, 0)
		if err != nil {
			t.Logf("UnpackName error on seed %d: %v (packed bytes: %x)", seed, err, buf[:n])
			return false
		}
		if consumed != n {
			t.Logf("seed %d: consumed=%d, packed=%d", seed, consumed, n)
			return false
		}
		return orig.Equal(unpacked)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 200}); err != nil {
		t.Errorf("NameRoundTrip property violated: %v", err)
	}
}

// TestProperty_MessageHeaderRoundTrip exercises HeaderPack/Unpack with
// arbitrary header values. The flag bits are bit-level — easy to drift
// silently if the unpacker treats a reserved bit as one of the
// canonical bits.
func TestProperty_MessageHeaderRoundTrip(t *testing.T) {
	f := func(id uint16, qd, an, ns, ar uint16, opcode uint8, rcode uint8,
		qr, aa, tc, rd, ra, ad, cd bool) bool {
		// opcode and rcode are 4-bit fields.
		opcode &= 0x0f
		rcode &= 0x0f
		orig := Header{
			ID: id,
			Flags: Flags{
				QR:     qr,
				Opcode: opcode,
				AA:     aa,
				TC:     tc,
				RD:     rd,
				RA:     ra,
				AD:     ad,
				CD:     cd,
				RCODE:  rcode,
			},
			QDCount: qd,
			ANCount: an,
			NSCount: ns,
			ARCount: ar,
		}

		buf := make([]byte, HeaderLen)
		if err := orig.Pack(buf); err != nil {
			t.Logf("Pack: %v", err)
			return false
		}

		var got Header
		if err := got.Unpack(buf); err != nil {
			t.Logf("Unpack: %v", err)
			return false
		}
		return got == orig
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 200}); err != nil {
		t.Errorf("HeaderRoundTrip property violated: %v", err)
	}
}

// TestProperty_ARDataRoundTrip — A record RDATA is 4 raw IPv4 bytes;
// the pack/unpack identity here catches byte-order regressions.
func TestProperty_ARDataRoundTrip(t *testing.T) {
	f := func(a, b, c, d byte) bool {
		orig := &RDataA{Address: [4]byte{a, b, c, d}}
		buf := make([]byte, 4)
		n, err := orig.Pack(buf, 0)
		if err != nil || n != 4 {
			return false
		}
		got := &RDataA{}
		if _, err := got.Unpack(buf, 0, 4); err != nil {
			return false
		}
		return got.Address == orig.Address
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 200}); err != nil {
		t.Errorf("RDataA property violated: %v", err)
	}
}

// TestProperty_AAAARDataRoundTrip — IPv6 is 16 bytes.
func TestProperty_AAAARDataRoundTrip(t *testing.T) {
	f := func(seed int64) bool {
		r := rand.New(rand.NewSource(seed))
		var ip [16]byte
		_, _ = r.Read(ip[:])
		orig := &RDataAAAA{Address: ip}

		buf := make([]byte, 16)
		n, err := orig.Pack(buf, 0)
		if err != nil || n != 16 {
			return false
		}
		got := &RDataAAAA{}
		if _, err := got.Unpack(buf, 0, 16); err != nil {
			return false
		}
		return got.Address == orig.Address
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 200}); err != nil {
		t.Errorf("RDataAAAA property violated: %v", err)
	}
}

// TestProperty_QuestionRoundTrip builds arbitrary question sections
// (name + type + class) and asserts unpack restores them.
func TestProperty_QuestionRoundTrip(t *testing.T) {
	f := func(seed int64, qtype uint16, qclass uint16) bool {
		r := rand.New(rand.NewSource(seed))
		name := genName(r)
		orig := &Question{Name: name, QType: qtype, QClass: qclass}

		// QuestionLen returns total wire length.
		buf := make([]byte, 512)
		n, err := orig.Pack(buf, 0, nil)
		if err != nil {
			return false
		}

		got, consumed, err := UnpackQuestion(buf[:n], 0)
		if err != nil {
			return false
		}
		if consumed != n {
			return false
		}
		return got.Name.Equal(name) && got.QType == qtype && got.QClass == qclass
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 200}); err != nil {
		t.Errorf("Question property violated: %v", err)
	}
}

// Compile-time guard: keep the net import used so future drift in
// generators referencing IPs still compiles.
var _ = net.IPv4
