package protocol

import "testing"

// Regression: PackName emitted ONLY a compression pointer when a strict
// suffix of the name was already in the compression map, dropping the
// leading labels — any message where a later owner name shared a suffix
// with an earlier name (CNAME chains, additionals, multi-name answers)
// decoded with corrupted names ("www.example.com." -> "example.com.").
func TestPackName_SuffixCompressionKeepsLeadingLabels(t *testing.T) {
	q, _ := ParseName("a.example.com.")
	owner2, _ := ParseName("www.example.com.")
	a := [4]byte{192, 0, 2, 1}

	msg := &Message{
		Header: Header{ID: 42, Flags: NewResponseFlags(RcodeSuccess)},
		Questions: []*Question{
			{Name: q, QType: TypeA, QClass: ClassIN},
		},
		Answers: []*ResourceRecord{
			{Name: q, Type: TypeCNAME, Class: ClassIN, TTL: 300, Data: &RDataCNAME{CName: owner2}},
			{Name: owner2, Type: TypeA, Class: ClassIN, TTL: 300, Data: &RDataA{Address: a}},
		},
	}
	msg.Header.QDCount = 1
	msg.Header.ANCount = 2

	buf := make([]byte, msg.WireLength())
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	rt, err := UnpackMessage(buf[:n])
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if got := rt.Answers[0].Name.String(); got != "a.example.com." {
		t.Errorf("answer[0] owner = %q, want a.example.com.", got)
	}
	if got := rt.Answers[1].Name.String(); got != "www.example.com." {
		t.Errorf("answer[1] owner = %q, want www.example.com. (leading label dropped by compression)", got)
	}
}

// Regression: compression bookkeeping was keyed on the unescaped
// presentation form, so a wire label containing a literal '.' byte
// ("a.b" as ONE label) desynced the presentation/wire label counts —
// the emit-before-pointer path wrote the wrong wire labels and the name
// round-tripped corrupted (e.g. "a.b.example.example.com."). Keys are
// now derived from the wire bytes themselves.
func TestPackName_EmbeddedDotLabelNotCorrupted(t *testing.T) {
	seed, _ := ParseName("example.com.")

	// Build {a.b}{example}{com}: first label is the 3 bytes 'a','.','b'.
	wire := []byte{3, 'a', '.', 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	inner, _, err := UnpackName(wire, 0)
	if err != nil {
		t.Fatalf("unpack embedded-dot name: %v", err)
	}

	buf := make([]byte, 512)
	compression := map[string]int{}
	n1, err := PackName(seed, buf, 0, compression)
	if err != nil {
		t.Fatalf("pack seed: %v", err)
	}
	n2, err := PackName(inner, buf, n1, compression)
	if err != nil {
		t.Fatalf("pack embedded-dot name: %v", err)
	}

	got, _, err := UnpackName(buf[:n1+n2], n1)
	if err != nil {
		t.Fatalf("unpack packed name: %v", err)
	}
	if !got.Equal(inner) {
		t.Fatalf("embedded-dot label corrupted by compression: got %q, want %q", got.String(), inner.String())
	}
}
