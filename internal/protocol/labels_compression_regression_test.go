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
