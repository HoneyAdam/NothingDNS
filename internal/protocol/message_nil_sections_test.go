package protocol

import (
	"strings"
	"testing"
	"time"
)

func TestMessageNilReceiverSafe(t *testing.T) {
	var msg *Message

	if msg.IsQuery() {
		t.Fatal("nil Message IsQuery() = true, want false")
	}
	if msg.IsResponse() {
		t.Fatal("nil Message IsResponse() = true, want false")
	}
	if got := msg.GetOPT(); got != nil {
		t.Fatalf("nil Message GetOPT() = %#v, want nil", got)
	}
	if got := msg.WireLength(); got != 0 {
		t.Fatalf("nil Message WireLength() = %d, want 0", got)
	}
	if got := msg.String(); got != "<nil message>" {
		t.Fatalf("nil Message String() = %q, want nil placeholder", got)
	}
	if got := msg.Copy(); got != nil {
		t.Fatalf("nil Message Copy() = %#v, want nil", got)
	}

	msg.SetResponse(RcodeSuccess)
	msg.AddQuestion(&Question{})
	msg.AddAnswer(&ResourceRecord{})
	msg.AddAuthority(&ResourceRecord{})
	msg.AddAdditional(&ResourceRecord{})
	msg.SetEDNS0(1232, true)
	msg.Clear()
	msg.Truncate(HeaderLen)
	msg.Release()

	if _, err := msg.Pack(make([]byte, HeaderLen)); err == nil || !strings.Contains(err.Error(), "nil message") {
		t.Fatalf("nil Message Pack() error = %v, want nil message error", err)
	}
}

func TestMessagePackRejectsNilQuestionEntries(t *testing.T) {
	msg := &Message{
		Questions: []*Question{nil},
	}

	_, err := msg.Pack(make([]byte, 512))
	if err == nil || !strings.Contains(err.Error(), "nil question at index 0") {
		t.Fatalf("Pack nil question error = %v, want nil question at index 0", err)
	}

	msg = &Message{
		Questions: []*Question{{QType: TypeA, QClass: ClassIN}},
	}
	_, err = msg.Pack(make([]byte, 512))
	if err == nil || !strings.Contains(err.Error(), "nil question name at index 0") {
		t.Fatalf("Pack nil question name error = %v, want nil question name at index 0", err)
	}
}

func TestMessagePackRejectsNilResourceRecordEntries(t *testing.T) {
	name := NewName([]string{"example", "com"}, true)
	tests := []struct {
		name string
		msg  *Message
		want string
	}{
		{
			name: "nil answer",
			msg:  &Message{Answers: []*ResourceRecord{nil}},
			want: "nil answer record at index 0",
		},
		{
			name: "nil authority name",
			msg:  &Message{Authorities: []*ResourceRecord{{Type: TypeSOA, Class: ClassIN, Data: &RDataSOA{}}}},
			want: "nil authority record name at index 0",
		},
		{
			name: "nil additional data",
			msg:  &Message{Additionals: []*ResourceRecord{{Name: name, Type: TypeA, Class: ClassIN}}},
			want: "nil additional record data at index 0",
		},
		{
			name: "typed nil additional data",
			msg: func() *Message {
				var data *RDataA
				return &Message{Additionals: []*ResourceRecord{{Name: name, Type: TypeA, Class: ClassIN, Data: data}}}
			}(),
			want: "nil additional record data at index 0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.msg.Pack(make([]byte, 512))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Pack error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestProtocolNilSectionHelpersDoNotPanic(t *testing.T) {
	msg := &Message{
		Questions: []*Question{nil, {QType: TypeA, QClass: ClassIN}},
		Answers: []*ResourceRecord{
			nil,
			{Type: TypeA, Class: ClassIN},
		},
		Authorities: []*ResourceRecord{
			{Type: TypeSOA, Class: ClassIN, Data: &RDataSOA{}},
		},
	}

	if got := msg.WireLength(); got != HeaderLen {
		t.Fatalf("WireLength = %d, want %d for invalid-only sections", got, HeaderLen)
	}
	if got := msg.String(); !strings.Contains(got, "<nil question>") || !strings.Contains(got, "<nil resource record>") {
		t.Fatalf("String() = %q, want nil placeholders", got)
	}

	cp := msg.Copy()
	if cp == nil {
		t.Fatal("Copy returned nil")
	}
	if len(cp.Questions) != 1 || cp.Questions[0].Name != nil {
		t.Fatalf("copied questions = %+v, want one nil-name question copy", cp.Questions)
	}
	if len(cp.Answers) != 1 || cp.Answers[0].Name != nil {
		t.Fatalf("copied answers = %+v, want one nil-name answer copy", cp.Answers)
	}
	if len(cp.Authorities) != 1 || cp.Authorities[0].Name != nil {
		t.Fatalf("copied authorities = %+v, want one nil-name authority copy", cp.Authorities)
	}
}

func TestResourceRecordTypedNilRDataHelpersDoNotPanic(t *testing.T) {
	var data *RDataA
	rr := &ResourceRecord{
		Name:  NewName([]string{"example", "com"}, true),
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  data,
	}

	if got := rr.WireLength(); got != rr.Name.WireLength()+10 {
		t.Fatalf("WireLength() = %d, want header-only length %d", got, rr.Name.WireLength()+10)
	}
	if got := rr.String(); !strings.Contains(got, "example.com.") {
		t.Fatalf("String() = %q, want record name", got)
	}
	cp := rr.Copy()
	if cp == nil {
		t.Fatal("Copy() returned nil")
	}
	if cp.Data != nil {
		t.Fatalf("copied Data = %T, want nil", cp.Data)
	}
}

func TestResourceRecordNilReceiverTTLSafe(t *testing.T) {
	var rr *ResourceRecord

	if !rr.IsExpired(time.Now()) {
		t.Fatal("nil ResourceRecord IsExpired() = false, want true")
	}
	if got := rr.RemainingTTL(time.Now()); got != 0 {
		t.Fatalf("nil ResourceRecord RemainingTTL() = %d, want 0", got)
	}
}

func TestMessageSetEDNS0DropsNilAndExistingOPT(t *testing.T) {
	extra := &ResourceRecord{
		Name:  NewName([]string{"example", "com"}, true),
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{192, 0, 2, 1}},
	}
	oldOPT := &ResourceRecord{
		Name:  NewName(nil, true),
		Type:  TypeOPT,
		Class: 4096,
		Data:  &RDataOPT{},
	}
	msg := &Message{
		Additionals: []*ResourceRecord{nil, extra, oldOPT},
	}

	if got := msg.GetOPT(); got != oldOPT {
		t.Fatalf("GetOPT() = %p, want existing OPT %p", got, oldOPT)
	}

	msg.SetEDNS0(1232, true)

	if len(msg.Additionals) != 2 {
		t.Fatalf("additionals length = %d, want 2", len(msg.Additionals))
	}
	if msg.Additionals[0] != extra {
		t.Fatalf("first additional = %p, want preserved non-OPT record %p", msg.Additionals[0], extra)
	}

	opt := msg.GetOPT()
	if opt == nil {
		t.Fatal("GetOPT() returned nil after SetEDNS0")
	}
	if opt == oldOPT {
		t.Fatal("SetEDNS0 preserved old OPT record, want replacement")
	}
	if opt.Class != 1232 {
		t.Fatalf("OPT class = %d, want UDP payload size 1232", opt.Class)
	}
	if _, ok := opt.Data.(*RDataOPT); !ok {
		t.Fatalf("OPT data type = %T, want *RDataOPT", opt.Data)
	}
}
