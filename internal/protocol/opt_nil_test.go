package protocol

import "testing"

func TestMiscRDataNilReceiverSafe(t *testing.T) {
	buf := make([]byte, 8)
	tests := []struct {
		name     string
		rdata    RData
		rdlength uint16
		unpack   func(buf []byte, offset int, rdlength uint16) (int, error)
	}{
		{
			name:     "Raw",
			rdata:    (*RDataRaw)(nil),
			rdlength: 1,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataRaw
				return r.Unpack(buf, offset, rdlength)
			},
		},
		{
			name:     "OPT",
			rdata:    (*RDataOPT)(nil),
			rdlength: 4,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataOPT
				return r.Unpack(buf, offset, rdlength)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rdata.String(); got != "" {
				t.Errorf("nil %s.String() = %q, want empty", tt.name, got)
			}
			if got := tt.rdata.Len(); got != 0 {
				t.Errorf("nil %s.Len() = %d, want 0", tt.name, got)
			}
			if got := tt.rdata.Copy(); got != nil {
				t.Errorf("nil %s.Copy() = %#v, want nil", tt.name, got)
			}
			if n, err := tt.rdata.Pack(buf, 0); err == nil || n != 0 {
				t.Errorf("nil %s.Pack() = (%d, %v), want error and 0 bytes", tt.name, n, err)
			}
			if n, err := tt.unpack(buf, 0, tt.rdlength); err == nil || n != 0 {
				t.Errorf("nil %s.Unpack() = (%d, %v), want error and 0 bytes", tt.name, n, err)
			}
		})
	}
}

func TestRawRDataTypeNilReceiverSafe(t *testing.T) {
	var r *RDataRaw
	if got := r.Type(); got != 0 {
		t.Fatalf("nil RDataRaw.Type() = %d, want 0", got)
	}
}

func TestAddExtendedErrorHandlesNilAndMalformedOPT(t *testing.T) {
	AddExtendedError(nil, EDEBlocked, "ignored")

	msg := &Message{
		Additionals: []*ResourceRecord{
			{
				Name:  NewName(nil, true),
				Type:  TypeOPT,
				Class: 4096,
			},
		},
	}

	AddExtendedError(msg, EDEFiltered, "category: malware")

	opt := msg.GetOPT()
	if opt == nil {
		t.Fatal("GetOPT() returned nil")
	}
	optData, ok := opt.Data.(*RDataOPT)
	if !ok {
		t.Fatalf("OPT data type = %T, want *RDataOPT", opt.Data)
	}
	edeOpt := optData.GetOption(OptionCodeExtendedError)
	if edeOpt == nil {
		t.Fatal("missing EDE option")
	}
	ede, err := UnpackEDNS0ExtendedError(edeOpt.Data)
	if err != nil {
		t.Fatalf("UnpackEDNS0ExtendedError() error = %v", err)
	}
	if ede.InfoCode != EDEFiltered {
		t.Fatalf("EDE info code = %d, want %d", ede.InfoCode, EDEFiltered)
	}
}

func TestParseEDNS0HeaderRejectsInvalidRecord(t *testing.T) {
	if got := ParseEDNS0Header(nil); got != nil {
		t.Fatalf("ParseEDNS0Header(nil) = %+v, want nil", got)
	}

	rr := &ResourceRecord{
		Name:  NewName([]string{"example", "com"}, true),
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{192, 0, 2, 1}},
	}
	if got := ParseEDNS0Header(rr); got != nil {
		t.Fatalf("ParseEDNS0Header(non-OPT) = %+v, want nil", got)
	}
}

func TestEDNS0OptionHelpersNilReceiverSafe(t *testing.T) {
	var ecs *EDNS0ClientSubnet
	if got := ecs.Pack(); got != nil {
		t.Fatalf("nil ECS Pack() = %#v, want nil", got)
	}
	if got := ecs.IP(); got != nil {
		t.Fatalf("nil ECS IP() = %#v, want nil", got)
	}
	if got := ecs.String(); got != "" {
		t.Fatalf("nil ECS String() = %q, want empty", got)
	}
	if got := ecs.ToEDNS0Option(); got.Code != OptionCodeClientSubnet || got.Data != nil {
		t.Fatalf("nil ECS ToEDNS0Option() = %+v, want ECS code with nil data", got)
	}

	var nsid *EDNS0NSID
	if got := nsid.Pack(); got != nil {
		t.Fatalf("nil NSID Pack() = %#v, want nil", got)
	}
	if got := nsid.String(); got != "" {
		t.Fatalf("nil NSID String() = %q, want empty", got)
	}
	if got := nsid.ToEDNS0Option(); got.Code != OptionCodeNSID || got.Data != nil {
		t.Fatalf("nil NSID ToEDNS0Option() = %+v, want NSID code with nil data", got)
	}

	var ede *EDNS0ExtendedError
	if got := ede.Pack(); got != nil {
		t.Fatalf("nil EDE Pack() = %#v, want nil", got)
	}
	if got := ede.String(); got != "" {
		t.Fatalf("nil EDE String() = %q, want empty", got)
	}
	if got := ede.ToEDNS0Option(); got.Code != OptionCodeExtendedError || got.Data != nil {
		t.Fatalf("nil EDE ToEDNS0Option() = %+v, want EDE code with nil data", got)
	}

	var chain *EDNS0Chain
	if got := chain.Pack(); got != nil {
		t.Fatalf("nil CHAIN Pack() = %#v, want nil", got)
	}
	if got := chain.String(); got != "" {
		t.Fatalf("nil CHAIN String() = %q, want empty", got)
	}
	if got := chain.ToEDNS0Option(); got.Code != OptionCodeChain || got.Data != nil {
		t.Fatalf("nil CHAIN ToEDNS0Option() = %+v, want CHAIN code with nil data", got)
	}
}

func TestRDataOPTOptionHelpersNilReceiverSafe(t *testing.T) {
	var opt *RDataOPT

	opt.AddOption(OptionCodeNSID, []byte("ignored"))
	if got := opt.GetOption(OptionCodeNSID); got != nil {
		t.Fatalf("nil RDataOPT GetOption() = %#v, want nil", got)
	}
	opt.RemoveOption(OptionCodeNSID)
}
