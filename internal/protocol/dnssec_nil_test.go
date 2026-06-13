package protocol

import "testing"

func TestDNSSECRDataNilReceiverSafe(t *testing.T) {
	buf := make([]byte, 32)
	tests := []struct {
		name     string
		rdata    RData
		rdlength uint16
		unpack   func(buf []byte, offset int, rdlength uint16) (int, error)
	}{
		{
			name:     "ZONEMD",
			rdata:    (*RDataZONEMD)(nil),
			rdlength: 6,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataZONEMD
				return r.Unpack(buf, offset, rdlength)
			},
		},
		{
			name:     "DS",
			rdata:    (*RDataDS)(nil),
			rdlength: 4,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataDS
				return r.Unpack(buf, offset, rdlength)
			},
		},
		{
			name:     "DNSKEY",
			rdata:    (*RDataDNSKEY)(nil),
			rdlength: 4,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataDNSKEY
				return r.Unpack(buf, offset, rdlength)
			},
		},
		{
			name:     "RRSIG",
			rdata:    (*RDataRRSIG)(nil),
			rdlength: 19,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataRRSIG
				return r.Unpack(buf, offset, rdlength)
			},
		},
		{
			name:     "NSEC3PARAM",
			rdata:    (*RDataNSEC3PARAM)(nil),
			rdlength: 5,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataNSEC3PARAM
				return r.Unpack(buf, offset, rdlength)
			},
		},
		{
			name:     "NSEC3",
			rdata:    (*RDataNSEC3)(nil),
			rdlength: 6,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataNSEC3
				return r.Unpack(buf, offset, rdlength)
			},
		},
		{
			name:     "NSEC",
			rdata:    (*RDataNSEC)(nil),
			rdlength: 1,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataNSEC
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

func TestDNSSECAuxNilReceiverSafe(t *testing.T) {
	var nsec *RDataNSEC
	if nsec.HasType(TypeA) {
		t.Fatal("nil RDataNSEC.HasType(TypeA) = true, want false")
	}
	nsec.AddType(TypeA)
	nsec.RemoveType(TypeA)
	if got := nsec.TypeList(); got != nil {
		t.Fatalf("nil RDataNSEC.TypeList() = %#v, want nil", got)
	}

	var rrsig *RDataRRSIG
	if rrsig.IsExpired() {
		t.Fatal("nil RDataRRSIG.IsExpired() = true, want false")
	}
	if rrsig.IsExpiredAt(1) {
		t.Fatal("nil RDataRRSIG.IsExpiredAt() = true, want false")
	}
	if rrsig.IsInceptionValid() {
		t.Fatal("nil RDataRRSIG.IsInceptionValid() = true, want false")
	}
	if rrsig.IsInceptionValidAt(1) {
		t.Fatal("nil RDataRRSIG.IsInceptionValidAt() = true, want false")
	}
	inception, expiration := rrsig.ValidityPeriod()
	if !inception.IsZero() || !expiration.IsZero() {
		t.Fatalf("nil RDataRRSIG.ValidityPeriod() = (%v, %v), want zero times", inception, expiration)
	}
	if got := rrsig.SignerNameString(); got != "." {
		t.Fatalf("nil RDataRRSIG.SignerNameString() = %q, want root", got)
	}

	var dnskey *RDataDNSKEY
	if dnskey.IsZoneKey() {
		t.Fatal("nil RDataDNSKEY.IsZoneKey() = true, want false")
	}
	if dnskey.IsSEP() {
		t.Fatal("nil RDataDNSKEY.IsSEP() = true, want false")
	}
	if dnskey.IsKSK() {
		t.Fatal("nil RDataDNSKEY.IsKSK() = true, want false")
	}
	if dnskey.IsZSK() {
		t.Fatal("nil RDataDNSKEY.IsZSK() = true, want false")
	}
	if dnskey.IsRevoked() {
		t.Fatal("nil RDataDNSKEY.IsRevoked() = true, want false")
	}
	if got := dnskey.CalculateKeyTag(); got != 0 {
		t.Fatalf("nil RDataDNSKEY.CalculateKeyTag() = %d, want 0", got)
	}

	var nsec3param *RDataNSEC3PARAM
	if nsec3param.IsOptOut() {
		t.Fatal("nil RDataNSEC3PARAM.IsOptOut() = true, want false")
	}
	if got := nsec3param.ToNSEC3Params(); got.Algorithm != 0 || got.Iterations != 0 || got.Salt != nil {
		t.Fatalf("nil RDataNSEC3PARAM.ToNSEC3Params() = %#v, want zero", got)
	}
	if err := nsec3param.VerifyParams(); err == nil {
		t.Fatal("nil RDataNSEC3PARAM.VerifyParams() = nil, want error")
	}

	var nsec3 *RDataNSEC3
	if nsec3.IsOptOut() {
		t.Fatal("nil RDataNSEC3.IsOptOut() = true, want false")
	}
	if nsec3.HasType(TypeA) {
		t.Fatal("nil RDataNSEC3.HasType(TypeA) = true, want false")
	}
	nsec3.AddType(TypeA)
	nsec3.RemoveType(TypeA)
}
