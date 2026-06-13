package protocol

import (
	"net"
	"testing"
)

func TestRDataANilReceiverSafe(t *testing.T) {
	var r *RDataA
	buf := make([]byte, 4)

	if got := r.String(); got != "" {
		t.Errorf("nil RDataA.String() = %q, want empty", got)
	}
	if got := r.Len(); got != 0 {
		t.Errorf("nil RDataA.Len() = %d, want 0", got)
	}
	if got := r.Copy(); got != nil {
		t.Errorf("nil RDataA.Copy() = %#v, want nil", got)
	}
	if got := r.IP(); got != nil {
		t.Errorf("nil RDataA.IP() = %v, want nil", got)
	}
	if n, err := r.Pack(buf, 0); err == nil || n != 0 {
		t.Errorf("nil RDataA.Pack() = (%d, %v), want error and 0 bytes", n, err)
	}
	if n, err := r.Unpack(buf, 0, 4); err == nil || n != 0 {
		t.Errorf("nil RDataA.Unpack() = (%d, %v), want error and 0 bytes", n, err)
	}

	r.SetIP(net.ParseIP("192.0.2.1"))
}

func TestNamingRDataNilReceiverSafe(t *testing.T) {
	buf := make([]byte, 8)
	tests := []struct {
		name     string
		rdata    RData
		rdlength uint16
		unpack   func(buf []byte, offset int, rdlength uint16) (int, error)
	}{
		{
			name:     "NAPTR",
			rdata:    (*RDataNAPTR)(nil),
			rdlength: 7,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataNAPTR
				return r.Unpack(buf, offset, rdlength)
			},
		},
		{
			name:     "SVCB",
			rdata:    (*RDataSVCB)(nil),
			rdlength: 3,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataSVCB
				return r.Unpack(buf, offset, rdlength)
			},
		},
		{
			name:     "HTTPS",
			rdata:    (*RDataHTTPS)(nil),
			rdlength: 3,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataHTTPS
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

func TestRDataAAAANilReceiverSafe(t *testing.T) {
	var r *RDataAAAA
	buf := make([]byte, 16)

	if got := r.String(); got != "" {
		t.Errorf("nil RDataAAAA.String() = %q, want empty", got)
	}
	if got := r.Len(); got != 0 {
		t.Errorf("nil RDataAAAA.Len() = %d, want 0", got)
	}
	if got := r.Copy(); got != nil {
		t.Errorf("nil RDataAAAA.Copy() = %#v, want nil", got)
	}
	if got := r.IP(); got != nil {
		t.Errorf("nil RDataAAAA.IP() = %v, want nil", got)
	}
	if n, err := r.Pack(buf, 0); err == nil || n != 0 {
		t.Errorf("nil RDataAAAA.Pack() = (%d, %v), want error and 0 bytes", n, err)
	}
	if n, err := r.Unpack(buf, 0, 16); err == nil || n != 0 {
		t.Errorf("nil RDataAAAA.Unpack() = (%d, %v), want error and 0 bytes", n, err)
	}

	r.SetIP(net.ParseIP("2001:db8::1"))
}

func TestNameRDataNilReceiverSafe(t *testing.T) {
	buf := []byte{0}
	tests := []struct {
		name   string
		rdata  RData
		unpack func([]byte, int, uint16) (int, error)
	}{
		{
			name:  "CNAME",
			rdata: (*RDataCNAME)(nil),
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataCNAME
				return r.Unpack(buf, offset, rdlength)
			},
		},
		{
			name:  "DNAME",
			rdata: (*RDataDNAME)(nil),
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataDNAME
				return r.Unpack(buf, offset, rdlength)
			},
		},
		{
			name:  "NS",
			rdata: (*RDataNS)(nil),
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataNS
				return r.Unpack(buf, offset, rdlength)
			},
		},
		{
			name:  "PTR",
			rdata: (*RDataPTR)(nil),
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataPTR
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
			if n, err := tt.unpack(buf, 0, 1); err == nil || n != 0 {
				t.Errorf("nil %s.Unpack() = (%d, %v), want error and 0 bytes", tt.name, n, err)
			}
		})
	}
}

func TestMailRDataNilReceiverSafe(t *testing.T) {
	buf := []byte{0}
	tests := []struct {
		name     string
		rdata    RData
		rdlength uint16
		unpack   func([]byte, int, uint16) (int, error)
	}{
		{
			name:     "MX",
			rdata:    (*RDataMX)(nil),
			rdlength: 1,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataMX
				return r.Unpack(buf, offset, rdlength)
			},
		},
		{
			name:     "TXT",
			rdata:    (*RDataTXT)(nil),
			rdlength: 0,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataTXT
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

func TestSecurityRDataNilReceiverSafe(t *testing.T) {
	buf := []byte{0, 0, 0}
	tests := []struct {
		name     string
		rdata    RData
		rdlength uint16
		unpack   func([]byte, int, uint16) (int, error)
	}{
		{
			name:     "CAA",
			rdata:    (*RDataCAA)(nil),
			rdlength: 2,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataCAA
				return r.Unpack(buf, offset, rdlength)
			},
		},
		{
			name:     "SSHFP",
			rdata:    (*RDataSSHFP)(nil),
			rdlength: 2,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataSSHFP
				return r.Unpack(buf, offset, rdlength)
			},
		},
		{
			name:     "TLSA",
			rdata:    (*RDataTLSA)(nil),
			rdlength: 3,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataTLSA
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

func TestAuthRDataNilReceiverSafe(t *testing.T) {
	buf := make([]byte, 22)
	tests := []struct {
		name     string
		rdata    RData
		rdlength uint16
		unpack   func([]byte, int, uint16) (int, error)
	}{
		{
			name:     "SOA",
			rdata:    (*RDataSOA)(nil),
			rdlength: 22,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataSOA
				return r.Unpack(buf, offset, rdlength)
			},
		},
		{
			name:     "SRV",
			rdata:    (*RDataSRV)(nil),
			rdlength: 7,
			unpack: func(buf []byte, offset int, rdlength uint16) (int, error) {
				var r *RDataSRV
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
