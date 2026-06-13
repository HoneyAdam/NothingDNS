package protocol

import (
	"bytes"
	"strings"
	"testing"
)

func TestRDataSVCBRoundTrip(t *testing.T) {
	target, err := ParseName("svc.example.com.")
	if err != nil {
		t.Fatalf("ParseName failed: %v", err)
	}

	tests := []struct {
		name string
		svcb *RDataSVCB
	}{
		{
			name: "AliasMode_no_params",
			svcb: &RDataSVCB{
				Priority: 0,
				Target:   target,
				Params:   nil,
			},
		},
		{
			name: "ServiceMode_alpn_only",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2'}},
				},
			},
		},
		{
			name: "ServiceMode_alpn_and_port",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2', 2, 'h', '3'}},
					{Key: SvcParamKeyPort, Value: []byte{0x01, 0xBB}}, // port 443
				},
			},
		},
		{
			name: "ServiceMode_ipv4hint",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyIPv4Hint, Value: []byte{192, 0, 2, 1}},
				},
			},
		},
		{
			name: "ServiceMode_ipv6hint",
			svcb: &RDataSVCB{
				Priority: 2,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyIPv6Hint, Value: []byte{
						0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
					}},
				},
			},
		},
		{
			name: "ServiceMode_all_common_params",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2', 2, 'h', '3'}},
					{Key: SvcParamKeyPort, Value: []byte{0x01, 0xBB}},
					{Key: SvcParamKeyIPv4Hint, Value: []byte{192, 0, 2, 1, 198, 51, 100, 2}},
					{Key: SvcParamKeyIPv6Hint, Value: []byte{
						0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
					}},
				},
			},
		},
		{
			name: "ServiceMode_no_default_alpn",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2'}},
					{Key: SvcParamKeyNoDefaultALPN, Value: []byte{}},
				},
			},
		},
		{
			name: "ServiceMode_ech",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyECH, Value: []byte{0xAB, 0xCD, 0xEF, 0x01}},
				},
			},
		},
		{
			name: "ServiceMode_dohpath",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyDOHPath, Value: []byte("/dns-query{?dns}")},
				},
			},
		},
		{
			name: "AliasMode_root_target",
			svcb: &RDataSVCB{
				Priority: 0,
				Target:   &Name{Labels: []string{}, FQDN: true},
				Params:   nil,
			},
		},
		{
			name: "ServiceMode_mandatory",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyMandatory, Value: []byte{0x00, 0x01, 0x00, 0x03}}, // alpn, port
					{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2'}},
					{Key: SvcParamKeyPort, Value: []byte{0x01, 0xBB}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pack
			buf := make([]byte, 512)
			n, err := tt.svcb.Pack(buf, 0)
			if err != nil {
				t.Fatalf("Pack failed: %v", err)
			}
			if n != tt.svcb.Len() {
				t.Errorf("Packed %d bytes, expected %d", n, tt.svcb.Len())
			}

			// Unpack
			unpacked := &RDataSVCB{}
			n2, err := unpacked.Unpack(buf, 0, uint16(n))
			if err != nil {
				t.Fatalf("Unpack failed: %v", err)
			}
			if n2 != n {
				t.Errorf("Unpacked %d bytes, expected %d", n2, n)
			}

			// Verify Priority
			if unpacked.Priority != tt.svcb.Priority {
				t.Errorf("Priority mismatch: got %d, want %d", unpacked.Priority, tt.svcb.Priority)
			}

			// Verify Target
			if tt.svcb.Target != nil {
				if unpacked.Target == nil {
					t.Fatal("Target is nil after unpack")
				}
				if !strings.EqualFold(tt.svcb.Target.String(), unpacked.Target.String()) {
					t.Errorf("Target mismatch: got %q, want %q", unpacked.Target.String(), tt.svcb.Target.String())
				}
			}

			// Verify Params count
			if len(unpacked.Params) != len(tt.svcb.Params) {
				t.Fatalf("Params count mismatch: got %d, want %d", len(unpacked.Params), len(tt.svcb.Params))
			}

			// Verify each param
			for i, want := range tt.svcb.Params {
				got := unpacked.Params[i]
				if got.Key != want.Key {
					t.Errorf("Param[%d] Key mismatch: got %d, want %d", i, got.Key, want.Key)
				}
				if !bytes.Equal(got.Value, want.Value) {
					t.Errorf("Param[%d] Value mismatch: got %x, want %x", i, got.Value, want.Value)
				}
			}

			// Verify Type
			if unpacked.Type() != TypeSVCB {
				t.Errorf("Type() = %d, want %d", unpacked.Type(), TypeSVCB)
			}

			// Verify String() does not panic
			s := unpacked.String()
			if s == "" {
				t.Error("String() returned empty")
			}

			// Verify Copy
			copied := unpacked.Copy().(*RDataSVCB)
			if copied.Priority != unpacked.Priority {
				t.Error("Copy failed to preserve Priority")
			}
			if len(copied.Params) != len(unpacked.Params) {
				t.Error("Copy failed to preserve Params count")
			}
			for i, p := range copied.Params {
				if !bytes.Equal(p.Value, unpacked.Params[i].Value) {
					t.Errorf("Copy Param[%d] Value mismatch", i)
				}
			}
		})
	}
}

func TestRDataHTTPSRoundTrip(t *testing.T) {
	target, err := ParseName("cdn.example.com.")
	if err != nil {
		t.Fatalf("ParseName failed: %v", err)
	}

	tests := []struct {
		name  string
		https *RDataHTTPS
	}{
		{
			name: "AliasMode",
			https: &RDataHTTPS{
				Priority: 0,
				Target:   target,
				Params:   nil,
			},
		},
		{
			name: "ServiceMode_alpn_port",
			https: &RDataHTTPS{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2', 2, 'h', '3'}},
					{Key: SvcParamKeyPort, Value: []byte{0x01, 0xBB}},
				},
			},
		},
		{
			name: "ServiceMode_ipv4_ipv6",
			https: &RDataHTTPS{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyIPv4Hint, Value: []byte{10, 0, 0, 1}},
					{Key: SvcParamKeyIPv6Hint, Value: []byte{
						0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
					}},
				},
			},
		},
		{
			name: "AliasMode_root_target",
			https: &RDataHTTPS{
				Priority: 0,
				Target:   &Name{Labels: []string{}, FQDN: true},
				Params:   nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pack
			buf := make([]byte, 512)
			n, err := tt.https.Pack(buf, 0)
			if err != nil {
				t.Fatalf("Pack failed: %v", err)
			}
			if n != tt.https.Len() {
				t.Errorf("Packed %d bytes, expected %d", n, tt.https.Len())
			}

			// Unpack
			unpacked := &RDataHTTPS{}
			n2, err := unpacked.Unpack(buf, 0, uint16(n))
			if err != nil {
				t.Fatalf("Unpack failed: %v", err)
			}
			if n2 != n {
				t.Errorf("Unpacked %d bytes, expected %d", n2, n)
			}

			// Verify Priority
			if unpacked.Priority != tt.https.Priority {
				t.Errorf("Priority mismatch: got %d, want %d", unpacked.Priority, tt.https.Priority)
			}

			// Verify Target
			if tt.https.Target != nil {
				if unpacked.Target == nil {
					t.Fatal("Target is nil after unpack")
				}
				if !strings.EqualFold(tt.https.Target.String(), unpacked.Target.String()) {
					t.Errorf("Target mismatch: got %q, want %q", unpacked.Target.String(), tt.https.Target.String())
				}
			}

			// Verify Params count
			if len(unpacked.Params) != len(tt.https.Params) {
				t.Fatalf("Params count mismatch: got %d, want %d", len(unpacked.Params), len(tt.https.Params))
			}

			// Verify each param
			for i, want := range tt.https.Params {
				got := unpacked.Params[i]
				if got.Key != want.Key {
					t.Errorf("Param[%d] Key mismatch: got %d, want %d", i, got.Key, want.Key)
				}
				if !bytes.Equal(got.Value, want.Value) {
					t.Errorf("Param[%d] Value mismatch: got %x, want %x", i, got.Value, want.Value)
				}
			}

			// Verify Type
			if unpacked.Type() != TypeHTTPS {
				t.Errorf("Type() = %d, want %d", unpacked.Type(), TypeHTTPS)
			}

			// Verify String() does not panic
			s := unpacked.String()
			if s == "" {
				t.Error("String() returned empty")
			}

			// Verify Copy
			copied := unpacked.Copy().(*RDataHTTPS)
			if copied.Priority != unpacked.Priority {
				t.Error("Copy failed to preserve Priority")
			}
			if len(copied.Params) != len(unpacked.Params) {
				t.Error("Copy failed to preserve Params count")
			}
		})
	}
}

func TestSVCBCreateRData(t *testing.T) {
	// Verify createRData returns correct types
	svcbRData := createRData(TypeSVCB)
	if svcbRData == nil {
		t.Fatal("createRData(TypeSVCB) returned nil")
	}
	if _, ok := svcbRData.(*RDataSVCB); !ok {
		t.Errorf("createRData(TypeSVCB) returned %T, want *RDataSVCB", svcbRData)
	}

	httpsRData := createRData(TypeHTTPS)
	if httpsRData == nil {
		t.Fatal("createRData(TypeHTTPS) returned nil")
	}
	if _, ok := httpsRData.(*RDataHTTPS); !ok {
		t.Errorf("createRData(TypeHTTPS) returned %T, want *RDataHTTPS", httpsRData)
	}
}

func TestSVCBStringFormat(t *testing.T) {
	target, _ := ParseName("svc.example.com.")

	tests := []struct {
		name     string
		svcb     *RDataSVCB
		contains []string
	}{
		{
			name: "AliasMode",
			svcb: &RDataSVCB{
				Priority: 0,
				Target:   target,
			},
			contains: []string{"0", "svc.example.com."},
		},
		{
			name: "alpn_param",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2', 2, 'h', '3'}},
				},
			},
			contains: []string{"1", "svc.example.com.", "alpn=", "h2", "h3"},
		},
		{
			name: "port_param",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyPort, Value: []byte{0x01, 0xBB}},
				},
			},
			contains: []string{"port=443"},
		},
		{
			name: "ipv4hint_param",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyIPv4Hint, Value: []byte{192, 0, 2, 1}},
				},
			},
			contains: []string{"ipv4hint=192.0.2.1"},
		},
		{
			name: "ipv6hint_param",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyIPv6Hint, Value: []byte{
						0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
					}},
				},
			},
			contains: []string{"ipv6hint=2001:db8::1"},
		},
		{
			name: "no_default_alpn",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyNoDefaultALPN, Value: []byte{}},
				},
			},
			contains: []string{"no-default-alpn"},
		},
		{
			name: "dohpath_param",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyDOHPath, Value: []byte("/dns-query{?dns}")},
				},
			},
			contains: []string{"dohpath=/dns-query{?dns}"},
		},
		{
			name: "mandatory_param",
			svcb: &RDataSVCB{
				Priority: 1,
				Target:   target,
				Params: []SvcParam{
					{Key: SvcParamKeyMandatory, Value: []byte{0x00, 0x01, 0x00, 0x03}},
				},
			},
			contains: []string{"mandatory=alpn,port"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.svcb.String()
			for _, want := range tt.contains {
				if !strings.Contains(s, want) {
					t.Errorf("String() = %q, missing %q", s, want)
				}
			}
		})
	}
}

func TestSVCBPackBufferTooSmall(t *testing.T) {
	target, _ := ParseName("svc.example.com.")
	svcb := &RDataSVCB{
		Priority: 1,
		Target:   target,
		Params: []SvcParam{
			{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2'}},
		},
	}

	// Buffer too small for priority
	_, err := svcb.Pack(make([]byte, 1), 0)
	if err != ErrBufferTooSmall {
		t.Errorf("expected ErrBufferTooSmall for tiny buffer, got %v", err)
	}

	// Buffer too small for name
	_, err = svcb.Pack(make([]byte, 3), 0)
	if err != ErrBufferTooSmall {
		t.Errorf("expected ErrBufferTooSmall for name, got %v", err)
	}

	// Buffer too small for params
	nameSize := 2 + target.WireLength() // priority + name
	_, err = svcb.Pack(make([]byte, nameSize), 0)
	if err != ErrBufferTooSmall {
		t.Errorf("expected ErrBufferTooSmall for params, got %v", err)
	}
}

func TestSVCBPackRejectsOversizedParamValue(t *testing.T) {
	target, _ := ParseName("svc.example.com.")
	svcb := &RDataSVCB{
		Priority: 1,
		Target:   target,
		Params: []SvcParam{
			{Key: SvcParamKeyECH, Value: make([]byte, maxSvcParamValueLen+1)},
		},
	}

	_, err := svcb.Pack(make([]byte, svcb.Len()), 0)
	if err == nil {
		t.Fatal("SVCB Pack accepted a SvcParam value that cannot fit in uint16 length")
	}
	if !strings.Contains(err.Error(), "SvcParam value too long") {
		t.Fatalf("SVCB Pack error = %v, want oversized SvcParam value error", err)
	}

	https := &RDataHTTPS{
		Priority: svcb.Priority,
		Target:   target,
		Params:   svcb.Params,
	}
	_, err = https.Pack(make([]byte, https.Len()), 0)
	if err == nil {
		t.Fatal("HTTPS Pack accepted a SvcParam value that cannot fit in uint16 length")
	}
	if !strings.Contains(err.Error(), "SvcParam value too long") {
		t.Fatalf("HTTPS Pack error = %v, want oversized SvcParam value error", err)
	}
}

func TestSVCBPackRejectsUnsortedParams(t *testing.T) {
	target, _ := ParseName("svc.example.com.")
	tests := []struct {
		name   string
		params []SvcParam
	}{
		{
			name: "decreasing",
			params: []SvcParam{
				{Key: SvcParamKeyPort, Value: []byte{0x01, 0xbb}},
				{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2'}},
			},
		},
		{
			name: "duplicate",
			params: []SvcParam{
				{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2'}},
				{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '3'}},
			},
		},
	}

	for _, tt := range tests {
		t.Run("SVCB_"+tt.name, func(t *testing.T) {
			svcb := &RDataSVCB{Priority: 1, Target: target, Params: tt.params}
			_, err := svcb.Pack(make([]byte, svcb.Len()), 0)
			if err == nil {
				t.Fatal("SVCB Pack accepted SvcParams that are not strictly increasing")
			}
			if !strings.Contains(err.Error(), "strictly increasing") {
				t.Fatalf("SVCB Pack error = %v, want strict ordering error", err)
			}
		})

		t.Run("HTTPS_"+tt.name, func(t *testing.T) {
			https := &RDataHTTPS{Priority: 1, Target: target, Params: tt.params}
			_, err := https.Pack(make([]byte, https.Len()), 0)
			if err == nil {
				t.Fatal("HTTPS Pack accepted SvcParams that are not strictly increasing")
			}
			if !strings.Contains(err.Error(), "strictly increasing") {
				t.Fatalf("HTTPS Pack error = %v, want strict ordering error", err)
			}
		})
	}
}

func TestSVCBPackRejectsInvalidParamValues(t *testing.T) {
	target, _ := ParseName("svc.example.com.")
	tests := []struct {
		name  string
		param SvcParam
	}{
		{name: "mandatory_empty", param: SvcParam{Key: SvcParamKeyMandatory}},
		{name: "mandatory_odd_length", param: SvcParam{Key: SvcParamKeyMandatory, Value: []byte{0x00}}},
		{name: "alpn_empty", param: SvcParam{Key: SvcParamKeyALPN}},
		{name: "alpn_empty_protocol", param: SvcParam{Key: SvcParamKeyALPN, Value: []byte{0x00}}},
		{name: "alpn_truncated", param: SvcParam{Key: SvcParamKeyALPN, Value: []byte{0x03, 'h', '2'}}},
		{name: "no_default_alpn_non_empty", param: SvcParam{Key: SvcParamKeyNoDefaultALPN, Value: []byte{0x01}}},
		{name: "port_short", param: SvcParam{Key: SvcParamKeyPort, Value: []byte{0x01}}},
		{name: "ipv4hint_bad_length", param: SvcParam{Key: SvcParamKeyIPv4Hint, Value: []byte{192, 0, 2, 1, 5}}},
		{name: "ipv6hint_bad_length", param: SvcParam{Key: SvcParamKeyIPv6Hint, Value: make([]byte, 15)}},
	}

	for _, tt := range tests {
		t.Run("SVCB_"+tt.name, func(t *testing.T) {
			svcb := &RDataSVCB{Priority: 1, Target: target, Params: []SvcParam{tt.param}}
			_, err := svcb.Pack(make([]byte, svcb.Len()), 0)
			if err == nil {
				t.Fatal("SVCB Pack accepted an invalid SvcParam value")
			}
			if !strings.Contains(err.Error(), "invalid SvcParam") {
				t.Fatalf("SVCB Pack error = %v, want invalid SvcParam error", err)
			}
		})

		t.Run("HTTPS_"+tt.name, func(t *testing.T) {
			https := &RDataHTTPS{Priority: 1, Target: target, Params: []SvcParam{tt.param}}
			_, err := https.Pack(make([]byte, https.Len()), 0)
			if err == nil {
				t.Fatal("HTTPS Pack accepted an invalid SvcParam value")
			}
			if !strings.Contains(err.Error(), "invalid SvcParam") {
				t.Fatalf("HTTPS Pack error = %v, want invalid SvcParam error", err)
			}
		})
	}
}

func TestSVCBPackRejectsInconsistentParams(t *testing.T) {
	target, _ := ParseName("svc.example.com.")
	tests := []struct {
		name   string
		params []SvcParam
	}{
		{
			name: "no_default_alpn_without_alpn",
			params: []SvcParam{
				{Key: SvcParamKeyNoDefaultALPN},
			},
		},
		{
			name: "mandatory_includes_self",
			params: []SvcParam{
				{Key: SvcParamKeyMandatory, Value: []byte{0x00, 0x00}},
			},
		},
		{
			name: "mandatory_unsorted",
			params: []SvcParam{
				{Key: SvcParamKeyMandatory, Value: []byte{0x00, 0x03, 0x00, 0x01}},
				{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2'}},
				{Key: SvcParamKeyPort, Value: []byte{0x01, 0xbb}},
			},
		},
		{
			name: "mandatory_duplicate",
			params: []SvcParam{
				{Key: SvcParamKeyMandatory, Value: []byte{0x00, 0x01, 0x00, 0x01}},
				{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2'}},
			},
		},
		{
			name: "mandatory_missing_key",
			params: []SvcParam{
				{Key: SvcParamKeyMandatory, Value: []byte{0x00, 0x03}},
			},
		},
	}

	for _, tt := range tests {
		t.Run("SVCB_"+tt.name, func(t *testing.T) {
			svcb := &RDataSVCB{Priority: 1, Target: target, Params: tt.params}
			_, err := svcb.Pack(make([]byte, svcb.Len()), 0)
			if err == nil {
				t.Fatal("SVCB Pack accepted inconsistent SvcParams")
			}
			if !strings.Contains(err.Error(), "invalid SvcParam") {
				t.Fatalf("SVCB Pack error = %v, want invalid SvcParam error", err)
			}
		})

		t.Run("HTTPS_"+tt.name, func(t *testing.T) {
			https := &RDataHTTPS{Priority: 1, Target: target, Params: tt.params}
			_, err := https.Pack(make([]byte, https.Len()), 0)
			if err == nil {
				t.Fatal("HTTPS Pack accepted inconsistent SvcParams")
			}
			if !strings.Contains(err.Error(), "invalid SvcParam") {
				t.Fatalf("HTTPS Pack error = %v, want invalid SvcParam error", err)
			}
		})
	}
}

func TestSVCBAliasModeIgnoresParams(t *testing.T) {
	target, _ := ParseName("alias.example.com.")
	params := []SvcParam{
		{Key: SvcParamKeyALPN},
	}

	svcb := &RDataSVCB{Priority: 0, Target: target, Params: params}
	wantLen := 2 + target.WireLength()
	if svcb.Len() != wantLen {
		t.Fatalf("SVCB AliasMode Len() = %d, want %d", svcb.Len(), wantLen)
	}
	if strings.Contains(svcb.String(), "alpn") {
		t.Fatalf("SVCB AliasMode String() included ignored params: %q", svcb.String())
	}

	buf := make([]byte, 512)
	n, err := svcb.Pack(buf, 0)
	if err != nil {
		t.Fatalf("SVCB AliasMode Pack failed: %v", err)
	}
	if n != wantLen {
		t.Fatalf("SVCB AliasMode Pack wrote %d bytes, want %d", n, wantLen)
	}
	unpacked := &RDataSVCB{}
	if _, err := unpacked.Unpack(buf[:n], 0, uint16(n)); err != nil {
		t.Fatalf("SVCB AliasMode Unpack failed: %v", err)
	}
	if len(unpacked.Params) != 0 {
		t.Fatalf("SVCB AliasMode Unpack kept %d ignored params", len(unpacked.Params))
	}

	https := &RDataHTTPS{Priority: 0, Target: target, Params: params}
	if https.Len() != wantLen {
		t.Fatalf("HTTPS AliasMode Len() = %d, want %d", https.Len(), wantLen)
	}
	if strings.Contains(https.String(), "alpn") {
		t.Fatalf("HTTPS AliasMode String() included ignored params: %q", https.String())
	}
	n, err = https.Pack(buf, 0)
	if err != nil {
		t.Fatalf("HTTPS AliasMode Pack failed: %v", err)
	}
	if n != wantLen {
		t.Fatalf("HTTPS AliasMode Pack wrote %d bytes, want %d", n, wantLen)
	}
	unpackedHTTPS := &RDataHTTPS{}
	if _, err := unpackedHTTPS.Unpack(buf[:n], 0, uint16(n)); err != nil {
		t.Fatalf("HTTPS AliasMode Unpack failed: %v", err)
	}
	if len(unpackedHTTPS.Params) != 0 {
		t.Fatalf("HTTPS AliasMode Unpack kept %d ignored params", len(unpackedHTTPS.Params))
	}
}

func TestSVCBUnpackBufferTooSmall(t *testing.T) {
	svcb := &RDataSVCB{}

	// Empty buffer
	_, err := svcb.Unpack([]byte{}, 0, 0)
	if err != ErrBufferTooSmall {
		t.Errorf("expected ErrBufferTooSmall for empty buffer, got %v", err)
	}

	// Buffer with priority but no name
	_, err = svcb.Unpack([]byte{0x00, 0x01}, 0, 2)
	if err == nil {
		t.Error("expected error for buffer with no name data")
	}

	// Buffer with truncated SvcParam
	// Priority(2) + root name(1) + incomplete param header
	buf := []byte{0x00, 0x01, 0x00, 0x00, 0x01}
	_, err = svcb.Unpack(buf, 0, uint16(len(buf)))
	if err != ErrBufferTooSmall {
		t.Errorf("expected ErrBufferTooSmall for truncated param, got %v", err)
	}

	// Buffer with SvcParam header but truncated value
	buf = []byte{0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x05}
	_, err = svcb.Unpack(buf, 0, uint16(len(buf)))
	if err != ErrBufferTooSmall {
		t.Errorf("expected ErrBufferTooSmall for truncated param value, got %v", err)
	}
}

// Unpack is deliberately lenient about SvcParam key ordering and duplicates:
// per RFC 9460 §4.3 a resolver/forwarder treats SvcParams as opaque and passes
// them through; rejection is the end client's job at RRSet level. Pack still
// rejects these (TestSVCBPackRejectsUnsortedParams).
func TestSVCBUnpackAcceptsUnsortedParams(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
	}{
		{
			name: "decreasing",
			// Priority(2) + root TargetName(1) + port key(3) + alpn key(1).
			buf: []byte{
				0x00, 0x01, 0x00,
				0x00, 0x03, 0x00, 0x02, 0x01, 0xbb,
				0x00, 0x01, 0x00, 0x03, 0x02, 'h', '2',
			},
		},
		{
			name: "duplicate",
			// Priority(2) + root TargetName(1) + duplicate alpn keys.
			buf: []byte{
				0x00, 0x01, 0x00,
				0x00, 0x01, 0x00, 0x03, 0x02, 'h', '2',
				0x00, 0x01, 0x00, 0x03, 0x02, 'h', '3',
			},
		},
	}

	for _, tt := range tests {
		t.Run("SVCB_"+tt.name, func(t *testing.T) {
			svcb := &RDataSVCB{}
			n, err := svcb.Unpack(tt.buf, 0, uint16(len(tt.buf)))
			if err != nil {
				t.Fatalf("SVCB Unpack rejected unsorted SvcParams: %v", err)
			}
			if n != len(tt.buf) {
				t.Fatalf("SVCB Unpack consumed %d bytes, want %d", n, len(tt.buf))
			}
			if len(svcb.Params) != 2 {
				t.Fatalf("SVCB Unpack kept %d params, want 2 (pass-through)", len(svcb.Params))
			}
		})

		t.Run("HTTPS_"+tt.name, func(t *testing.T) {
			https := &RDataHTTPS{}
			n, err := https.Unpack(tt.buf, 0, uint16(len(tt.buf)))
			if err != nil {
				t.Fatalf("HTTPS Unpack rejected unsorted SvcParams: %v", err)
			}
			if n != len(tt.buf) {
				t.Fatalf("HTTPS Unpack consumed %d bytes, want %d", n, len(tt.buf))
			}
			if len(https.Params) != 2 {
				t.Fatalf("HTTPS Unpack kept %d params, want 2 (pass-through)", len(https.Params))
			}
		})
	}
}

// Unpack accepts semantically invalid SvcParam values (opaque pass-through per
// RFC 9460 §4.3); Pack still rejects them (TestSVCBPackRejectsInvalidParamValues).
func TestSVCBUnpackAcceptsInvalidParamValues(t *testing.T) {
	rdataWithParam := func(key uint16, value []byte) []byte {
		buf := []byte{0x00, 0x01, 0x00}
		buf = append(buf, byte(key>>8), byte(key))
		buf = append(buf, byte(len(value)>>8), byte(len(value)))
		buf = append(buf, value...)
		return buf
	}

	tests := []struct {
		name  string
		key   uint16
		value []byte
	}{
		{name: "mandatory_empty", key: SvcParamKeyMandatory},
		{name: "mandatory_odd_length", key: SvcParamKeyMandatory, value: []byte{0x00}},
		{name: "alpn_empty", key: SvcParamKeyALPN},
		{name: "alpn_empty_protocol", key: SvcParamKeyALPN, value: []byte{0x00}},
		{name: "alpn_truncated", key: SvcParamKeyALPN, value: []byte{0x03, 'h', '2'}},
		{name: "no_default_alpn_non_empty", key: SvcParamKeyNoDefaultALPN, value: []byte{0x01}},
		{name: "port_short", key: SvcParamKeyPort, value: []byte{0x01}},
		{name: "ipv4hint_bad_length", key: SvcParamKeyIPv4Hint, value: []byte{192, 0, 2, 1, 5}},
		{name: "ipv6hint_bad_length", key: SvcParamKeyIPv6Hint, value: make([]byte, 15)},
	}

	for _, tt := range tests {
		buf := rdataWithParam(tt.key, tt.value)
		t.Run("SVCB_"+tt.name, func(t *testing.T) {
			svcb := &RDataSVCB{}
			n, err := svcb.Unpack(buf, 0, uint16(len(buf)))
			if err != nil {
				t.Fatalf("SVCB Unpack rejected an SvcParam value it should pass through: %v", err)
			}
			if n != len(buf) {
				t.Fatalf("SVCB Unpack consumed %d bytes, want %d", n, len(buf))
			}
			if len(svcb.Params) != 1 || svcb.Params[0].Key != tt.key {
				t.Fatalf("SVCB Unpack params = %+v, want the received param preserved", svcb.Params)
			}
		})

		t.Run("HTTPS_"+tt.name, func(t *testing.T) {
			https := &RDataHTTPS{}
			n, err := https.Unpack(buf, 0, uint16(len(buf)))
			if err != nil {
				t.Fatalf("HTTPS Unpack rejected an SvcParam value it should pass through: %v", err)
			}
			if n != len(buf) {
				t.Fatalf("HTTPS Unpack consumed %d bytes, want %d", n, len(buf))
			}
			if len(https.Params) != 1 || https.Params[0].Key != tt.key {
				t.Fatalf("HTTPS Unpack params = %+v, want the received param preserved", https.Params)
			}
		})
	}
}

// Unpack accepts inconsistent SvcParams (opaque pass-through per RFC 9460
// §4.3); Pack still rejects them (TestSVCBPackRejectsInconsistentParams).
func TestSVCBUnpackAcceptsInconsistentParams(t *testing.T) {
	rdataWithParams := func(params []SvcParam) []byte {
		buf := []byte{0x00, 0x01, 0x00}
		for _, p := range params {
			buf = append(buf, byte(p.Key>>8), byte(p.Key))
			buf = append(buf, byte(len(p.Value)>>8), byte(len(p.Value)))
			buf = append(buf, p.Value...)
		}
		return buf
	}

	tests := []struct {
		name   string
		params []SvcParam
	}{
		{
			name: "no_default_alpn_without_alpn",
			params: []SvcParam{
				{Key: SvcParamKeyNoDefaultALPN},
			},
		},
		{
			name: "mandatory_includes_self",
			params: []SvcParam{
				{Key: SvcParamKeyMandatory, Value: []byte{0x00, 0x00}},
			},
		},
		{
			name: "mandatory_unsorted",
			params: []SvcParam{
				{Key: SvcParamKeyMandatory, Value: []byte{0x00, 0x03, 0x00, 0x01}},
				{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2'}},
				{Key: SvcParamKeyPort, Value: []byte{0x01, 0xbb}},
			},
		},
		{
			name: "mandatory_duplicate",
			params: []SvcParam{
				{Key: SvcParamKeyMandatory, Value: []byte{0x00, 0x01, 0x00, 0x01}},
				{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2'}},
			},
		},
		{
			name: "mandatory_missing_key",
			params: []SvcParam{
				{Key: SvcParamKeyMandatory, Value: []byte{0x00, 0x03}},
			},
		},
	}

	for _, tt := range tests {
		buf := rdataWithParams(tt.params)
		t.Run("SVCB_"+tt.name, func(t *testing.T) {
			svcb := &RDataSVCB{}
			n, err := svcb.Unpack(buf, 0, uint16(len(buf)))
			if err != nil {
				t.Fatalf("SVCB Unpack rejected inconsistent SvcParams it should pass through: %v", err)
			}
			if n != len(buf) {
				t.Fatalf("SVCB Unpack consumed %d bytes, want %d", n, len(buf))
			}
			if len(svcb.Params) != len(tt.params) {
				t.Fatalf("SVCB Unpack kept %d params, want %d (pass-through)", len(svcb.Params), len(tt.params))
			}
		})

		t.Run("HTTPS_"+tt.name, func(t *testing.T) {
			https := &RDataHTTPS{}
			n, err := https.Unpack(buf, 0, uint16(len(buf)))
			if err != nil {
				t.Fatalf("HTTPS Unpack rejected inconsistent SvcParams it should pass through: %v", err)
			}
			if n != len(buf) {
				t.Fatalf("HTTPS Unpack consumed %d bytes, want %d", n, len(buf))
			}
			if len(https.Params) != len(tt.params) {
				t.Fatalf("HTTPS Unpack kept %d params, want %d (pass-through)", len(https.Params), len(tt.params))
			}
		})
	}
}

func TestSVCBUnpackAliasModeDiscardsMalformedParams(t *testing.T) {
	// Priority(0) + root TargetName(1) + invalid ALPN value. AliasMode
	// recipients must ignore present SvcParams instead of using them.
	buf := []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}

	svcb := &RDataSVCB{}
	n, err := svcb.Unpack(buf, 0, uint16(len(buf)))
	if err != nil {
		t.Fatalf("SVCB AliasMode Unpack rejected ignored params: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("SVCB AliasMode Unpack consumed %d bytes, want %d", n, len(buf))
	}
	if len(svcb.Params) != 0 {
		t.Fatalf("SVCB AliasMode Unpack kept %d ignored params", len(svcb.Params))
	}

	https := &RDataHTTPS{}
	n, err = https.Unpack(buf, 0, uint16(len(buf)))
	if err != nil {
		t.Fatalf("HTTPS AliasMode Unpack rejected ignored params: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("HTTPS AliasMode Unpack consumed %d bytes, want %d", n, len(buf))
	}
	if len(https.Params) != 0 {
		t.Fatalf("HTTPS AliasMode Unpack kept %d ignored params", len(https.Params))
	}
}

func TestSVCBUnpackRejectsTargetNamePastRDLength(t *testing.T) {
	// Priority(2) + TargetName label length(1) + one label byte(1).
	// The remaining label bytes and root terminator are present in the buffer
	// but outside rdlength and must not be consumed.
	buf := []byte{0x00, 0x01, 0x03, 'w', 'w', 'w', 0x00}

	svcb := &RDataSVCB{}
	if _, err := svcb.Unpack(buf, 0, 4); err != ErrBufferTooSmall {
		t.Fatalf("SVCB expected ErrBufferTooSmall for target past rdlength, got %v", err)
	}

	https := &RDataHTTPS{}
	if _, err := https.Unpack(buf, 0, 4); err != ErrBufferTooSmall {
		t.Fatalf("HTTPS expected ErrBufferTooSmall for target past rdlength, got %v", err)
	}
}

// Regression test: a response containing an HTTPS record with out-of-order
// SvcParam keys (as some upstreams emit) must not fail the whole message —
// the valid A answer alongside it has to survive. Per RFC 9460 §4.3 a
// resolver/forwarder passes SvcParams through opaquely.
func TestUnpackMessageAcceptsHTTPSWithOutOfOrderParams(t *testing.T) {
	buf := []byte{
		// Header: ID=0x1234, flags QR|RD|RA, QD=1, AN=2, NS=0, AR=0.
		0x12, 0x34, 0x81, 0x80,
		0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		// Question: example.com HTTPS IN.
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x41, 0x00, 0x01,
		// Answer 1: HTTPS, name ptr to 0x0c, TTL 60, rdlength 16.
		0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10,
		// rdata: priority 1, root target, then port (key 3) BEFORE alpn (key 1).
		0x00, 0x01, 0x00,
		0x00, 0x03, 0x00, 0x02, 0x01, 0xbb,
		0x00, 0x01, 0x00, 0x03, 0x02, 'h', '2',
		// Answer 2: A, name ptr to 0x0c, TTL 60, rdata 192.0.2.1.
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
		192, 0, 2, 1,
	}

	msg, err := UnpackMessage(buf)
	if err != nil {
		t.Fatalf("UnpackMessage failed on message with out-of-order HTTPS SvcParams: %v", err)
	}
	if len(msg.Answers) != 2 {
		t.Fatalf("got %d answers, want 2", len(msg.Answers))
	}

	https, ok := msg.Answers[0].Data.(*RDataHTTPS)
	if !ok {
		t.Fatalf("answer 0 Data = %T, want *RDataHTTPS", msg.Answers[0].Data)
	}
	if https.Priority != 1 {
		t.Errorf("HTTPS priority = %d, want 1", https.Priority)
	}
	if len(https.Params) != 2 || https.Params[0].Key != SvcParamKeyPort || https.Params[1].Key != SvcParamKeyALPN {
		t.Fatalf("HTTPS params = %+v, want port then alpn preserved in received order", https.Params)
	}

	if msg.Answers[1].Type != TypeA {
		t.Fatalf("answer 1 type = %d, want A — valid sibling record must survive", msg.Answers[1].Type)
	}
}

func TestSVCBTypeMapEntries(t *testing.T) {
	// Verify TypeToString entries
	if s, ok := TypeToString[TypeSVCB]; !ok || s != "SVCB" {
		t.Errorf("TypeToString[TypeSVCB] = %q, %v; want \"SVCB\", true", s, ok)
	}
	if s, ok := TypeToString[TypeHTTPS]; !ok || s != "HTTPS" {
		t.Errorf("TypeToString[TypeHTTPS] = %q, %v; want \"HTTPS\", true", s, ok)
	}

	// Verify StringToType entries
	if v, ok := StringToType["SVCB"]; !ok || v != TypeSVCB {
		t.Errorf("StringToType[\"SVCB\"] = %d, %v; want %d, true", v, ok, TypeSVCB)
	}
	if v, ok := StringToType["HTTPS"]; !ok || v != TypeHTTPS {
		t.Errorf("StringToType[\"HTTPS\"] = %d, %v; want %d, true", v, ok, TypeHTTPS)
	}
}

func TestSVCBPackUnpackAtOffset(t *testing.T) {
	target, _ := ParseName("example.com.")
	svcb := &RDataSVCB{
		Priority: 1,
		Target:   target,
		Params: []SvcParam{
			{Key: SvcParamKeyPort, Value: []byte{0x00, 0x50}}, // port 80
		},
	}

	// Pack at a non-zero offset
	offset := 20
	buf := make([]byte, 512)
	n, err := svcb.Pack(buf, offset)
	if err != nil {
		t.Fatalf("Pack at offset %d failed: %v", offset, err)
	}

	// Unpack from the same offset
	unpacked := &RDataSVCB{}
	n2, err := unpacked.Unpack(buf, offset, uint16(n))
	if err != nil {
		t.Fatalf("Unpack at offset %d failed: %v", offset, err)
	}
	if n2 != n {
		t.Errorf("Unpacked %d bytes, expected %d", n2, n)
	}
	if unpacked.Priority != 1 {
		t.Errorf("Priority = %d, want 1", unpacked.Priority)
	}
	if len(unpacked.Params) != 1 || unpacked.Params[0].Key != SvcParamKeyPort {
		t.Error("Params not preserved through offset pack/unpack")
	}
}

func TestSVCBNilTarget(t *testing.T) {
	svcb := &RDataSVCB{
		Priority: 0,
		Target:   nil,
		Params:   nil,
	}

	// Len should handle nil target
	expectedLen := 2 + 1 // priority + root label
	if svcb.Len() != expectedLen {
		t.Errorf("Len() = %d, want %d", svcb.Len(), expectedLen)
	}

	// String should handle nil target
	s := svcb.String()
	if !strings.Contains(s, ".") {
		t.Errorf("String() = %q, expected root target", s)
	}

	// Pack should handle nil target
	buf := make([]byte, 512)
	n, err := svcb.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack with nil target failed: %v", err)
	}
	if n != expectedLen {
		t.Errorf("Packed %d bytes, expected %d", n, expectedLen)
	}

	// Copy should handle nil target
	copied := svcb.Copy().(*RDataSVCB)
	if copied.Target != nil {
		t.Error("Copy should preserve nil target")
	}
}

func TestSVCBMultipleIPv4Hints(t *testing.T) {
	target, _ := ParseName("svc.example.com.")
	// Two IPv4 addresses: 192.0.2.1 and 198.51.100.2
	svcb := &RDataSVCB{
		Priority: 1,
		Target:   target,
		Params: []SvcParam{
			{Key: SvcParamKeyIPv4Hint, Value: []byte{192, 0, 2, 1, 198, 51, 100, 2}},
		},
	}

	s := svcb.String()
	if !strings.Contains(s, "192.0.2.1") {
		t.Errorf("String() missing first IPv4: %q", s)
	}
	if !strings.Contains(s, "198.51.100.2") {
		t.Errorf("String() missing second IPv4: %q", s)
	}

	// Round-trip
	buf := make([]byte, 512)
	n, err := svcb.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}
	unpacked := &RDataSVCB{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}
	if !bytes.Equal(unpacked.Params[0].Value, svcb.Params[0].Value) {
		t.Error("IPv4 hint values not preserved")
	}
}

// TestSvcParamNameTableAgreement asserts that parseSvcParam and
// svcParamKeyFromString agree on every name in the shared
// svcParamKeysByName table, so a SvcParamKey added in one place cannot be
// accepted by SVCB/HTTPS rdata parsing yet rejected in mandatory= lists.
func TestSvcParamNameTableAgreement(t *testing.T) {
	for name, want := range svcParamKeysByName {
		// parseSvcParam must recognize the name. no-default-alpn takes no
		// value; every other key requires one ("0035" is valid hex for keys
		// without dedicated presentation syntax and also a valid alpn/port/
		// ech value; mandatory/hint/dohpath keys need a shaped value).
		field := name + "=0035"
		switch name {
		case "no-default-alpn":
			field = name
		case "mandatory":
			field = name + "=alpn"
		case "ipv4hint":
			field = name + "=192.0.2.1"
		case "ipv6hint":
			field = name + "=2001:db8::1"
		case "dohpath":
			field = name + "=/dns-query{?dns}"
		}
		param, ok := parseSvcParam(field)
		if !ok {
			t.Errorf("parseSvcParam(%q) rejected name from shared table", field)
			continue
		}
		if param.Key != want {
			t.Errorf("parseSvcParam(%q) key = %d, want %d", field, param.Key, want)
		}

		key, ok := svcParamKeyFromString(name)
		if name == "mandatory" {
			// RFC 9460 §8: "mandatory" must not appear inside its own list.
			if ok {
				t.Errorf("svcParamKeyFromString(%q) = %d, want rejection", name, key)
			}
			continue
		}
		if !ok {
			t.Errorf("svcParamKeyFromString(%q) rejected name from shared table", name)
			continue
		}
		if key != want {
			t.Errorf("svcParamKeyFromString(%q) = %d, want %d", name, key, want)
		}
	}
	if got := len(svcParamKeysByName); got != len(svcParamKeyToString) {
		t.Errorf("svcParamKeysByName has %d entries, svcParamKeyToString has %d (duplicate name?)",
			got, len(svcParamKeyToString))
	}
}
