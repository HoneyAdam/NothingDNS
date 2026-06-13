package transfer

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestDynamicDNSHandlerHandleUpdateRejectsNilRequest(t *testing.T) {
	handler := NewDynamicDNSHandler(map[string]*zone.Zone{})

	resp, err := handler.HandleUpdate(nil, net.ParseIP("127.0.0.1"))
	if err == nil || err.Error() != "nil UPDATE request" {
		t.Fatalf("HandleUpdate(nil) error = %v, want nil UPDATE request", err)
	}
	if resp != nil {
		t.Fatalf("HandleUpdate(nil) response = %#v, want nil", resp)
	}
}

func TestDynamicDNSHandlerHandleUpdateRejectsNilZoneQuestionName(t *testing.T) {
	handler := NewDynamicDNSHandler(map[string]*zone.Zone{})
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      0x3301,
			QDCount: 1,
			Flags:   protocol.Flags{Opcode: protocol.OpcodeUpdate},
		},
		Questions: []*protocol.Question{
			{QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
	}

	resp, err := handler.HandleUpdate(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleUpdate: %v", err)
	}
	if resp == nil {
		t.Fatal("HandleUpdate returned nil response")
	}
	if resp.Header.Flags.RCODE != protocol.RcodeFormatError {
		t.Fatalf("RCODE = %d, want FORMERR", resp.Header.Flags.RCODE)
	}
}

func TestNOTIFYSlaveHandlerHandleNOTIFYRejectsNilRequest(t *testing.T) {
	handler := NewNOTIFYSlaveHandler(map[string]*zone.Zone{})

	resp, err := handler.HandleNOTIFY(nil, net.ParseIP("127.0.0.1"))
	if err == nil || err.Error() != "nil NOTIFY request" {
		t.Fatalf("HandleNOTIFY(nil) error = %v, want nil NOTIFY request", err)
	}
	if resp != nil {
		t.Fatalf("HandleNOTIFY(nil) response = %#v, want nil", resp)
	}
}

func TestNOTIFYSlaveHandlerHandleNOTIFYRejectsNilQuestionName(t *testing.T) {
	handler := NewNOTIFYSlaveHandler(map[string]*zone.Zone{})
	if err := handler.AddNotifyAllowed("127.0.0.1/32"); err != nil {
		t.Fatalf("AddNotifyAllowed: %v", err)
	}
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      0x4401,
			QDCount: 1,
			Flags:   protocol.Flags{Opcode: protocol.OpcodeNotify},
		},
		Questions: []*protocol.Question{
			{QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
	}

	resp, err := handler.HandleNOTIFY(req, net.ParseIP("127.0.0.1"))
	if err == nil || err.Error() != "NOTIFY requires exactly one valid question" {
		t.Fatalf("HandleNOTIFY error = %v, want valid question error", err)
	}
	if resp == nil {
		t.Fatal("HandleNOTIFY returned nil response")
	}
	if resp.Header.Flags.RCODE != protocol.RcodeFormatError {
		t.Fatalf("RCODE = %d, want FORMERR", resp.Header.Flags.RCODE)
	}
}

func TestNOTIFYSlaveHandlerHandleNOTIFYSkipsNilSerialRecords(t *testing.T) {
	origin, err := protocol.ParseName("example.com.")
	if err != nil {
		t.Fatalf("ParseName origin: %v", err)
	}
	mname, err := protocol.ParseName("ns1.example.com.")
	if err != nil {
		t.Fatalf("ParseName mname: %v", err)
	}
	rname, err := protocol.ParseName("admin.example.com.")
	if err != nil {
		t.Fatalf("ParseName rname: %v", err)
	}
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  10,
		Refresh: 3600,
	}
	handler := NewNOTIFYSlaveHandler(map[string]*zone.Zone{"example.com.": z})
	if err := handler.AddNotifyAllowed("127.0.0.1/32"); err != nil {
		t.Fatalf("AddNotifyAllowed: %v", err)
	}
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      0x4402,
			QDCount: 1,
			NSCount: 2,
			Flags:   protocol.Flags{Opcode: protocol.OpcodeNotify},
		},
		Questions: []*protocol.Question{
			{Name: origin, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
		Answers: []*protocol.ResourceRecord{nil},
		Authorities: []*protocol.ResourceRecord{
			nil,
			{
				Name:  origin,
				Type:  protocol.TypeSOA,
				Class: protocol.ClassIN,
				Data: &protocol.RDataSOA{
					MName:   mname,
					RName:   rname,
					Serial:  11,
					Refresh: 3600,
					Retry:   600,
					Expire:  604800,
					Minimum: 86400,
				},
			},
		},
	}

	resp, err := handler.HandleNOTIFY(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleNOTIFY: %v", err)
	}
	if resp == nil {
		t.Fatal("HandleNOTIFY returned nil response")
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("RCODE = %d, want success", resp.Header.Flags.RCODE)
	}
}
