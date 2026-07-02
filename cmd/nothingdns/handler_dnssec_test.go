// Regression tests for the DNSSEC forwarding fixes: DO-bit upgrade on
// upstream queries, client-facing response scrubbing, and EDE error
// responses that must survive packing.

package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func makeClientQuery(t *testing.T, name string, qtype uint16) *protocol.Message {
	t.Helper()
	parsed, err := protocol.ParseName(name)
	if err != nil {
		t.Fatalf("parsing %q: %v", name, err)
	}
	return &protocol.Message{
		Header: protocol.Header{
			ID:      42,
			Flags:   protocol.NewQueryFlags(),
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: parsed, QType: qtype, QClass: protocol.ClassIN},
		},
	}
}

func optDO(msg *protocol.Message) (hasOPT, do bool) {
	opt := msg.GetOPT()
	if opt == nil {
		return false, false
	}
	h := protocol.ParseEDNS0Header(opt)
	return true, h != nil && h.DO
}

// withDOBit must add EDNS0+DO for clients that sent no OPT, without touching
// the original message. A validator that forwards DO-less queries gets
// RRSIG-less answers back and marks every signed domain Bogus.
func TestWithDOBit_NoClientOPT(t *testing.T) {
	msg := makeClientQuery(t, "example.com.", protocol.TypeA)

	fwd := withDOBit(msg)
	if fwd == msg {
		t.Fatal("withDOBit must copy when the client sent no OPT")
	}
	if has, do := optDO(fwd); !has || !do {
		t.Errorf("forwarded message: hasOPT=%v do=%v, want true/true", has, do)
	}
	if has, _ := optDO(msg); has {
		t.Error("original client message gained an OPT record — must stay untouched")
	}
	if int(fwd.Header.ARCount) != len(fwd.Additionals) {
		t.Errorf("ARCount %d != len(Additionals) %d", fwd.Header.ARCount, len(fwd.Additionals))
	}
}

// withDOBit must set DO on a copy while preserving the client's payload size
// and EDNS options (cookies, ECS) when the client sent OPT with DO=0.
func TestWithDOBit_ClientOPTWithoutDO(t *testing.T) {
	msg := makeClientQuery(t, "example.com.", protocol.TypeA)
	msg.SetEDNS0(1232, false)
	if optData, ok := msg.GetOPT().Data.(*protocol.RDataOPT); ok {
		optData.AddOption(protocol.OptionCodeCookie, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	}

	fwd := withDOBit(msg)
	if fwd == msg {
		t.Fatal("withDOBit must copy when the client OPT lacks DO")
	}
	if _, do := optDO(fwd); !do {
		t.Error("forwarded OPT must carry DO")
	}
	if got := fwd.GetOPT().Class; got != 1232 {
		t.Errorf("forwarded OPT payload size = %d, want client's 1232", got)
	}
	fwdOpt, ok := fwd.GetOPT().Data.(*protocol.RDataOPT)
	if !ok || fwdOpt.GetOption(protocol.OptionCodeCookie) == nil {
		t.Error("forwarded OPT lost the client's cookie option")
	}
	if _, do := optDO(msg); do {
		t.Error("original client OPT gained the DO bit — must stay untouched")
	}
}

// A client that already sent DO needs no rewrite at all.
func TestWithDOBit_ClientAlreadyDO(t *testing.T) {
	msg := makeClientQuery(t, "example.com.", protocol.TypeA)
	msg.SetEDNS0(4096, true)

	if fwd := withDOBit(msg); fwd != msg {
		t.Error("withDOBit must return the message unchanged when DO is already set")
	}
}

func makeSignedResponse(t *testing.T, qname string) *protocol.Message {
	t.Helper()
	name, err := protocol.ParseName(qname)
	if err != nil {
		t.Fatalf("parsing %q: %v", qname, err)
	}
	signer, _ := protocol.ParseName(qname)
	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
	}
	resp.AddAnswer(&protocol.ResourceRecord{
		Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
	})
	resp.AddAnswer(&protocol.ResourceRecord{
		Name: name, Type: protocol.TypeRRSIG, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataRRSIG{TypeCovered: protocol.TypeA, SignerName: signer, Signature: []byte{1}},
	})
	resp.SetEDNS0(1232, true)
	return resp
}

// A client that did not set DO must not receive DNSSEC records
// (RFC 4035 §3.2.2) — the upstream query is DO-upgraded for validation, so
// responses carry RRSIGs regardless of what the client asked for.
func TestScrubForClient_StripsRRSIGForDO0(t *testing.T) {
	query := makeClientQuery(t, "example.com.", protocol.TypeA)
	query.SetEDNS0(1232, false)
	resp := makeSignedResponse(t, "example.com.")

	scrubForClient(query, resp)

	for _, rr := range resp.Answers {
		if rr.Type == protocol.TypeRRSIG {
			t.Error("RRSIG survived scrub for a DO=0 client")
		}
	}
	if resp.GetOPT() == nil {
		t.Error("OPT must remain for an EDNS0 client")
	}
}

// A client that sent no EDNS0 must get neither OPT (RFC 6891 §7) nor
// DNSSEC records back.
func TestScrubForClient_StripsOPTForNonEDNSClient(t *testing.T) {
	query := makeClientQuery(t, "example.com.", protocol.TypeA)
	resp := makeSignedResponse(t, "example.com.")

	scrubForClient(query, resp)

	if resp.GetOPT() != nil {
		t.Error("OPT survived scrub for a non-EDNS client (RFC 6891 §7 violation)")
	}
}

// A DO=1 client gets the full DNSSEC response.
func TestScrubForClient_KeepsRRSIGForDO1(t *testing.T) {
	query := makeClientQuery(t, "example.com.", protocol.TypeA)
	query.SetEDNS0(4096, true)
	resp := makeSignedResponse(t, "example.com.")

	scrubForClient(query, resp)

	found := false
	for _, rr := range resp.Answers {
		if rr.Type == protocol.TypeRRSIG {
			found = true
		}
	}
	if !found {
		t.Error("RRSIG stripped for a DO=1 client")
	}
}

// An explicit RRSIG query keeps its RRSIGs even at DO=0 — the client asked
// for that type by name.
func TestScrubForClient_KeepsExplicitlyQueriedType(t *testing.T) {
	query := makeClientQuery(t, "example.com.", protocol.TypeRRSIG)
	resp := makeSignedResponse(t, "example.com.")

	scrubForClient(query, resp)

	found := false
	for _, rr := range resp.Answers {
		if rr.Type == protocol.TypeRRSIG {
			found = true
		}
	}
	if !found {
		t.Error("explicitly queried RRSIG records were stripped")
	}
}

// sendErrorWithEDE builds an OPT record inline; a nil OPT owner name makes
// Message.Pack fail and the client receives NOTHING (timeout instead of
// SERVFAIL). Pin that the produced response actually packs.
func TestSendErrorWithEDE_ResponsePacks(t *testing.T) {
	query := makeClientQuery(t, "example.com.", protocol.TypeA)
	query.SetEDNS0(1232, false) // client sent EDNS0 → response carries EDE OPT

	w := newCaptureWriter("192.0.2.10", "udp")
	sendErrorWithEDE(w, query, protocol.RcodeServerFailure, protocol.EDEDNSSECBogus, "DNSSEC validation failed")

	if w.msg == nil {
		t.Fatal("no response written")
	}
	opt := w.msg.GetOPT()
	if opt == nil {
		t.Fatal("EDE response lacks OPT record")
	}
	if opt.Name == nil {
		t.Fatal("OPT record has nil owner name — Pack would fail and the client would get no response at all")
	}
	buf := make([]byte, 4096)
	if _, err := w.msg.Pack(buf); err != nil {
		t.Fatalf("EDE error response does not pack: %v", err)
	}
}
