package e2e

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/dns64"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/upstream"
)

// startFakeUpstreamDNS starts a real UDP DNS server that plays the role of an
// IPv4-only upstream resolver:
//   - A queries for v4only.*   -> A 192.0.2.1
//   - AAAA queries for v4only.* -> NOERROR with no answers (NODATA)
//   - AAAA queries for dual.*  -> native AAAA 2001:db8::1
//   - any query for nx.*       -> NXDOMAIN
func startFakeUpstreamDNS(t *testing.T) *net.UDPAddr {
	t.Helper()

	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: req.Questions,
		}
		if len(req.Questions) == 0 {
			w.Write(resp)
			return
		}
		q := req.Questions[0]
		name := strings.ToLower(q.Name.String())

		switch {
		case strings.HasPrefix(name, "nx."):
			resp.Header.Flags = protocol.NewResponseFlags(protocol.RcodeNameError)
		case strings.HasPrefix(name, "dual.") && q.QType == protocol.TypeAAAA:
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  q.Name,
				Type:  protocol.TypeAAAA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data: &protocol.RDataAAAA{Address: [16]byte{
					0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
				}},
			})
		case q.QType == protocol.TypeA:
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  q.Name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
			})
			// AAAA for v4only.* falls through as NOERROR/NODATA (no answers).
		}
		w.Write(resp)
	})

	srv := server.NewUDPServer("127.0.0.1:0", handler)
	if err := srv.Listen(); err != nil {
		t.Fatalf("fake upstream Listen: %v", err)
	}
	t.Cleanup(func() { srv.Stop() })
	go srv.Serve()
	time.Sleep(10 * time.Millisecond)

	addr, ok := srv.Addr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("Expected *net.UDPAddr, got %T", srv.Addr())
	}
	return addr
}

// startDNS64FrontServer starts a real UDP DNS server whose handler forwards
// queries to the fake upstream via a real upstream.Client and applies DNS64
// synthesis (RFC 6147) for AAAA questions answered with A-only data.
func startDNS64FrontServer(t *testing.T, upstreamAddr *net.UDPAddr) *net.UDPAddr {
	t.Helper()

	synth, err := dns64.NewSynthesizer("", 0) // default 64:ff9b::/96 (RFC 6052)
	if err != nil {
		t.Fatalf("NewSynthesizer: %v", err)
	}

	client, err := upstream.NewClient(upstream.Config{
		Servers:     []string{upstreamAddr.String()},
		Strategy:    "round_robin",
		Timeout:     2 * time.Second,
		HealthCheck: time.Hour, // keep health probes out of the test window
	})
	if err != nil {
		t.Fatalf("upstream.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		servfail := func() {
			w.Write(&protocol.Message{
				Header:    protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeServerFailure)},
				Questions: req.Questions,
			})
		}
		if len(req.Questions) == 0 {
			servfail()
			return
		}
		q := req.Questions[0]

		resp, err := client.Query(req)
		if err != nil {
			servfail()
			return
		}

		// Stage 19 of the production pipeline: DNS64 synthesis. If the AAAA
		// answer came back empty (NOERROR/NODATA), re-query for A and embed
		// the IPv4 addresses into the NAT64 prefix.
		if synth.ShouldSynthesize(q, resp) {
			aQuery, err := protocol.NewQuery(req.Header.ID, q.Name.String(), protocol.TypeA)
			if err == nil {
				if aResp, err := client.Query(aQuery); err == nil {
					if syn := synth.SynthesizeResponse(q, aResp); syn != nil && len(syn.Answers) > 0 {
						resp = syn
					}
				}
			}
		}

		resp.Header.ID = req.Header.ID
		w.Write(resp)
	})

	srv := server.NewUDPServer("127.0.0.1:0", handler)
	if err := srv.Listen(); err != nil {
		t.Fatalf("front server Listen: %v", err)
	}
	t.Cleanup(func() { srv.Stop() })
	go srv.Serve()
	time.Sleep(10 * time.Millisecond)

	addr, ok := srv.Addr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("Expected *net.UDPAddr, got %T", srv.Addr())
	}
	return addr
}

// dns64UDPQuery performs a plain UDP DNS query against addr.
func dns64UDPQuery(t *testing.T, addr *net.UDPAddr, id uint16, name string, qtype uint16) *protocol.Message {
	t.Helper()

	query, err := protocol.NewQuery(id, name, qtype)
	if err != nil {
		t.Fatalf("NewQuery(%q): %v", name, err)
	}
	buf := make([]byte, 512)
	n, err := query.Pack(buf)
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial front server: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(buf[:n]); err != nil {
		t.Fatalf("send query: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	respBuf := make([]byte, 4096)
	rn, err := conn.Read(respBuf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	resp, err := protocol.UnpackMessage(respBuf[:rn])
	if err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	if resp.Header.ID != id {
		t.Fatalf("response ID = %#x, want %#x", resp.Header.ID, id)
	}
	return resp
}

// TestDNS64EndToEnd verifies RFC 6147 DNS64 synthesis through a real
// UDP server + upstream forwarding chain: an AAAA query for an IPv4-only
// name yields a synthesized AAAA inside the 64:ff9b::/96 NAT64 prefix,
// while native AAAA answers and NXDOMAINs pass through untouched.
func TestDNS64EndToEnd(t *testing.T) {
	upstreamAddr := startFakeUpstreamDNS(t)
	frontAddr := startDNS64FrontServer(t, upstreamAddr)

	t.Run("synthesizes AAAA from A-only upstream", func(t *testing.T) {
		resp := dns64UDPQuery(t, frontAddr, 0x6401, "v4only.example.com.", protocol.TypeAAAA)

		if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
			t.Fatalf("RCODE = %d, want NOERROR", resp.Header.Flags.RCODE)
		}
		if len(resp.Answers) != 1 {
			t.Fatalf("expected 1 synthesized answer, got %d", len(resp.Answers))
		}
		rr := resp.Answers[0]
		if rr.Type != protocol.TypeAAAA {
			t.Fatalf("answer type = %d, want AAAA", rr.Type)
		}
		aaaa, ok := rr.Data.(*protocol.RDataAAAA)
		if !ok {
			t.Fatalf("expected RDataAAAA, got %T", rr.Data)
		}
		// 64:ff9b::192.0.2.1 per RFC 6052 (96-bit well-known prefix).
		want := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1}
		if aaaa.Address != want {
			t.Errorf("synthesized AAAA = %v, want %v (64:ff9b::192.0.2.1)",
				net.IP(aaaa.Address[:]), net.IP(want[:]))
		}
		if rr.TTL != 300 {
			t.Errorf("synthesized TTL = %d, want 300 (preserved from A record)", rr.TTL)
		}
		if len(resp.Questions) != 1 || resp.Questions[0].QType != protocol.TypeAAAA {
			t.Errorf("question section should remain AAAA: %+v", resp.Questions)
		}
	})

	t.Run("native AAAA passes through unsynthesized", func(t *testing.T) {
		resp := dns64UDPQuery(t, frontAddr, 0x6402, "dual.example.com.", protocol.TypeAAAA)

		if len(resp.Answers) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
		}
		aaaa, ok := resp.Answers[0].Data.(*protocol.RDataAAAA)
		if !ok {
			t.Fatalf("expected RDataAAAA, got %T", resp.Answers[0].Data)
		}
		want := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
		if aaaa.Address != want {
			t.Errorf("AAAA = %v, want native 2001:db8::1", net.IP(aaaa.Address[:]))
		}
	})

	t.Run("NXDOMAIN is not synthesized", func(t *testing.T) {
		resp := dns64UDPQuery(t, frontAddr, 0x6403, "nx.example.com.", protocol.TypeAAAA)

		if resp.Header.Flags.RCODE != protocol.RcodeNameError {
			t.Fatalf("RCODE = %d, want NXDOMAIN (RFC 6147 §5.1.7: never synthesize over NXDOMAIN)", resp.Header.Flags.RCODE)
		}
		if len(resp.Answers) != 0 {
			t.Errorf("expected 0 answers for NXDOMAIN, got %d", len(resp.Answers))
		}
	})
}
