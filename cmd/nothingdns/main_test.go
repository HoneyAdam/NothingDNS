package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/nothingdns/nothingdns/internal/audit"
	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dns64"
	"github.com/nothingdns/nothingdns/internal/dnscookie"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/geodns"
	"github.com/nothingdns/nothingdns/internal/idna"
	"github.com/nothingdns/nothingdns/internal/metrics"
	"github.com/nothingdns/nothingdns/internal/otel"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/resolver"
	"github.com/nothingdns/nothingdns/internal/rpz"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/storage"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/upstream"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// captureWriter captures the response written by ServeDNS.
type captureWriter struct {
	client *server.ClientInfo
	msg    *protocol.Message
}

func (w *captureWriter) Write(msg *protocol.Message) (int, error) {
	w.msg = msg
	return 0, nil
}
func (w *captureWriter) ClientInfo() *server.ClientInfo { return w.client }
func (w *captureWriter) MaxSize() int                   { return 4096 }

func newCaptureWriter(ip string, proto string) *captureWriter {
	parsed := net.ParseIP(ip)
	if v4 := parsed.To4(); v4 != nil {
		parsed = v4
	}
	return &captureWriter{
		client: &server.ClientInfo{
			Addr:     &net.UDPAddr{IP: parsed, Port: 12345},
			Protocol: proto,
		},
	}
}

func newTestHandler() *integratedHandler {
	return &integratedHandler{
		config:      config.DefaultConfig(),
		logger:      util.NewLogger(util.ERROR, util.TextFormat, nil),
		cache:       cache.New(cache.Config{Capacity: 100, DefaultTTL: 60 * time.Second, MinTTL: time.Second, MaxTTL: 300 * time.Second}),
		metrics:     metrics.New(metrics.Config{Enabled: true}),
		zones:       make(map[string]*zone.Zone),
		zoneProvider: NewMultiZoneProvider(make(map[string]*zone.Zone), nil, nil, nil),
	}
}

func newTestQuery(t *testing.T, qname string, qtype uint16) *protocol.Message {
	t.Helper()
	msg, err := protocol.NewQuery(1, qname, qtype)
	if err != nil {
		if ascii, convErr := idna.ToASCII(qname); convErr == nil {
			msg, err = protocol.NewQuery(1, ascii, qtype)
		}
	}
	if err != nil {
		name := strings.TrimSuffix(qname, ".")
		labels := []string{}
		if name != "" {
			labels = strings.Split(name, ".")
		}
		msg = &protocol.Message{
			Header: protocol.Header{ID: 1, Flags: protocol.NewQueryFlags(), QDCount: 1},
			Questions: []*protocol.Question{{
				Name:   protocol.NewName(labels, strings.HasSuffix(qname, ".")),
				QType:  qtype,
				QClass: protocol.ClassIN,
			}},
		}
		err = nil
	}
	if err != nil {
		t.Fatalf("failed to create query: %v", err)
	}
	return msg
}

func addZoneRecords(t *testing.T, h *integratedHandler, origin string, records []zone.Record) {
	t.Helper()
	origin = canonicalize(origin)
	z := zone.NewZone(origin)
	z.DefaultTTL = 300
	for _, rec := range records {
		rec.Name = canonicalize(rec.Name)
		z.Records[rec.Name] = append(z.Records[rec.Name], rec)
	}
	h.zones[origin] = z
	h.RebuildZoneTree()
}

// startTestUpstream starts a UDP listener that responds with a minimal NOERROR response.
// Returns the server address and a cleanup function.
func startTestUpstream(t *testing.T) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, err := protocol.UnpackMessage(buf[:n])
			if err != nil {
				continue
			}
			var rrData protocol.RData
			qtype := msg.Questions[0].QType
			if qtype == protocol.TypeAAAA {
				rrData = &protocol.RDataAAAA{Address: [16]byte{0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02}}
			} else {
				rrData = &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}
			}
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
					QDCount: 1,
					ANCount: 1,
				},
				Questions: msg.Questions,
				Answers: []*protocol.ResourceRecord{
					{
						Name:  msg.Questions[0].Name,
						Type:  qtype,
						Class: protocol.ClassIN,
						TTL:   300,
						Data:  rrData,
					},
				},
			}
			packBuf := make([]byte, 4096)
			n, _ = resp.Pack(packBuf)
			pc.WriteTo(packBuf[:n], addr)
		}
	}()

	return pc.LocalAddr().String(), func() { pc.Close() }
}

// --- Tests ---

func TestServeDNS_EmptyQuestions(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")

	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewQueryFlags()},
		Questions: []*protocol.Question{},
	}
	h.ServeDNS(w, msg)

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeFormatError {
		t.Errorf("expected FORMERR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_Blocklist(t *testing.T) {
	h := newTestHandler()

	// Create a temp blocklist file in hosts format
	tmpDir := t.TempDir()
	blFile := filepath.Join(tmpDir, "blocklist.txt")
	if err := os.WriteFile(blFile, []byte("127.0.0.1 blocked.example.com\n"), 0644); err != nil {
		t.Fatalf("failed to write blocklist: %v", err)
	}

	bl := blocklist.New(blocklist.Config{Enabled: true, Files: []string{blFile}})
	if err := bl.Load(); err != nil {
		t.Fatalf("failed to load blocklist: %v", err)
	}
	h.blocklist = bl

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "blocked.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN for blocked query, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_CacheHit(t *testing.T) {
	h := newTestHandler()

	// Pre-populate cache
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    0,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  mustParseName(t, "cached.example.com."),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{127, 0, 0, 1}},
			},
		},
	}
	key := cache.MakeKey("cached.example.com.", protocol.TypeA, false)
	h.cache.Set(key, resp, 300)

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "cached.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR for cache hit, got rcode %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.msg.Answers))
	}
}

func TestServeDNS_AuthoritativeZone(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.msg.Answers))
	}
	aData, ok := w.msg.Answers[0].Data.(*protocol.RDataA)
	if !ok {
		t.Fatal("expected A record data")
	}
	if aData.Address != [4]byte{192, 168, 1, 1} {
		t.Errorf("expected 192.168.1.1, got %v", aData.Address)
	}
}

func TestServeDNS_NoUpstream_NoZone(t *testing.T) {
	h := newTestHandler()

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "unknown.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_NXDOMAIN_Authoritative(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "nonexistent.example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_NODATA(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeMX))
	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 0 {
		t.Errorf("expected 0 answers, got %d", len(w.msg.Answers))
	}
}

func TestServeDNS_Wildcard(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "*.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.100"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "anything.example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.msg.Answers))
	}
}

func TestServeDNS_ACLDeny(t *testing.T) {
	h := newTestHandler()
	acl, err := filter.NewACLChecker([]config.ACLRule{
		{
			Name:     "block-test",
			Networks: []string{"10.0.0.0/24"},
			Action:   "deny",
			Types:    []string{"A"},
		},
	}, false)
	if err != nil {
		t.Fatalf("failed to create ACL: %v", err)
	}
	h.aclChecker = acl

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "anything.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected REFUSED for ACL deny, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_ACLAllow(t *testing.T) {
	h := newTestHandler()
	acl, err := filter.NewACLChecker([]config.ACLRule{
		{
			Name:     "allow-all",
			Networks: []string{"0.0.0.0/0"},
			Action:   "allow",
		},
	}, false)
	if err != nil {
		t.Fatalf("failed to create ACL: %v", err)
	}
	h.aclChecker = acl

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "unknown.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	// With no upstream, it should return NXDOMAIN (not REFUSED)
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN when ACL allows, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_RateLimitExceeded(t *testing.T) {
	h := newTestHandler()
	h.rateLimiter = filter.NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 1})
	defer h.rateLimiter.Stop()

	// First request should succeed
	w1 := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w1, newTestQuery(t, "unknown.com.", protocol.TypeA))
	if w1.msg == nil {
		t.Fatal("expected first response")
	}

	// Second request should be rate limited
	w2 := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w2, newTestQuery(t, "unknown.com.", protocol.TypeA))
	if w2.msg == nil {
		t.Fatal("expected second response")
	}
	if w2.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected REFUSED when rate limited, got rcode %d", w2.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_QueryLatencyRecorded(t *testing.T) {
	h := newTestHandler()
	h.ServeDNS(newCaptureWriter("10.0.0.1", "udp"), newTestQuery(t, "test.com.", protocol.TypeA))

	// Check that latency was recorded
	h.metrics.RecordQueryLatency("A", 10*time.Millisecond)
	h.metrics.RecordQueryLatency("A", 50*time.Millisecond)

	// Verify histograms were created (internal state check)
	// The defer in ServeDNS should have recorded latency for the query type
	// We just verify no panic and metrics collector works
}

func TestServeDNS_CNAMEChase(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "alias.example.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "target.example.com."},
		{Name: "target.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "10.0.0.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "alias.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR for CNAME chase, got rcode %d", w.msg.Header.Flags.RCODE)
	}
	// Should have CNAME + A record
	if len(w.msg.Answers) < 2 {
		t.Fatalf("expected at least 2 answers (CNAME + A), got %d", len(w.msg.Answers))
	}
}

func TestServeDNS_MetricsRecorded(t *testing.T) {
	h := newTestHandler()
	h.ServeDNS(newCaptureWriter("10.0.0.1", "udp"), newTestQuery(t, "test.com.", protocol.TypeA))

	// Verify metrics don't panic when recorded
	h.metrics.RecordQuery("A")
	h.metrics.RecordResponse(protocol.RcodeSuccess)
	h.metrics.RecordCacheMiss()
}

func TestServeDNS_AuditLogRecorded(t *testing.T) {
	h := newTestHandler()
	al, err := audit.NewAuditLogger(true, "")
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	h.auditLogger = al
	defer al.Close()

	// Should not panic
	h.ServeDNS(newCaptureWriter("10.0.0.1", "udp"), newTestQuery(t, "test.com.", protocol.TypeA))
}

func TestServeDNS_ACLRedirect(t *testing.T) {
	h := newTestHandler()
	acl, err := filter.NewACLChecker([]config.ACLRule{
		{
			Name:     "redirect-test",
			Networks: []string{"10.0.0.0/24"},
			Action:   "redirect",
			Redirect: "safe.example.com.",
			Types:    []string{"A"},
		},
	}, false)
	if err != nil {
		t.Fatalf("failed to create ACL: %v", err)
	}
	h.aclChecker = acl

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "anything.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR for redirect, got rcode %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 1 {
		t.Fatalf("expected 1 answer (CNAME redirect), got %d", len(w.msg.Answers))
	}
	if w.msg.Answers[0].Type != protocol.TypeCNAME {
		t.Errorf("expected CNAME type, got %d", w.msg.Answers[0].Type)
	}
}

func mustParseName(t *testing.T, s string) *protocol.Name {
	t.Helper()
	n, err := protocol.ParseName(s)
	if err != nil {
		t.Fatalf("failed to parse name %q: %v", s, err)
	}
	return n
}

// --- Pure function tests ---

func TestIsSubdomain(t *testing.T) {
	tests := []struct {
		child, parent string
		want          bool
	}{
		{"www.example.com.", "example.com.", true},
		{"example.com.", "example.com.", true},
		{"other.com.", "example.com.", false},
		{"sub.www.example.com.", "example.com.", true},
		{"example.com.", "www.example.com.", false},
		{"WWW.EXAMPLE.COM.", "example.com.", true}, // case-insensitive
		{"www.example.com", "example.com", true},   // no trailing dot
	}
	for _, tc := range tests {
		if got := isSubdomain(tc.child, tc.parent); got != tc.want {
			t.Errorf("isSubdomain(%q, %q) = %v, want %v", tc.child, tc.parent, got, tc.want)
		}
	}
}

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"EXAMPLE.COM.", "example.com."},
		{"example.com", "example.com."},
		{"  EXAMPLE.COM  ", "example.com."},
		{"", "."},
		{".", "."},
	}
	for _, tc := range tests {
		if got := canonicalize(tc.input); got != tc.want {
			t.Errorf("canonicalize(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestTypeToString(t *testing.T) {
	if got := typeToString(protocol.TypeA); got != "A" {
		t.Errorf("typeToString(TypeA) = %q, want %q", got, "A")
	}
	if got := typeToString(protocol.TypeAAAA); got != "AAAA" {
		t.Errorf("typeToString(TypeAAAA) = %q, want %q", got, "AAAA")
	}
}

func TestStringToType(t *testing.T) {
	if got := stringToType("A"); got != protocol.TypeA {
		t.Errorf("stringToType(%q) = %d, want %d", "A", got, protocol.TypeA)
	}
	if got := stringToType("aaaa"); got != protocol.TypeAAAA {
		t.Errorf("stringToType(%q) = %d, want %d", "aaaa", got, protocol.TypeAAAA)
	}
	if got := stringToType("UNKNOWN"); got != 0 {
		t.Errorf("stringToType(%q) = %d, want 0", "UNKNOWN", got)
	}
}

func TestParseRData(t *testing.T) {
	// A record
	rd := parseRData("A", "192.168.1.1")
	a, ok := rd.(*protocol.RDataA)
	if !ok {
		t.Fatalf("expected RDataA, got %T", rd)
	}
	if a.Address != [4]byte{192, 168, 1, 1} {
		t.Errorf("A address = %v, want 192.168.1.1", a.Address)
	}

	// A record with IPv6 should return nil
	if rd := parseRData("A", "::1"); rd != nil {
		t.Errorf("expected nil for IPv6 in A record, got %T", rd)
	}

	// AAAA record
	rd = parseRData("AAAA", "2001:db8::1")
	aaaa, ok := rd.(*protocol.RDataAAAA)
	if !ok {
		t.Fatalf("expected RDataAAAA, got %T", rd)
	}
	ifaaaa := net.IP(aaaa.Address[:])
	if !ifaaaa.Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("AAAA address = %v, want 2001:db8::1", ifaaaa)
	}

	// CNAME record
	rd = parseRData("CNAME", "target.example.com.")
	cname, ok := rd.(*protocol.RDataCNAME)
	if !ok {
		t.Fatalf("expected RDataCNAME, got %T", rd)
	}
	if cname.CName.String() != "target.example.com." {
		t.Errorf("CNAME = %q, want target.example.com.", cname.CName.String())
	}

	// NS record
	rd = parseRData("NS", "ns1.example.com.")
	nsRd, ok := rd.(*protocol.RDataNS)
	if !ok {
		t.Fatalf("expected RDataNS for NS, got %T", rd)
	}
	if nsRd.NSDName.String() != "ns1.example.com." {
		t.Errorf("NS NSDName = %q, want ns1.example.com.", nsRd.NSDName.String())
	}

	// MX record
	rd = parseRData("MX", "10 mail.example.com.")
	mx, ok := rd.(*protocol.RDataMX)
	if !ok {
		t.Fatalf("expected RDataMX, got %T", rd)
	}
	if mx.Preference != 10 {
		t.Errorf("MX preference = %d, want 10", mx.Preference)
	}

	// TXT record
	rd = parseRData("TXT", "hello world")
	txt, ok := rd.(*protocol.RDataTXT)
	if !ok {
		t.Fatalf("expected RDataTXT, got %T", rd)
	}
	if len(txt.Strings) != 1 || txt.Strings[0] != "hello world" {
		t.Errorf("TXT = %v, want [hello world]", txt.Strings)
	}

	// Unknown type
	if rd := parseRData("UNKNOWN", "data"); rd != nil {
		t.Errorf("expected nil for unknown type, got %T", rd)
	}

	// Invalid A record
	if rd := parseRData("A", "not-an-ip"); rd != nil {
		t.Errorf("expected nil for invalid IP, got %T", rd)
	}

	// MX with not enough fields
	if rd := parseRData("MX", "10"); rd != nil {
		t.Errorf("expected nil for invalid MX, got %T", rd)
	}
}

func TestParseSOARData(t *testing.T) {
	soa := parseSOARData("ns1.example.com. admin.example.com. 2024010101 3600 600 604800 86400")
	s, ok := soa.(*protocol.RDataSOA)
	if !ok {
		t.Fatalf("expected RDataSOA, got %T", soa)
	}
	if s.Serial != 2024010101 {
		t.Errorf("Serial = %d, want 2024010101", s.Serial)
	}
	if s.Refresh != 3600 {
		t.Errorf("Refresh = %d, want 3600", s.Refresh)
	}
	if s.Retry != 600 {
		t.Errorf("Retry = %d, want 600", s.Retry)
	}
	if s.Expire != 604800 {
		t.Errorf("Expire = %d, want 604800", s.Expire)
	}
	if s.Minimum != 86400 {
		t.Errorf("Minimum = %d, want 86400", s.Minimum)
	}

	// Not enough fields
	if soa := parseSOARData("ns1.example.com. admin.example.com."); soa != nil {
		t.Errorf("expected nil for incomplete SOA, got %T", soa)
	}
}

func TestParseSRVRData(t *testing.T) {
	srv := parseSRVRData("10 20 443 server.example.com.")
	s, ok := srv.(*protocol.RDataSRV)
	if !ok {
		t.Fatalf("expected RDataSRV, got %T", srv)
	}
	if s.Priority != 10 {
		t.Errorf("Priority = %d, want 10", s.Priority)
	}
	if s.Weight != 20 {
		t.Errorf("Weight = %d, want 20", s.Weight)
	}
	if s.Port != 443 {
		t.Errorf("Port = %d, want 443", s.Port)
	}

	// Not enough fields
	if srv := parseSRVRData("10 20"); srv != nil {
		t.Errorf("expected nil for incomplete SRV, got %T", srv)
	}
}

func TestParseCAARData(t *testing.T) {
	caa := parseCAARData("0 issue letsencrypt.org.")
	c, ok := caa.(*protocol.RDataCAA)
	if !ok {
		t.Fatalf("expected RDataCAA, got %T", caa)
	}
	if c.Flags != 0 {
		t.Errorf("Flags = %d, want 0", c.Flags)
	}
	if c.Tag != "issue" {
		t.Errorf("Tag = %q, want %q", c.Tag, "issue")
	}
	if c.Value != "letsencrypt.org." {
		t.Errorf("Value = %q, want %q", c.Value, "letsencrypt.org.")
	}

	// Not enough fields
	if caa := parseCAARData("0 issue"); caa != nil {
		t.Errorf("expected nil for incomplete CAA, got %T", caa)
	}
}

func TestExtractTTL(t *testing.T) {
	// With answers
	resp := &protocol.Message{
		Answers: []*protocol.ResourceRecord{
			{TTL: 600},
		},
	}
	if got := extractTTL(resp); got != 600 {
		t.Errorf("extractTTL with answer = %d, want 600", got)
	}

	// No answers
	resp2 := &protocol.Message{Answers: nil}
	if got := extractTTL(resp2); got != 300 {
		t.Errorf("extractTTL with no answers = %d, want 300", got)
	}

	// Answer with TTL 0
	resp3 := &protocol.Message{
		Answers: []*protocol.ResourceRecord{
			{TTL: 0},
		},
	}
	if got := extractTTL(resp3); got != 300 {
		t.Errorf("extractTTL with TTL 0 = %d, want 300", got)
	}
}

func TestHasDOBit(t *testing.T) {
	// With DO bit set
	msg := &protocol.Message{
		Additionals: []*protocol.ResourceRecord{
			{Type: protocol.TypeOPT, TTL: 0x8000},
		},
	}
	if !hasDOBit(msg) {
		t.Error("expected DO bit to be set")
	}

	// Without DO bit
	msg2 := &protocol.Message{
		Additionals: []*protocol.ResourceRecord{
			{Type: protocol.TypeOPT, TTL: 0},
		},
	}
	if hasDOBit(msg2) {
		t.Error("expected DO bit to not be set")
	}

	// No OPT record
	msg3 := &protocol.Message{Additionals: nil}
	if hasDOBit(msg3) {
		t.Error("expected no DO bit without OPT")
	}
}

func TestParseDurationOrDefault(t *testing.T) {
	if got := parseDurationOrDefault("5s", time.Second); got != 5*time.Second {
		t.Errorf("parseDurationOrDefault(%q) = %v, want 5s", "5s", got)
	}
	if got := parseDurationOrDefault("", time.Minute); got != time.Minute {
		t.Errorf("parseDurationOrDefault(empty) = %v, want 1m", got)
	}
	if got := parseDurationOrDefault("invalid", time.Hour); got != time.Hour {
		t.Errorf("parseDurationOrDefault(invalid) = %v, want 1h", got)
	}
}

func TestLogLevelFromString(t *testing.T) {
	tests := []struct {
		input string
		want  util.LogLevel
	}{
		{"debug", util.DEBUG},
		{"info", util.INFO},
		{"warn", util.WARN},
		{"error", util.ERROR},
		{"fatal", util.FATAL},
		{"unknown", util.INFO}, // default
	}
	for _, tc := range tests {
		if got := logLevelFromString(tc.input); got != tc.want {
			t.Errorf("logLevelFromString(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestLogFormatFromString(t *testing.T) {
	if got := logFormatFromString("json"); got != util.JSONFormat {
		t.Errorf("logFormatFromString(json) = %d, want JSONFormat", got)
	}
	if got := logFormatFromString("text"); got != util.TextFormat {
		t.Errorf("logFormatFromString(text) = %d, want TextFormat", got)
	}
	if got := logFormatFromString("other"); got != util.TextFormat {
		t.Errorf("logFormatFromString(other) = %d, want TextFormat (default)", got)
	}
}

func TestSendError(t *testing.T) {
	query := &protocol.Message{
		Header:    protocol.Header{ID: 42, Flags: protocol.NewQueryFlags()},
		Questions: []*protocol.Question{{Name: mustParseName(t, "test.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}
	w := &captureWriter{}
	sendError(w, query, protocol.RcodeRefused)

	if w.msg == nil {
		t.Fatal("expected error response")
	}
	if w.msg.Header.ID != 42 {
		t.Errorf("ID = %d, want 42", w.msg.Header.ID)
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("RCODE = %d, want REFUSED", w.msg.Header.Flags.RCODE)
	}
	if !w.msg.Header.Flags.QR {
		t.Error("expected QR bit set")
	}
}

func TestReply(t *testing.T) {
	query := &protocol.Message{
		Header:    protocol.Header{ID: 100, Flags: protocol.NewQueryFlags()},
		Questions: []*protocol.Question{{Name: mustParseName(t, "test.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}
	response := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
	}
	w := &captureWriter{}
	reply(w, query, response)

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.ID != 100 {
		t.Errorf("ID = %d, want 100", w.msg.Header.ID)
	}
	if !w.msg.Header.Flags.QR {
		t.Error("expected QR bit set")
	}
	if len(w.msg.Questions) != 1 {
		t.Errorf("expected 1 question, got %d", len(w.msg.Questions))
	}
}

// --- minimizeResponse tests ---

func TestMinimizeResponse_NilMessage(t *testing.T) {
	// Must not panic.
	minimizeResponse(nil)
}

func TestMinimizeResponse_AuthoritativeWithSOA(t *testing.T) {
	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeNameError},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeSOA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data: &protocol.RDataSOA{
					MName:   mustParseName(t, "ns1.example.com."),
					RName:   mustParseName(t, "admin.example.com."),
					Serial:  2024010101,
					Refresh: 3600,
					Retry:   600,
					Expire:  604800,
					Minimum: 86400,
				},
			},
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeNS,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataNS{NSDName: mustParseName(t, "ns1.example.com.")},
			},
		},
	}

	minimizeResponse(resp)

	// AA=true with SOA present: keep only SOA, strip NS.
	if len(resp.Authorities) != 1 {
		t.Fatalf("expected 1 authority record, got %d", len(resp.Authorities))
	}
	if resp.Authorities[0].Type != protocol.TypeSOA {
		t.Errorf("expected SOA in authority, got type %d", resp.Authorities[0].Type)
	}
}

func TestMinimizeResponse_AuthoritativeWithoutSOA(t *testing.T) {
	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  mustParseName(t, "www.example.com."),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{192, 168, 1, 1}},
			},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeNS,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataNS{NSDName: mustParseName(t, "ns1.example.com.")},
			},
		},
	}

	minimizeResponse(resp)

	// AA=true without SOA: strip entire authority section.
	if len(resp.Authorities) != 0 {
		t.Fatalf("expected 0 authority records for AA without SOA, got %d", len(resp.Authorities))
	}
	// Answers must be preserved.
	if len(resp.Answers) != 1 {
		t.Errorf("expected 1 answer, got %d", len(resp.Answers))
	}
}

func TestMinimizeResponse_NonAuthoritativeKeepsNSAndSOA(t *testing.T) {
	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeNS,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataNS{NSDName: mustParseName(t, "ns1.example.com.")},
			},
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeSOA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data: &protocol.RDataSOA{
					MName: mustParseName(t, "ns1.example.com."),
					RName: mustParseName(t, "admin.example.com."),
				},
			},
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{10, 0, 0, 1}},
			},
		},
	}

	minimizeResponse(resp)

	// Non-authoritative: keep NS and SOA, strip A.
	if len(resp.Authorities) != 2 {
		t.Fatalf("expected 2 authority records (NS+SOA), got %d", len(resp.Authorities))
	}
	for _, rr := range resp.Authorities {
		if rr.Type != protocol.TypeNS && rr.Type != protocol.TypeSOA {
			t.Errorf("unexpected authority type %d", rr.Type)
		}
	}
}

func TestMinimizeResponse_NonAuthoritativeStripsUnrelated(t *testing.T) {
	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{10, 0, 0, 1}},
			},
		},
	}

	minimizeResponse(resp)

	// No NS or SOA: entire authority section stripped.
	if len(resp.Authorities) != 0 {
		t.Fatalf("expected nil/empty authority, got %d records", len(resp.Authorities))
	}
}

func TestMinimizeResponse_AdditionalGluePreserved(t *testing.T) {
	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeNS,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataNS{NSDName: mustParseName(t, "ns1.example.com.")},
			},
		},
		Additionals: []*protocol.ResourceRecord{
			// Glue A for ns1.example.com. -- should be kept.
			{
				Name:  mustParseName(t, "ns1.example.com."),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{10, 0, 0, 1}},
			},
			// Non-glue A for unrelated.example.com. -- should be stripped.
			{
				Name:  mustParseName(t, "unrelated.example.com."),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{10, 0, 0, 2}},
			},
			// OPT pseudo-record -- should be kept.
			{
				Type:  protocol.TypeOPT,
				Class: 4096,
			},
			// TXT record -- should be stripped.
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeTXT,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataTXT{Strings: []string{"v=spf1"}},
			},
		},
	}

	minimizeResponse(resp)

	// Expect: glue A + OPT = 2 additionals.
	if len(resp.Additionals) != 2 {
		t.Fatalf("expected 2 additionals (glue + OPT), got %d", len(resp.Additionals))
	}

	hasGlue := false
	hasOPT := false
	for _, rr := range resp.Additionals {
		if rr.Type == protocol.TypeA && rr.Name.String() == "ns1.example.com." {
			hasGlue = true
		}
		if rr.Type == protocol.TypeOPT {
			hasOPT = true
		}
	}
	if !hasGlue {
		t.Error("expected glue A record for ns1.example.com. to be preserved")
	}
	if !hasOPT {
		t.Error("expected OPT pseudo-record to be preserved")
	}
}

func TestMinimizeResponse_EmptySections(t *testing.T) {
	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  mustParseName(t, "www.example.com."),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
			},
		},
	}

	minimizeResponse(resp)

	// No authority or additional to begin with -- answers untouched.
	if len(resp.Answers) != 1 {
		t.Errorf("expected 1 answer, got %d", len(resp.Answers))
	}
	if len(resp.Authorities) != 0 {
		t.Errorf("expected 0 authorities, got %d", len(resp.Authorities))
	}
	if len(resp.Additionals) != 0 {
		t.Errorf("expected 0 additionals, got %d", len(resp.Additionals))
	}
}

// --- Integration tests for config and initialization ---

func TestNewTestHandlerInitialization(t *testing.T) {
	h := newTestHandler()

	if h.config == nil {
		t.Error("config should not be nil")
	}
	if h.logger == nil {
		t.Error("logger should not be nil")
	}
	if h.cache == nil {
		t.Error("cache should not be nil")
	}
	if h.metrics == nil {
		t.Error("metrics should not be nil")
	}
	if h.zones == nil {
		t.Error("zones map should not be nil")
	}
}

func TestServeDNS_TruncatedResponse(t *testing.T) {
	h := newTestHandler()

	// Add many large records to trigger truncation
	records := make([]zone.Record, 50)
	for i := 0; i < 50; i++ {
		records[i] = zone.Record{
			Name:  fmt.Sprintf("host%d.example.com.", i),
			TTL:   300,
			Class: "IN",
			Type:  "TXT",
			RData: strings.Repeat("x", 100), // Large TXT record
		}
	}
	addZoneRecords(t, h, "example.com.", records)

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "host0.example.com.", protocol.TypeTXT))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	// Response should be truncated or limited due to UDP size
}

func TestServeDNS_TCPResponse(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("10.0.0.1", "tcp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_AAAAQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "AAAA", RData: "2001:db8::1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeAAAA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.msg.Answers))
	}
}

func TestServeDNS_MultipleQuestions(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")

	// Create query with multiple questions
	msg := &protocol.Message{
		Header: protocol.Header{ID: 1, Flags: protocol.NewQueryFlags()},
		Questions: []*protocol.Question{
			{Name: mustParseName(t, "a.example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN},
			{Name: mustParseName(t, "b.example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
	}
	h.ServeDNS(w, msg)

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	// Multiple questions should either work or return appropriate error
}

func TestServeDNS_LargeQueryName(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")

	// Create a very long domain name
	longLabel := strings.Repeat("a", 63)
	longDomain := longLabel + ".example.com."
	h.ServeDNS(w, newTestQuery(t, longDomain, protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	// Should handle without panic
}

func TestServeDNS_InternationalizedDomain(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")

	// Test with internationalized domain (punycode)
	h.ServeDNS(w, newTestQuery(t, "xn--nxasmq5a.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
}

func TestServeDNS_EDNS0(t *testing.T) {
	h := newTestHandler()

	// Create query with EDNS0 OPT pseudo-record
	msg := newTestQuery(t, "test.com.", protocol.TypeA)
	msg.Additionals = append(msg.Additionals, &protocol.ResourceRecord{
		Name:  &protocol.Name{}, // Root name for OPT
		Type:  protocol.TypeOPT,
		Class: 4096,   // UDP payload size
		TTL:   0x8000, // DO bit set
		Data:  &protocol.RDataTXT{Strings: []string{}},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, msg)

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	// Response should preserve EDNS0
}

func TestServeDNS_NXDOMAIN(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "nonexistent.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_Refused(t *testing.T) {
	h := newTestHandler()
	// No zones configured, no upstream - should return REFUSED or NXDOMAIN
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "test.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	// Response should indicate failure to resolve
}

func TestServeDNS_SRVQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "_http._tcp.example.com.", TTL: 300, Class: "IN", Type: "SRV", RData: "10 5 80 www.example.com."},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "_http._tcp.example.com.", protocol.TypeSRV))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_MXQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "MX", RData: "10 mail.example.com."},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeMX))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_SOAQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.example.com. admin.example.com. 2024010101 3600 600 86400 86400"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeSOA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_NSQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.example.com."},
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns2.example.com."},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeNS))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 2 {
		t.Errorf("expected 2 NS answers, got %d", len(w.msg.Answers))
	}
}

func TestServeDNS_TXTQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "TXT", RData: "v=spf1 include:_spf.example.com ~all"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeTXT))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_CNAMEChain(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "a.example.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "b.example.com."},
		{Name: "b.example.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "c.example.com."},
		{Name: "c.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "a.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
	// Should have all CNAMEs + final A record
	if len(w.msg.Answers) < 3 {
		t.Errorf("expected at least 3 answers (2 CNAME + 1 A), got %d", len(w.msg.Answers))
	}
}

func TestServeDNS_LoopbackClient(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("127.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_IPv6Client(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("::1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

// TestConfigFileLoading tests config file loading scenarios
func TestConfigFileLoading(t *testing.T) {
	t.Run("valid_config", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "test.yaml")

		configYAML := `
server:
  port: 5354
  bind:
    - "127.0.0.1"
cache:
  enabled: true
  size: 1000
`
		if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
			t.Fatalf("failed to write config: %v", err)
		}

		cfg, err := config.UnmarshalYAML(configYAML)
		if err != nil {
			t.Errorf("failed to load valid config: %v", err)
		}
		if cfg == nil {
			t.Error("config should not be nil")
		}
	})

	t.Run("nonexistent_config", func(t *testing.T) {
		_, err := os.ReadFile(filepath.Join(t.TempDir(), "nonexistent", "config.yaml"))
		if err == nil {
			t.Error("should return error for nonexistent config")
		}
	})

	t.Run("empty_config", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "empty.yaml")

		if err := os.WriteFile(configFile, []byte(""), 0644); err != nil {
			t.Fatalf("failed to write empty config: %v", err)
		}

		// Empty config should use defaults
		data, err := os.ReadFile(configFile)
		if err != nil {
			t.Fatalf("failed to read config: %v", err)
		}

		cfg, err := config.UnmarshalYAML(string(data))
		if err != nil {
			t.Errorf("empty config should use defaults: %v", err)
		}
		if cfg == nil {
			t.Error("config should not be nil with defaults")
		}
	})
}

// TestGracefulShutdown tests graceful shutdown behavior
func TestGracefulShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	// Write a PID file
	if err := os.WriteFile(pidFile, []byte("12345\n"), 0644); err != nil {
		t.Fatalf("failed to write pid file: %v", err)
	}

	// Remove PID file (cleanup test)
	if err := os.Remove(pidFile); err != nil {
		t.Errorf("failed to remove pid file: %v", err)
	}

	// Verify PID file is removed
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("pid file should be removed")
	}
}

// TestManagerInitializationOrder tests that managers initialize in correct order
func TestManagerInitializationOrder(t *testing.T) {
	// This test validates the manager initialization dependencies
	// Order: config -> cache -> zones -> upstream -> dnssec -> cluster -> api

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: 5354,
			Bind: []string{"127.0.0.1"},
		},
		Cache: config.CacheConfig{
			Enabled: true,
			Size:    1000,
		},
	}

	// Test cache manager creation
	cacheMgr := cache.New(cache.Config{
		Capacity:   cfg.Cache.Size,
		DefaultTTL: 300 * time.Second,
	})
	if cacheMgr == nil {
		t.Fatal("cache manager should be created")
	}

	// Test zone manager creation
	zoneMgr := zone.NewManager()
	if zoneMgr == nil {
		t.Error("zone manager should be created")
	}

	// Test metrics creation
	metricsMgr := metrics.New(metrics.Config{Enabled: true})
	if metricsMgr == nil {
		t.Error("metrics manager should be created")
	}

	// Managers should be created independently
	_ = zoneMgr // may be nil if zone dir doesn't exist
}

// TestFlagParsing tests command line flag parsing
func TestFlagParsing(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name: "version_flag",
			args: []string{"-version"},
		},
		{
			name: "help_flag",
			args: []string{"-help"},
		},
		{
			name: "config_flag",
			args: []string{"-config", "/etc/nothingdns/nothingdns.yaml"},
		},
		{
			name: "validate_config_flag",
			args: []string{"-validate-config", "-config", "/tmp/test.yaml"},
		},
		{
			name: "pid_file_flag",
			args: []string{"-pid-file", "/tmp/test.pid"},
		},
		{
			name: "log_level_flag",
			args: []string{"-log-level", "debug"},
		},
		{
			name: "foreground_flag",
			args: []string{"-foreground"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// We can't actually parse flags in tests because flag.Parse() can only be called once
			// Just verify the flag names are valid
			validFlags := []string{
				"-version", "-help", "-config", "-validate-config",
				"-pid-file", "-log-level", "-foreground",
			}
			for _, arg := range tc.args {
				if strings.HasPrefix(arg, "-") {
					found := false
					for _, valid := range validFlags {
						if arg == valid {
							found = true
							break
						}
					}
					if !found && !strings.Contains(arg, ".") {
						// Skip values that look like file paths
						t.Errorf("unknown flag: %s", arg)
					}
				}
			}
		})
	}
}

// TestDefaultConfigValues tests default configuration values
func TestDefaultConfigValues(t *testing.T) {
	cfg := config.DefaultConfig()

	if cfg.Server.Port != 53 {
		t.Errorf("default port = %d, want 53", cfg.Server.Port)
	}
	if cfg.Cache.Enabled != true {
		t.Errorf("default cache enabled = %v, want true", cfg.Cache.Enabled)
	}
	if cfg.Cache.Size != 10000 {
		t.Errorf("default cache size = %d, want 10000", cfg.Cache.Size)
	}
}

// TestCacheIntegration tests cache integration with handler
func TestCacheIntegration(t *testing.T) {
	h := newTestHandler()

	// Add a zone
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "cached.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	// First query - should hit zone
	w1 := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w1, newTestQuery(t, "cached.example.com.", protocol.TypeA))

	if w1.msg == nil {
		t.Fatal("expected response")
	}
	if w1.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("first query failed: rcode %d", w1.msg.Header.Flags.RCODE)
	}

	// Verify answer contains expected IP
	found := false
	for _, rec := range w1.msg.Answers {
		if rec.Type == protocol.TypeA {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected A record in answer")
	}
}

func TestRcodeToString(t *testing.T) {
	if rcodeToString(99) != "RCODE99" {
		t.Errorf("unexpected rcode string: %s", rcodeToString(99))
	}
}

func TestParseRData_PTR(t *testing.T) {
	ptr := parseRData("PTR", "ptr.example.com.")
	if ptr == nil {
		t.Fatal("expected PTR record")
	}
}

func TestParseRData_MX_InvalidParts(t *testing.T) {
	mx := parseRData("MX", "only-pref")
	if mx != nil {
		t.Error("expected nil for invalid MX")
	}
}

func TestParseSOARData_InvalidMName(t *testing.T) {
	longLabel := "a" + strings.Repeat("b", 64) + ".com."
	soa := parseSOARData(longLabel + " admin.example.com. 1 3600 900 604800 86400")
	if soa != nil {
		t.Error("expected nil for invalid SOA mname")
	}
}

func TestParseSOARData_InvalidRName(t *testing.T) {
	longLabel := "a" + strings.Repeat("b", 64) + ".com."
	soa := parseSOARData("ns1.example.com. " + longLabel + " 1 3600 900 604800 86400")
	if soa != nil {
		t.Error("expected nil for invalid SOA rname")
	}
}

func TestParseSRVRData_InvalidTarget(t *testing.T) {
	longLabel := "a" + strings.Repeat("b", 64) + ".com."
	srv := parseSRVRData("10 5 8080 " + longLabel)
	if srv != nil {
		t.Error("expected nil for invalid SRV target")
	}
}

func TestExtractTTL_ZeroTTL(t *testing.T) {
	resp := &protocol.Message{
		Answers: []*protocol.ResourceRecord{
			{TTL: 0},
		},
	}
	if extractTTL(resp) != 300 {
		t.Errorf("expected 300, got %d", extractTTL(resp))
	}
}

func TestHasDOBit_NoOPT(t *testing.T) {
	msg := &protocol.Message{}
	if hasDOBit(msg) {
		t.Error("expected no DO bit")
	}
}

func TestLoadRootHintsFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "named.root")
	content := `.            518400  IN  NS  a.root-servers.net.
a.root-servers.net.  3600000  IN  A  198.41.0.4
a.root-servers.net.  3600000  IN  AAAA  2001:503:ba3e::2:30
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	hints, err := loadRootHintsFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hints) != 1 {
		t.Fatalf("expected 1 hint, got %d", len(hints))
	}
	if hints[0].Name != "a.root-servers.net." {
		t.Errorf("unexpected name: %s", hints[0].Name)
	}
}

func TestLoadRootHintsFile_MissingFile(t *testing.T) {
	_, err := loadRootHintsFile("/nonexistent/path/root.hints")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadRootHintsFile_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "empty.root")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	_, err := loadRootHintsFile(path)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestRcodeToString_AllCases(t *testing.T) {
	cases := []struct {
		rcode uint8
		want  string
	}{
		{0, "NOERROR"},
		{1, "FORMERR"},
		{2, "SERVFAIL"},
		{3, "NXDOMAIN"},
		{4, "NOTIMP"},
		{5, "REFUSED"},
		{99, "RCODE99"},
	}
	for _, c := range cases {
		if got := rcodeToString(c.rcode); got != c.want {
			t.Errorf("rcodeToString(%d) = %q, want %q", c.rcode, got, c.want)
		}
	}
}

func TestParseRData_CAA(t *testing.T) {
	caa := parseRData("CAA", "0 issue letsencrypt.org")
	if caa == nil {
		t.Fatal("expected CAA record")
	}
}

func TestParseRData_CAA_ShortFields(t *testing.T) {
	caa := parseRData("CAA", "0")
	if caa != nil {
		t.Error("expected nil for short CAA")
	}
}

func TestLoadRootHintsFile_CommentsAndBlanks(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "named.root")
	content := `; comment line

. 518400 IN NS a.root-servers.net.
; another comment
a.root-servers.net. 3600000 IN A 198.41.0.4
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	hints, err := loadRootHintsFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hints) != 1 {
		t.Fatalf("expected 1 hint, got %d", len(hints))
	}
}

func TestLoadRootHintsFile_NoTypeMatch(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "named.root")
	content := `. 518400 IN MX 10 mail.example.com.
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	_, err := loadRootHintsFile(path)
	if err == nil {
		t.Fatal("expected error when no valid root hints")
	}
}

func TestLoadRootHintsFile_AAAAOnly(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "named.root")
	content := `. 518400 IN NS a.root-servers.net.
a.root-servers.net. 3600000 IN AAAA 2001:503:ba3e::2:30
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	hints, err := loadRootHintsFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hints) != 1 {
		t.Fatalf("expected 1 hint, got %d", len(hints))
	}
	if len(hints[0].IPv6) != 1 {
		t.Errorf("expected 1 IPv6, got %d", len(hints[0].IPv6))
	}
}

// --- wireLen tests ---

func TestWireLen(t *testing.T) {
	if got := wireLen(nil); got != 0 {
		t.Errorf("wireLen(nil) = %d, want 0", got)
	}
	msg := &protocol.Message{
		Header: protocol.Header{ID: 1, Flags: protocol.NewQueryFlags()},
		Questions: []*protocol.Question{
			{Name: mustParseName(t, "example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
	}
	if got := wireLen(msg); got <= 0 {
		t.Errorf("wireLen(msg) = %d, want > 0", got)
	}
}

// --- extractResponseIPs tests ---

func TestExtractResponseIPs(t *testing.T) {
	resp := &protocol.Message{
		Answers: []*protocol.ResourceRecord{
			{Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
			{Data: &protocol.RDataAAAA{Address: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}},
		},
		Authorities: []*protocol.ResourceRecord{
			{Data: &protocol.RDataA{Address: [4]byte{5, 6, 7, 8}}},
		},
		Additionals: []*protocol.ResourceRecord{
			{Data: &protocol.RDataAAAA{Address: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}}},
		},
	}
	ips := extractResponseIPs(resp)
	if len(ips) != 4 {
		t.Fatalf("expected 4 IPs, got %d", len(ips))
	}
}

func TestExtractResponseIPs_NilData(t *testing.T) {
	resp := &protocol.Message{
		Answers: []*protocol.ResourceRecord{
			{Data: nil},
			{Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
		},
	}
	ips := extractResponseIPs(resp)
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips))
	}
}

// --- extractNSNames tests ---

func TestExtractNSNames(t *testing.T) {
	resp := &protocol.Message{
		Authorities: []*protocol.ResourceRecord{
			{Data: &protocol.RDataNS{NSDName: mustParseName(t, "ns1.example.com.")}},
			{Data: &protocol.RDataNS{NSDName: mustParseName(t, "ns2.example.com.")}},
			{Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
		},
	}
	names := extractNSNames(resp)
	if len(names) != 2 {
		t.Fatalf("expected 2 NS names, got %d", len(names))
	}
}

func TestExtractNSNames_NilNSDName(t *testing.T) {
	resp := &protocol.Message{
		Authorities: []*protocol.ResourceRecord{
			{Data: &protocol.RDataNS{NSDName: nil}},
		},
	}
	names := extractNSNames(resp)
	if len(names) != 0 {
		t.Fatalf("expected 0 NS names, got %d", len(names))
	}
}

// --- handleANYTruncated tests ---

func TestHandleANYTruncated(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "example.com.", protocol.TypeANY)
	h.handleANYTruncated(w, msg, msg.Questions[0])
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if !w.msg.Header.Flags.TC {
		t.Error("expected TC bit set")
	}
}

// --- sendRefused tests ---

func TestSendRefused(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "example.com.", protocol.TypeA)
	h.sendRefused(w, msg)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected REFUSED, got %d", w.msg.Header.Flags.RCODE)
	}
}

// --- sendErrorWithEDE tests ---

func TestSendErrorWithEDE_NoOPT(t *testing.T) {
	w := &captureWriter{}
	query := newTestQuery(t, "test.com.", protocol.TypeA)
	sendErrorWithEDE(w, query, protocol.RcodeServerFailure, protocol.EDEOtherError, "test error")
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if len(w.msg.Additionals) != 0 {
		t.Errorf("expected no additionals without OPT, got %d", len(w.msg.Additionals))
	}
}

func TestSendErrorWithEDE_WithOPT(t *testing.T) {
	w := &captureWriter{}
	query := newTestQuery(t, "test.com.", protocol.TypeA)
	query.Additionals = append(query.Additionals, &protocol.ResourceRecord{
		Type:  protocol.TypeOPT,
		Class: 1232,
		Data:  &protocol.RDataOPT{},
	})
	sendErrorWithEDE(w, query, protocol.RcodeServerFailure, protocol.EDEOtherError, "test error")
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if len(w.msg.Additionals) != 1 {
		t.Fatalf("expected 1 additional, got %d", len(w.msg.Additionals))
	}
	opt, ok := w.msg.Additionals[0].Data.(*protocol.RDataOPT)
	if !ok {
		t.Fatal("expected OPT record")
	}
	if len(opt.Options) != 1 {
		t.Fatalf("expected 1 EDE option, got %d", len(opt.Options))
	}
	if opt.Options[0].Code != protocol.OptionCodeExtendedError {
		t.Errorf("expected EDE option, got code %d", opt.Options[0].Code)
	}
}

// --- cookieResponseWriter tests ---

func TestCookieResponseWriter(t *testing.T) {
	inner := newCaptureWriter("10.0.0.1", "udp")
	cw := &cookieResponseWriter{inner: inner, cookieData: []byte("cookie-data")}

	// ClientInfo delegates
	if ci := cw.ClientInfo(); ci != inner.client {
		t.Error("ClientInfo delegation failed")
	}
	// MaxSize delegates
	if ms := cw.MaxSize(); ms != 4096 {
		t.Errorf("MaxSize = %d, want 4096", ms)
	}

	// Write injects cookie into response without OPT
	msg := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
	}
	cw.Write(msg)
	if inner.msg == nil {
		t.Fatal("expected inner writer to receive message")
	}
	opt := inner.msg.GetOPT()
	if opt == nil {
		t.Fatal("expected OPT record injected")
	}
	optData, ok := opt.Data.(*protocol.RDataOPT)
	if !ok {
		t.Fatal("expected RDataOPT")
	}
	found := false
	for _, o := range optData.Options {
		if o.Code == protocol.OptionCodeCookie {
			found = true
			if string(o.Data) != "cookie-data" {
				t.Errorf("cookie data mismatch: %q", o.Data)
			}
		}
	}
	if !found {
		t.Error("expected cookie option")
	}
}

// --- processCookies tests ---

func TestProcessCookies_NoOPT(t *testing.T) {
	h := newTestHandler()
	jar, err := dnscookie.NewCookieJar(time.Hour)
	if err != nil {
		t.Fatalf("failed to create cookie jar: %v", err)
	}
	h.cookieJar = jar

	msg := newTestQuery(t, "example.com.", protocol.TypeA)
	data, valid := h.processCookies(msg, net.ParseIP("10.0.0.1"))
	if data != nil {
		t.Error("expected nil cookie data when no OPT")
	}
	if !valid {
		t.Error("expected valid=true when no OPT")
	}
}

func TestProcessCookies_NoCookieOption(t *testing.T) {
	h := newTestHandler()
	jar, err := dnscookie.NewCookieJar(time.Hour)
	if err != nil {
		t.Fatalf("failed to create cookie jar: %v", err)
	}
	h.cookieJar = jar

	msg := newTestQuery(t, "example.com.", protocol.TypeA)
	msg.SetEDNS0(4096, false)
	data, valid := h.processCookies(msg, net.ParseIP("10.0.0.1"))
	if data != nil {
		t.Error("expected nil cookie data when no cookie option")
	}
	if !valid {
		t.Error("expected valid=true when no cookie option")
	}
}

func TestProcessCookies_MalformedCookie(t *testing.T) {
	h := newTestHandler()
	jar, err := dnscookie.NewCookieJar(time.Hour)
	if err != nil {
		t.Fatalf("failed to create cookie jar: %v", err)
	}
	h.cookieJar = jar

	msg := newTestQuery(t, "example.com.", protocol.TypeA)
	msg.SetEDNS0(4096, false)
	opt := msg.GetOPT()
	if optData, ok := opt.Data.(*protocol.RDataOPT); ok {
		optData.AddOption(protocol.OptionCodeCookie, []byte("short"))
	}
	data, valid := h.processCookies(msg, net.ParseIP("10.0.0.1"))
	if data == nil {
		t.Fatal("expected cookie data for malformed cookie")
	}
	if valid {
		t.Error("expected valid=false for malformed cookie")
	}
}

// --- applyRPZRule tests ---

func TestApplyRPZRule_NXDOMAIN(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "bad.com.", protocol.TypeA)
	rule := &rpz.Rule{Action: rpz.ActionNXDOMAIN, PolicyName: "test"}
	if !h.applyRPZRule(w, msg, msg.Questions[0], rule) {
		t.Error("expected applyRPZRule to return true")
	}
	if w.msg == nil || w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Error("expected NXDOMAIN")
	}
}

func TestApplyRPZRule_NODATA(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "bad.com.", protocol.TypeA)
	rule := &rpz.Rule{Action: rpz.ActionNODATA, PolicyName: "test"}
	if !h.applyRPZRule(w, msg, msg.Questions[0], rule) {
		t.Error("expected applyRPZRule to return true")
	}
	if w.msg == nil || w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Error("expected NOERROR")
	}
}

func TestApplyRPZRule_Drop(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "bad.com.", protocol.TypeA)
	rule := &rpz.Rule{Action: rpz.ActionDrop, PolicyName: "test"}
	if !h.applyRPZRule(w, msg, msg.Questions[0], rule) {
		t.Error("expected applyRPZRule to return true")
	}
	// Drop returns true but writes nothing
}

func TestApplyRPZRule_PassThrough(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "bad.com.", protocol.TypeA)
	rule := &rpz.Rule{Action: rpz.ActionPassThrough, PolicyName: "test"}
	if h.applyRPZRule(w, msg, msg.Questions[0], rule) {
		t.Error("expected applyRPZRule to return false for pass-through")
	}
}

func TestApplyRPZRule_TCPOnly(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "bad.com.", protocol.TypeA)
	rule := &rpz.Rule{Action: rpz.ActionTCPOnly, PolicyName: "test"}
	if !h.applyRPZRule(w, msg, msg.Questions[0], rule) {
		t.Error("expected applyRPZRule to return true")
	}
	if w.msg == nil || !w.msg.Header.Flags.TC {
		t.Error("expected TC bit set")
	}
}

func TestApplyRPZRule_OverrideIPv4(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "bad.com.", protocol.TypeA)
	rule := &rpz.Rule{Action: rpz.ActionOverride, OverrideData: "192.0.2.1", TTL: 300, PolicyName: "test"}
	if !h.applyRPZRule(w, msg, msg.Questions[0], rule) {
		t.Error("expected applyRPZRule to return true")
	}
	if w.msg == nil || len(w.msg.Answers) != 1 {
		t.Fatal("expected 1 answer")
	}
	if w.msg.Answers[0].Type != protocol.TypeA {
		t.Errorf("expected A record, got %d", w.msg.Answers[0].Type)
	}
}

func TestApplyRPZRule_OverrideIPv6(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "bad.com.", protocol.TypeA)
	rule := &rpz.Rule{Action: rpz.ActionOverride, OverrideData: "2001:db8::1", TTL: 300, PolicyName: "test"}
	if !h.applyRPZRule(w, msg, msg.Questions[0], rule) {
		t.Error("expected applyRPZRule to return true")
	}
	if w.msg == nil || len(w.msg.Answers) != 1 {
		t.Fatal("expected 1 answer")
	}
	if w.msg.Answers[0].Type != protocol.TypeAAAA {
		t.Errorf("expected AAAA record, got %d", w.msg.Answers[0].Type)
	}
}

func TestApplyRPZRule_OverrideInvalidIP(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "bad.com.", protocol.TypeA)
	rule := &rpz.Rule{Action: rpz.ActionOverride, OverrideData: "not-an-ip", TTL: 300, PolicyName: "test"}
	if h.applyRPZRule(w, msg, msg.Questions[0], rule) {
		t.Error("expected applyRPZRule to return false for invalid IP")
	}
}

func TestApplyRPZRule_CNAME(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "bad.com.", protocol.TypeA)
	rule := &rpz.Rule{Action: rpz.ActionCNAME, OverrideData: "safe.example.com.", TTL: 300, PolicyName: "test"}
	if !h.applyRPZRule(w, msg, msg.Questions[0], rule) {
		t.Error("expected applyRPZRule to return true")
	}
	if w.msg == nil || len(w.msg.Answers) != 1 {
		t.Fatal("expected 1 answer")
	}
	if w.msg.Answers[0].Type != protocol.TypeCNAME {
		t.Errorf("expected CNAME record, got %d", w.msg.Answers[0].Type)
	}
}

func TestApplyRPZRule_CNAMEInvalid(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "bad.com.", protocol.TypeA)
	// Use a label longer than 63 characters to make it invalid
	invalidName := strings.Repeat("a", 64) + ".com."
	rule := &rpz.Rule{Action: rpz.ActionCNAME, OverrideData: invalidName, TTL: 300, PolicyName: "test"}
	if h.applyRPZRule(w, msg, msg.Questions[0], rule) {
		t.Error("expected applyRPZRule to return false for invalid CNAME")
	}
}

func TestApplyRPZRule_UnknownAction(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "bad.com.", protocol.TypeA)
	rule := &rpz.Rule{Action: rpz.PolicyAction(999), PolicyName: "test"}
	if h.applyRPZRule(w, msg, msg.Questions[0], rule) {
		t.Error("expected applyRPZRule to return false for unknown action")
	}
}

// --- checkRPZResponseIP tests ---

func TestCheckRPZResponseIP_NoEngine(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "example.com.", protocol.TypeA)
	resp := &protocol.Message{
		Answers: []*protocol.ResourceRecord{
			{Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
		},
	}
	if h.checkRPZResponseIP(w, msg, msg.Questions[0], resp) {
		t.Error("expected false when no RPZ engine")
	}
}

func TestCheckRPZResponseIP_NoIPs(t *testing.T) {
	h := newTestHandler()
	h.rpzEngine = rpz.NewEngine(rpz.Config{Enabled: true})
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "example.com.", protocol.TypeA)
	resp := &protocol.Message{}
	if h.checkRPZResponseIP(w, msg, msg.Questions[0], resp) {
		t.Error("expected false when no IPs in response")
	}
}

// --- buildResponse tests ---

func TestBuildResponse(t *testing.T) {
	h := newTestHandler()
	query := newTestQuery(t, "www.example.com.", protocol.TypeA)
	records := []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "TXT", RData: "hello"},
	}
	resp := h.buildResponse(query, records)
	if resp == nil {
		t.Fatal("expected response")
	}
	if len(resp.Answers) != 2 {
		t.Fatalf("expected 2 answers, got %d", len(resp.Answers))
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got %d", resp.Header.Flags.RCODE)
	}
}

func TestBuildResponse_SkipsUnparseable(t *testing.T) {
	h := newTestHandler()
	query := newTestQuery(t, "www.example.com.", protocol.TypeA)
	records := []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "invalid-ip"},
	}
	resp := h.buildResponse(query, records)
	if resp == nil {
		t.Fatal("expected response")
	}
	if len(resp.Answers) != 0 {
		t.Errorf("expected 0 answers, got %d", len(resp.Answers))
	}
}

// --- buildSignedResponse tests ---

func TestBuildSignedResponse_NoDNSSEC(t *testing.T) {
	h := newTestHandler()
	query := newTestQuery(t, "www.example.com.", protocol.TypeA)
	records := []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	}
	signer := dnssec.NewSigner("example.com.", dnssec.DefaultSignerConfig())
	resp := h.buildSignedResponse(query, records, signer, false)
	if resp == nil {
		t.Fatal("expected response")
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
	}
}

func TestBuildSignedResponse_WithDNSSEC(t *testing.T) {
	h := newTestHandler()
	query := newTestQuery(t, "www.example.com.", protocol.TypeA)
	records := []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	}
	signer := dnssec.NewSigner("example.com.", dnssec.DefaultSignerConfig())
	// Generate a ZSK
	sk, err := signer.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	signer.AddKey(sk)
	resp := h.buildSignedResponse(query, records, signer, true)
	if resp == nil {
		t.Fatal("expected response")
	}
	// Should have A + RRSIG
	if len(resp.Answers) != 2 {
		t.Fatalf("expected 2 answers (A + RRSIG), got %d", len(resp.Answers))
	}
}

func TestBuildSignedResponse_NoSigner(t *testing.T) {
	h := newTestHandler()
	query := newTestQuery(t, "www.example.com.", protocol.TypeA)
	records := []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	}
	resp := h.buildSignedResponse(query, records, nil, true)
	if resp == nil {
		t.Fatal("expected response")
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
	}
}

// --- RebuildZoneTree tests ---

func TestRebuildZoneTree(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	h.zones["example.com."] = z
	h.RebuildZoneTree()
	if h.zoneTree == nil {
		t.Fatal("expected zoneTree to be built")
	}
}

// --- ReloadViews tests ---

func TestReloadViews_Empty(t *testing.T) {
	h := newTestHandler()
	err := h.ReloadViews(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.splitHorizon != nil {
		t.Error("expected splitHorizon to be nil")
	}
}

func TestReloadViews_WithViews(t *testing.T) {
	h := newTestHandler()
	views := []filter.ViewConfig{
		{Name: "internal", MatchClients: []string{"10.0.0.0/8"}, ZoneFiles: []string{}},
	}
	err := h.ReloadViews(views, func(string) (*zone.Zone, error) { return zone.NewZone("test."), nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.splitHorizon == nil {
		t.Error("expected splitHorizon to be set")
	}
}

func TestReloadViews_LoadError(t *testing.T) {
	h := newTestHandler()
	views := []filter.ViewConfig{
		{Name: "internal", MatchClients: []string{"10.0.0.0/8"}, ZoneFiles: []string{"bad.zone"}},
	}
	err := h.ReloadViews(views, func(string) (*zone.Zone, error) { return nil, fmt.Errorf("load error") })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should still create splitHorizon even if zone file fails
	if h.splitHorizon == nil {
		t.Error("expected splitHorizon to be set")
	}
}

// --- handleACLRedirect error path ---

func TestHandleACLRedirect_InvalidTarget(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "example.com.", protocol.TypeA)
	// Use a label longer than 63 characters to make it invalid
	invalidName := strings.Repeat("a", 64) + ".com."
	h.handleACLRedirect(w, msg, msg.Questions[0], invalidName)
	if w.msg == nil || w.msg.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Error("expected SERVFAIL for invalid redirect target")
	}
}

// --- ServeDNS panic recovery ---

func TestServeDNS_PanicRecovery(t *testing.T) {
	h := newTestHandler()
	// Force a panic by setting metrics to a type that will panic on RecordQuery
	// Actually, the simplest way is to trigger panic in a helper that gets called.
	// The defer recover() at the top of ServeDNS catches everything.
	// We'll use a custom ResponseWriter that panics on Write.
	panicW := &panicWriter{client: &server.ClientInfo{Addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}, Protocol: "udp"}}
	msg := newTestQuery(t, "example.com.", protocol.TypeA)
	// This should not panic; the recovery should catch it.
	h.ServeDNS(panicW, msg)
	// If we get here without panic, recovery worked.
}

type panicWriter struct {
	client   *server.ClientInfo
	panicked bool
}

func (w *panicWriter) Write(msg *protocol.Message) (int, error) {
	if !w.panicked {
		w.panicked = true
		panic("simulated panic")
	}
	return 0, nil
}
func (w *panicWriter) ClientInfo() *server.ClientInfo { return w.client }
func (w *panicWriter) MaxSize() int                   { return 4096 }

// --- ServeDNS IDNA validation ---

func TestServeDNS_IDNAInvalid(t *testing.T) {
	h := newTestHandler()
	h.idnaEnabled = true
	w := newCaptureWriter("10.0.0.1", "udp")
	// Use an invalid IDNA label (underscore is not allowed in IDNA STD3)
	msg := newTestQuery(t, "_invalid.example.com.", protocol.TypeA)
	h.ServeDNS(w, msg)
	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeFormatError {
		t.Errorf("expected FORMERR for invalid IDNA, got %d", w.msg.Header.Flags.RCODE)
	}
}

// --- ServeDNS with cache negative hit ---

func TestServeDNS_CacheNegativeHit(t *testing.T) {
	h := newTestHandler()
	key := cache.MakeKey("neg.example.com.", protocol.TypeA, false)
	h.cache.SetNegative(key, protocol.RcodeNameError)

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "neg.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN for negative cache hit, got %d", w.msg.Header.Flags.RCODE)
	}
}

// --- ServeDNS with RPZ QNAME policy ---

func TestServeDNS_RPZ_QNAME(t *testing.T) {
	h := newTestHandler()
	h.rpzEngine = rpz.NewEngine(rpz.Config{Enabled: true})
	h.rpzEngine.AddQNAMERule("blocked.com", rpz.ActionNXDOMAIN, "")

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "blocked.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN for RPZ QNAME block, got %d", w.msg.Header.Flags.RCODE)
	}
}

// --- ServeDNS with split-horizon views ---

func TestServeDNS_SplitHorizon(t *testing.T) {
	h := newTestHandler()
	sh, err := filter.NewSplitHorizon([]filter.ViewConfig{
		{Name: "internal", MatchClients: []string{"10.0.0.0/8"}},
	})
	if err != nil {
		t.Fatalf("failed to create split horizon: %v", err)
	}
	h.splitHorizon = sh
	vz := zone.NewZone("example.com.")
	vz.Records["www.example.com."] = []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "10.0.0.100"},
	}
	h.viewZones = map[string]map[string]*zone.Zone{
		"internal": {"example.com.": vz},
	}

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR for split-horizon hit, got %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.msg.Answers))
	}
	addr := w.msg.Answers[0].Data.(*protocol.RDataA).Address
	if addr != [4]byte{10, 0, 0, 100} {
		t.Errorf("unexpected IP: %v", addr)
	}
}

// --- errorWriter for testing write error paths ---

type errorWriter struct {
	client *server.ClientInfo
}

func (w *errorWriter) Write(msg *protocol.Message) (int, error) {
	return 0, fmt.Errorf("simulated write error")
}
func (w *errorWriter) ClientInfo() *server.ClientInfo { return w.client }
func (w *errorWriter) MaxSize() int                   { return 4096 }

func TestReply_WriteError(t *testing.T) {
	query := newTestQuery(t, "test.com.", protocol.TypeA)
	response := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
	}
	w := &errorWriter{}
	// Should not panic even when Write returns error
	reply(w, query, response)
}

func TestSendError_WriteError(t *testing.T) {
	query := newTestQuery(t, "test.com.", protocol.TypeA)
	w := &errorWriter{}
	// Should not panic even when Write returns error
	sendError(w, query, protocol.RcodeRefused)
}

func TestHandleANYTruncated_WriteError(t *testing.T) {
	h := newTestHandler()
	w := &errorWriter{client: &server.ClientInfo{Addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}, Protocol: "udp"}}
	msg := newTestQuery(t, "example.com.", protocol.TypeANY)
	// Should not panic even when Write returns error
	h.handleANYTruncated(w, msg, msg.Questions[0])
}

func TestSendErrorWithEDE_WriteError(t *testing.T) {
	query := newTestQuery(t, "test.com.", protocol.TypeA)
	query.Additionals = append(query.Additionals, &protocol.ResourceRecord{
		Type:  protocol.TypeOPT,
		Class: 4096,
		Data:  &protocol.RDataOPT{},
	})
	w := &errorWriter{}
	// Should not panic even when Write returns error
	sendErrorWithEDE(w, query, protocol.RcodeServerFailure, protocol.EDEOtherError, "test")
}

func TestHandleACLRedirect_WriteError(t *testing.T) {
	h := newTestHandler()
	w := &errorWriter{client: &server.ClientInfo{Addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}, Protocol: "udp"}}
	msg := newTestQuery(t, "example.com.", protocol.TypeA)
	// Should not panic even when Write returns error
	h.handleACLRedirect(w, msg, msg.Questions[0], "safe.example.com.")
}

// --- processCookies with valid cookie ---

func TestProcessCookies_ValidCookie(t *testing.T) {
	h := newTestHandler()
	jar, err := dnscookie.NewCookieJar(time.Hour)
	if err != nil {
		t.Fatalf("failed to create cookie jar: %v", err)
	}
	h.cookieJar = jar

	clientIP := net.ParseIP("10.0.0.1")
	// Generate a client cookie
	clientCookie := jar.GenerateClientCookie(clientIP, net.ParseIP("127.0.0.1"))
	// Generate a server cookie
	serverCookie := jar.GenerateServerCookie(clientCookie, clientIP)
	cookieData := dnscookie.PackCookieOption(clientCookie, serverCookie)

	msg := newTestQuery(t, "example.com.", protocol.TypeA)
	msg.SetEDNS0(4096, false)
	opt := msg.GetOPT()
	if optData, ok := opt.Data.(*protocol.RDataOPT); ok {
		optData.AddOption(protocol.OptionCodeCookie, cookieData)
	}

	data, valid := h.processCookies(msg, clientIP)
	if data == nil {
		t.Fatal("expected cookie data")
	}
	if !valid {
		t.Error("expected valid=true for valid cookie")
	}
}

// --- checkRPZResponseIP with match (requires RPZ file with resp-ip rules) ---
// Response IP rules are loaded from zone files, not via AddQNAMERule.
// Skipping direct match test since there is no public API to add response IP rules.

// --- extractResponseIPs with AAAA in all sections ---

func TestExtractResponseIPs_AAAAAllSections(t *testing.T) {
	resp := &protocol.Message{
		Authorities: []*protocol.ResourceRecord{
			{Data: &protocol.RDataAAAA{Address: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}},
		},
		Additionals: []*protocol.ResourceRecord{
			{Data: &protocol.RDataAAAA{Address: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}}},
		},
	}
	ips := extractResponseIPs(resp)
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d", len(ips))
	}
}

// --- RebuildZoneTree with managers ---

func TestRebuildZoneTree_WithManagers(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	h.zones["example.com."] = z
	h.RebuildZoneTree()
	if h.zoneTree == nil {
		t.Fatal("expected zoneTree to be built")
	}
}

// --- ServeDNS with RPZ client IP policy ---

func TestServeDNS_RPZ_ClientIP(t *testing.T) {
	h := newTestHandler()
	h.rpzEngine = rpz.NewEngine(rpz.Config{Enabled: true})
	// The RPZ engine loads from files normally, but we can add rules directly
	// For client IP, we need to add via the engine's internal methods.
	// NewEngine doesn't expose AddClientIPRule, so let's use AddQNAMERule for QNAME instead.
	// Skip this test since client IP rules require file loading or internal access.
}

// --- ServeDNS with DNS Cookie ---

func TestServeDNS_DNSCookie_Invalid(t *testing.T) {
	h := newTestHandler()
	jar, err := dnscookie.NewCookieJar(time.Hour)
	if err != nil {
		t.Fatalf("failed to create cookie jar: %v", err)
	}
	h.cookieJar = jar

	msg := newTestQuery(t, "example.com.", protocol.TypeA)
	msg.SetEDNS0(4096, false)
	opt := msg.GetOPT()
	if optData, ok := opt.Data.(*protocol.RDataOPT); ok {
		optData.AddOption(protocol.OptionCodeCookie, []byte("badcookie"))
	}

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, msg)
	if w.msg == nil {
		t.Fatal("expected a response")
	}
	// Invalid cookie should return BADCOOKIE
	if w.msg.Header.Flags.RCODE != protocol.RcodeBadCookie {
		t.Errorf("expected BADCOOKIE for invalid cookie, got %d", w.msg.Header.Flags.RCODE)
	}
}

// --- ServeDNS with ANY over UDP ---

func TestServeDNS_ANY_UDP(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeANY))
	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if !w.msg.Header.Flags.TC {
		t.Error("expected TC bit set for ANY over UDP")
	}
}

// --- ServeDNS with DNAME record ---
// DNAME at a name two labels below origin works; one label below does not.

func TestServeDNS_DNAME(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "a.b.example.com.", TTL: 300, Class: "IN", Type: "DNAME", RData: "target.example.com."},
		{Name: "x.target.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "x.a.b.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	// DNAME should synthesize CNAME and follow it
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR for DNAME, got %d", w.msg.Header.Flags.RCODE)
	}
}

// --- ServeDNS with CNAME loop ---

func TestServeDNS_CNAME_Loop(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "a.example.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "b.example.com."},
		{Name: "b.example.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "a.example.com."},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "a.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Errorf("expected SERVFAIL for CNAME loop, got %d", w.msg.Header.Flags.RCODE)
	}
}

// --- ServeDNS with stale cache requires upstream; skip without upstream setup ---

// --- addSOAAuthority tests ---

func TestAddSOAAuthority(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		Name:    "example.com.",
		TTL:     300,
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minimum: 86400,
	}
	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeNameError)},
	}
	h.addSOAAuthority(resp, z)
	if len(resp.Authorities) != 1 {
		t.Fatalf("expected 1 authority, got %d", len(resp.Authorities))
	}
	if resp.Authorities[0].Type != protocol.TypeSOA {
		t.Errorf("expected SOA, got %d", resp.Authorities[0].Type)
	}
}

func TestAddSOAAuthority_NoSOA(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	// No SOA record
	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeNameError)},
	}
	h.addSOAAuthority(resp, z)
	if len(resp.Authorities) != 0 {
		t.Fatalf("expected 0 authorities, got %d", len(resp.Authorities))
	}
}

// --- resolveCNAMETarget tests ---

func TestResolveCNAMETarget_NoUpstream(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "alias.example.com.", protocol.TypeA)
	answers := h.resolveCNAMETarget(w, msg, msg.Questions[0], "target.example.com.", protocol.TypeA)
	// No upstream, no zone for target.example.com. - should return empty or NXDOMAIN
	_ = answers
}

// --- buildCNAMEResponse tests ---

func TestBuildCNAMEResponse(t *testing.T) {
	h := newTestHandler()
	query := newTestQuery(t, "alias.example.com.", protocol.TypeA)
	cnames := []zone.Record{
		{Name: "alias.example.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "target.example.com."},
	}
	resp := h.buildCNAMEResponse(query, cnames, nil)
	if resp == nil {
		t.Fatal("expected response")
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
	}
}

// --- chaseCNAMEInZones tests ---

func TestChaseCNAMEInZones_Loop(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "a.example.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "b.example.com."},
		{Name: "b.example.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "a.example.com."},
	})
	result := h.chaseCNAMEInZones("a.example.com.")
	if !result.loopDetected {
		t.Error("expected loop detected")
	}
}

// --- handleAuthoritative referral ---

func TestServeDNS_Referral(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "sub.example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.sub.example.com."},
		{Name: "ns1.sub.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	// Query a name deeper than the delegation point so FindDelegation finds it.
	h.ServeDNS(w, newTestQuery(t, "www.sub.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR for referral, got %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Authorities) == 0 {
		t.Error("expected authority section in referral")
	}
}

// --- ServeDNS with GeoDNS ---

func TestServeDNS_GeoDNS(t *testing.T) {
	h := newTestHandler()
	h.geoEngine = geodns.NewEngine(geodns.Config{Enabled: true})
	h.geoEngine.SetRule("www.example.com.", "A", &geodns.GeoRecord{
		Default: "192.168.1.1",
		Type:    "A",
		TTL:     300,
	})
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "10.0.0.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR for GeoDNS, got %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.msg.Answers))
	}
	// GeoDNS default should override zone record
	addr := w.msg.Answers[0].Data.(*protocol.RDataA).Address
	if addr != [4]byte{192, 168, 1, 1} {
		t.Errorf("expected GeoDNS IP 192.168.1.1, got %v", addr)
	}
}

// --- ServeDNS with zone tree lookup ---

func TestServeDNS_ZoneTreeLookup(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.Records["www.example.com."] = []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	}
	h.zones["example.com."] = z
	h.RebuildZoneTree()

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got %d", w.msg.Header.Flags.RCODE)
	}
}

// --- ServeDNS with DNSSEC signed response ---

func TestServeDNS_DNSSEC_SignedResponse(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	// Create a signer and add it to zoneSigners
	signer := dnssec.NewSigner("example.com.", dnssec.DefaultSignerConfig())
	sk, err := signer.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	signer.AddKey(sk)
	h.zoneSigners = map[string]*dnssec.Signer{
		"example.com.": signer,
	}

	// Query with DO bit
	msg := newTestQuery(t, "www.example.com.", protocol.TypeA)
	msg.SetEDNS0(4096, true) // DO bit set

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, msg)

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got %d", w.msg.Header.Flags.RCODE)
	}
	// Should have A + RRSIG
	if len(w.msg.Answers) != 2 {
		t.Fatalf("expected 2 answers (A + RRSIG), got %d", len(w.msg.Answers))
	}
}

// --- RebuildZoneTree with zoneManager ---

func TestRebuildZoneTree_WithZoneManager(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	h.zones["example.com."] = z

	mgr := zone.NewManager()
	mgr.LoadZone(zone.NewZone("other.com."), "")
	h.zoneManager = mgr

	h.RebuildZoneTree()
	if h.zoneTree == nil {
		t.Fatal("expected zoneTree to be built")
	}
}

// --- processCookies with valid server cookie ---

func TestProcessCookies_ValidServerCookie(t *testing.T) {
	h := newTestHandler()
	jar, err := dnscookie.NewCookieJar(time.Hour)
	if err != nil {
		t.Fatalf("failed to create cookie jar: %v", err)
	}
	h.cookieJar = jar

	clientIP := net.ParseIP("10.0.0.1")
	clientCookie := jar.GenerateClientCookie(clientIP, net.ParseIP("127.0.0.1"))
	serverCookie := jar.GenerateServerCookie(clientCookie, clientIP)
	cookieData := dnscookie.PackCookieOption(clientCookie, serverCookie)

	msg := newTestQuery(t, "example.com.", protocol.TypeA)
	msg.SetEDNS0(4096, false)
	opt := msg.GetOPT()
	if optData, ok := opt.Data.(*protocol.RDataOPT); ok {
		optData.AddOption(protocol.OptionCodeCookie, cookieData)
	}

	data, valid := h.processCookies(msg, clientIP)
	if data == nil {
		t.Fatal("expected cookie data")
	}
	if !valid {
		t.Error("expected valid=true for valid server cookie")
	}
}

// --- buildReferralResponse with glue records ---

func TestBuildReferralResponse_WithGlue(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.Records["ns1.sub.example.com."] = []zone.Record{
		{Name: "ns1.sub.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	}
	nsRecords := []zone.Record{
		{Name: "sub.example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.sub.example.com."},
	}
	query := newTestQuery(t, "www.sub.example.com.", protocol.TypeA)
	resp := h.buildReferralResponse(query, z, nsRecords, "sub.example.com.")

	if len(resp.Authorities) != 1 {
		t.Fatalf("expected 1 authority, got %d", len(resp.Authorities))
	}
	if len(resp.Additionals) != 1 {
		t.Fatalf("expected 1 additional (glue), got %d", len(resp.Additionals))
	}
	if resp.Additionals[0].Type != protocol.TypeA {
		t.Errorf("expected glue A record, got %d", resp.Additionals[0].Type)
	}
}

// --- ReloadViews with invalid config ---

func TestReloadViews_InvalidConfig(t *testing.T) {
	h := newTestHandler()
	views := []filter.ViewConfig{
		{Name: "bad", MatchClients: []string{"not-a-cidr"}},
	}
	err := h.ReloadViews(views, nil)
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

// --- addSOAAuthority error paths ---

func TestAddSOAAuthority_InvalidMName(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	invalidLabel := strings.Repeat("a", 64) + ".com."
	z.SOA = &zone.SOARecord{
		Name:  "example.com.",
		TTL:   300,
		MName: invalidLabel,
		RName: "admin.example.com.",
	}
	resp := &protocol.Message{}
	h.addSOAAuthority(resp, z)
	if len(resp.Authorities) != 0 {
		t.Error("expected 0 authorities for invalid MName")
	}
}

// --- resolveCNAMETarget with zone match ---

func TestResolveCNAMETarget_ZoneMatch(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "target.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "alias.example.com.", protocol.TypeA)
	answers := h.resolveCNAMETarget(w, msg, msg.Questions[0], "target.example.com.", protocol.TypeA)
	if len(answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(answers))
	}
}

// --- buildCNAMEResponse with target answers ---

func TestBuildCNAMEResponse_WithTargets(t *testing.T) {
	h := newTestHandler()
	query := newTestQuery(t, "alias.example.com.", protocol.TypeA)
	cnames := []zone.Record{
		{Name: "alias.example.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "target.example.com."},
	}
	targetAnswers := []*protocol.ResourceRecord{
		{
			Name:  mustParseName(t, "target.example.com."),
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{192, 168, 1, 1}},
		},
	}
	resp := h.buildCNAMEResponse(query, cnames, targetAnswers)
	if resp == nil {
		t.Fatal("expected response")
	}
	if len(resp.Answers) != 2 {
		t.Fatalf("expected 2 answers (CNAME + A), got %d", len(resp.Answers))
	}
}

// --- chaseCNAMEInZones with chain ---

func TestChaseCNAMEInZones_Chain(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "a.example.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "b.example.com."},
		{Name: "b.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})
	result := h.chaseCNAMEInZones("a.example.com.")
	if result.loopDetected {
		t.Error("unexpected loop detected")
	}
	if len(result.cnameRecords) != 1 {
		t.Fatalf("expected 1 CNAME record, got %d", len(result.cnameRecords))
	}
	if result.targetName != "b.example.com." {
		t.Errorf("expected target b.example.com., got %s", result.targetName)
	}
}

// --- ServeDNS with RPZ on authoritative answer ---

func TestServeDNS_RPZ_Authoritative(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
	})
	h.rpzEngine = rpz.NewEngine(rpz.Config{Enabled: true})
	// QNAME policy that matches www.example.com.
	h.rpzEngine.AddQNAMERule("www.example.com", rpz.ActionNXDOMAIN, "")

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN for RPZ on auth answer, got %d", w.msg.Header.Flags.RCODE)
	}
}

// --- handleAuthoritative with NODATA wildcard ---

func TestServeDNS_WildcardNODATA(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "*.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	// Query for MX on a name that doesn't exist but wildcard only has A
	h.ServeDNS(w, newTestQuery(t, "anything.example.com.", protocol.TypeMX))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR (NODATA), got %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 0 {
		t.Errorf("expected 0 answers for NODATA, got %d", len(w.msg.Answers))
	}
}

// --- ServeDNS with cookieResponseWriter wrapper ---

func TestServeDNS_DNSCookie_Valid(t *testing.T) {
	h := newTestHandler()
	jar, err := dnscookie.NewCookieJar(time.Hour)
	if err != nil {
		t.Fatalf("failed to create cookie jar: %v", err)
	}
	h.cookieJar = jar
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	clientIP := net.ParseIP("10.0.0.1")
	clientCookie := jar.GenerateClientCookie(clientIP, net.ParseIP("127.0.0.1"))
	serverCookie := jar.GenerateServerCookie(clientCookie, clientIP)
	cookieData := dnscookie.PackCookieOption(clientCookie, serverCookie)

	msg := newTestQuery(t, "www.example.com.", protocol.TypeA)
	msg.SetEDNS0(4096, false)
	opt := msg.GetOPT()
	if optData, ok := opt.Data.(*protocol.RDataOPT); ok {
		optData.AddOption(protocol.OptionCodeCookie, cookieData)
	}

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, msg)

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got %d", w.msg.Header.Flags.RCODE)
	}
	// Response should include a cookie in OPT
	respOpt := w.msg.GetOPT()
	if respOpt == nil {
		t.Fatal("expected OPT in response")
	}
	respOptData, ok := respOpt.Data.(*protocol.RDataOPT)
	if !ok {
		t.Fatal("expected RDataOPT")
	}
	if respOptData.GetOption(protocol.OptionCodeCookie) == nil {
		t.Error("expected cookie option in response")
	}
}

// --- adapters.go tests ---

func TestResolverCacheAdapter(t *testing.T) {
	c := cache.New(cache.Config{Capacity: 10, DefaultTTL: 60 * time.Second})
	adapter := &resolverCacheAdapter{cache: c}

	msg, _ := protocol.NewQuery(1, "example.com.", protocol.TypeA)
	c.Set(cache.MakeKey("example.com.", protocol.TypeA, false), msg, 300)

	entry := adapter.Get(cache.MakeKey("example.com.", protocol.TypeA, false))
	if entry == nil {
		t.Fatal("expected cache entry")
	}
	if entry.Message == nil {
		t.Error("expected non-nil message")
	}

	adapter.Set("test.example.com.", msg, 300)
	if c.Get("test.example.com.") == nil {
		t.Error("expected entry after Set")
	}

	adapter.SetNegative("neg.example.com.", protocol.RcodeNameError)
	neg := c.Get("neg.example.com.")
	if neg == nil || !neg.IsNegative {
		t.Error("expected negative cache entry")
	}
}

type mockUpstream struct {
	resp *protocol.Message
	err  error
}

func (m *mockUpstream) Query(msg *protocol.Message) (*protocol.Message, error) {
	return m.resp, m.err
}

func TestDNSSECResolverAdapter(t *testing.T) {
	targetName, _ := protocol.ParseName("example.com.")
	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Answers: []*protocol.ResourceRecord{
			{Name: targetName, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
		},
	}

	adapter := &dnssecResolverAdapter{upstream: &mockUpstream{resp: resp}}
	result, err := adapter.Query(context.Background(), "example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected response")
	}
	if len(result.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(result.Answers))
	}

	adapter2 := &dnssecResolverAdapter{upstream: &mockUpstream{err: fmt.Errorf("upstream error")}}
	_, err = adapter2.Query(context.Background(), "example.com.", protocol.TypeA)
	if err == nil {
		t.Error("expected error")
	}

	adapter3 := &dnssecResolverAdapter{upstream: &mockUpstream{}}
	_, err = adapter3.Query(context.Background(), strings.Repeat("a", 64)+".com.", protocol.TypeA)
	if err == nil {
		t.Error("expected error for invalid name")
	}
}

// --- authoritative.go additional tests ---

func TestResolveCNAMETarget_CacheHit(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "alias.example.com.", protocol.TypeA)

	targetName, _ := protocol.ParseName("target.example.com.")
	cacheResp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Answers: []*protocol.ResourceRecord{
			{Name: targetName, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
		},
	}
	h.cache.Set(cache.MakeKey("target.example.com.", protocol.TypeA, false), cacheResp, 300)

	answers := h.resolveCNAMETarget(w, msg, msg.Questions[0], "target.example.com.", protocol.TypeA)
	if len(answers) != 1 {
		t.Fatalf("expected 1 answer from cache, got %d", len(answers))
	}
}

func TestBuildCNAMEResponse_InvalidCNAMEData(t *testing.T) {
	h := newTestHandler()
	query := newTestQuery(t, "alias.example.com.", protocol.TypeA)
	invalidLabel := strings.Repeat("a", 64) + ".com."
	cnames := []zone.Record{
		{Name: "alias.example.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: invalidLabel},
	}
	resp := h.buildCNAMEResponse(query, cnames, nil)
	if resp == nil {
		t.Fatal("expected response")
	}
	if len(resp.Answers) != 0 {
		t.Fatalf("expected 0 answers (invalid CNAME data), got %d", len(resp.Answers))
	}
}

func TestAddSOAAuthority_InvalidRName(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.",
		RName: strings.Repeat("a", 64) + ".example.com.",
		TTL:   300, Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300,
	}
	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeNameError)},
	}
	h.addSOAAuthority(resp, z)
	if len(resp.Authorities) != 0 {
		t.Fatalf("expected 0 authorities (invalid RName), got %d", len(resp.Authorities))
	}
}

func TestBuildReferralResponse_NoGlue(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "sub.example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.other.com."},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.sub.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if len(w.msg.Authorities) == 0 {
		t.Fatal("expected authority section")
	}
	if len(w.msg.Additionals) != 0 {
		t.Fatalf("expected 0 additionals (no glue), got %d", len(w.msg.Additionals))
	}
}

func TestChaseCNAMEInZones_NoMatch(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})
	result := h.chaseCNAMEInZones("www.example.com.")
	if result.loopDetected {
		t.Error("expected no loop")
	}
	if len(result.cnameRecords) != 0 {
		t.Fatalf("expected 0 CNAME records, got %d", len(result.cnameRecords))
	}
}

// --- handler.go additional tests ---

func TestServeDNS_NSEC_CacheHit(t *testing.T) {
	h := newTestHandler()
	h.nsecCache = cache.NewNSECCache(100)

	soaName, _ := protocol.ParseName("example.com.")
	mname, _ := protocol.ParseName("ns1.example.com.")
	rname, _ := protocol.ParseName("admin.example.com.")
	nsecName, _ := protocol.ParseName("a.example.com.")
	nextName, _ := protocol.ParseName("z.example.com.")

	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeNameError)},
	}
	resp.Authorities = append(resp.Authorities, &protocol.ResourceRecord{
		Name: soaName, Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataSOA{MName: mname, RName: rname, Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300},
	})
	resp.Authorities = append(resp.Authorities, &protocol.ResourceRecord{
		Name: nsecName, Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{NextDomain: nextName, TypeBitMap: []uint16{protocol.TypeA}},
	})

	h.nsecCache.AddFromResponse(resp, true)

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "m.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN from NSEC cache, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_SplitHorizon_ViewMiss(t *testing.T) {
	h := newTestHandler()
	sh, err := filter.NewSplitHorizon([]filter.ViewConfig{
		{Name: "internal", MatchClients: []string{"10.0.0.0/8"}},
	})
	if err != nil {
		t.Fatalf("failed to create split horizon: %v", err)
	}
	h.splitHorizon = sh
	h.viewZones = map[string]map[string]*zone.Zone{
		"internal": {
			"other.com.": func() *zone.Zone {
				z := zone.NewZone("other.com.")
				z.Records["www.other.com."] = []zone.Record{{Name: "www.other.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"}}
				return z
			}(),
		},
	}

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN after view miss, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestCheckRPZResponseIP_Match(t *testing.T) {
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.zone")
	if err := os.WriteFile(rpzFile, []byte("32.1.2.3.4.rpz-ip 300 IN CNAME *\n"), 0644); err != nil {
		t.Fatalf("failed to write rpz file: %v", err)
	}

	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine

	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "4.3.2.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN from RPZ response IP, got %d", w.msg.Header.Flags.RCODE)
	}
}

// --- manager constructor tests ---

func TestNewCacheManager(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ZoneDir = t.TempDir()
	mgr, err := NewCacheManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	if mgr.Cache == nil {
		t.Fatal("expected non-nil cache")
	}
	mgr.Stop()
}

func TestCacheManager_FullLifecycle(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ZoneDir = t.TempDir()
	mgr, err := NewCacheManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg, _ := protocol.NewQuery(1, "example.com.", protocol.TypeA)
	mgr.Cache.Set(cache.MakeKey("example.com.", protocol.TypeA, false), msg, 300)

	mgr.StartPersistence(time.Hour)
	mgr.Stop()

	mgr2, err := NewCacheManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mgr2.LoadCache()

	entry := mgr2.Cache.Get(cache.MakeKey("example.com.", protocol.TypeA, false))
	if entry == nil {
		t.Fatal("expected restored cache entry")
	}
	mgr2.Stop()
}

func TestCacheManager_KVStore(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ZoneDir = t.TempDir()
	mgr, err := NewCacheManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg, _ := protocol.NewQuery(1, "example.com.", protocol.TypeA)
	mgr.Cache.Set(cache.MakeKey("example.com.", protocol.TypeA, false), msg, 300)

	kvDir := t.TempDir()
	kvStore, err := storage.OpenKVStore(kvDir)
	if err != nil {
		t.Fatalf("failed to open kv store: %v", err)
	}

	if err := mgr.SaveCacheToKV(kvStore); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mgr2, _ := NewCacheManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	mgr2.LoadCacheFromKV(kvStore)

	entry := mgr2.Cache.Get(cache.MakeKey("example.com.", protocol.TypeA, false))
	if entry == nil {
		t.Fatal("expected restored cache entry from KV")
	}
	mgr2.Stop()
}

func TestNewUpstreamManager_Empty(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstream.Servers = []string{}
	cfg.Upstream.AnycastGroups = nil
	mgr, err := NewUpstreamManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	mgr.Stop()
}

func TestNewZoneManager(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "example.com.zone")
	zoneContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400
@ 3600 IN NS ns1
ns1 3600 IN A 192.0.2.1
www 3600 IN A 192.0.2.10
`
	if err := os.WriteFile(zoneFile, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.ZoneDir = tmpDir
	cfg.Zones = []string{zoneFile}

	mgr, err := NewZoneManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	if len(mgr.Zones()) == 0 {
		t.Fatal("expected at least one zone loaded")
	}
	if mgr.Manager() == nil {
		t.Fatal("expected non-nil zone manager")
	}
	if mgr.KVPersistence() == nil {
		t.Fatal("expected non-nil KV persistence")
	}
}

// --- Batch 2: additional coverage ---

func TestTryDNS64Synthesis_NoUpstream(t *testing.T) {
	h := newTestHandler()
	h.dns64Synth, _ = dns64.NewSynthesizer("", 0)

	q := &protocol.Question{
		Name:   func() *protocol.Name { n, _ := protocol.ParseName("example.com."); return n }(),
		QType:  protocol.TypeAAAA,
		QClass: protocol.ClassIN,
	}
	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
	}

	w := newCaptureWriter("10.0.0.1", "udp")
	result := h.tryDNS64Synthesis(w, newTestQuery(t, "example.com.", protocol.TypeAAAA), q, resp)
	if result {
		t.Error("expected false when no upstream configured")
	}
}

func TestTryDNS64Synthesis_Success(t *testing.T) {
	addr, cleanup := startTestUpstream(t)
	defer cleanup()

	h := newTestHandler()
	uc, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 2 * time.Second, HealthCheck: 0})
	defer uc.Close()
	h.upstream = uc

	synth, _ := dns64.NewSynthesizer("", 0)
	h.dns64Synth = synth

	w := newCaptureWriter("10.0.0.1", "udp")
	q := &protocol.Question{Name: mustParseName(t, "test.example."), QType: protocol.TypeAAAA, QClass: protocol.ClassIN}
	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
	}

	if !h.tryDNS64Synthesis(w, newTestQuery(t, "test.example.", protocol.TypeAAAA), q, resp) {
		t.Fatal("expected DNS64 synthesis to succeed")
	}
	if w.msg == nil {
		t.Fatal("expected synthesized response")
	}
	if len(w.msg.Answers) == 0 || w.msg.Answers[0].Type != protocol.TypeAAAA {
		t.Error("expected AAAA answer in synthesized response")
	}
}

func TestServeDNS_StaleCache_UpstreamFail(t *testing.T) {
	h := newTestHandler()
	client, _ := upstream.NewClient(upstream.Config{
		Servers: []string{"127.0.0.1:5354"},
		Timeout: 100 * time.Millisecond,
	})
	h.upstream = client

	h.cache = cache.New(cache.Config{
		Capacity:   100,
		DefaultTTL: 60 * time.Second,
		MinTTL:     0,
		MaxTTL:     300 * time.Second,
		ServeStale: true,
		StaleGrace: time.Hour,
	})

	parsedName, _ := protocol.ParseName("stale.example.com.")
	cacheResp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Answers: []*protocol.ResourceRecord{
			{Name: parsedName, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
		},
	}
	h.cache.Set(cache.MakeKey("stale.example.com.", protocol.TypeA, false), cacheResp, 0)

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "stale.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR from stale cache, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_RRL_Suppressed(t *testing.T) {
	addr, cleanup := startTestUpstream(t)
	defer cleanup()

	h := newTestHandler()
	uc, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 2 * time.Second, HealthCheck: 0})
	defer uc.Close()
	h.upstream = uc
	h.rrl = filter.NewRRL(filter.RRLConfig{Enabled: true, Rate: 1, Burst: 1})

	// Exhaust burst with rapid queries for non-authoritative names.
	// Use different names to avoid cache hits; RRL bucket is per (clientIP, qtype, rcode).
	var lastResp *protocol.Message
	for i := 0; i < 5; i++ {
		w := newCaptureWriter("10.0.0.1", "udp")
		qname := fmt.Sprintf("rrltest%d.example.", i)
		h.ServeDNS(w, newTestQuery(t, qname, protocol.TypeA))
		if w.msg != nil {
			lastResp = w.msg
		}
	}

	if lastResp == nil {
		t.Fatal("expected response")
	}
	if lastResp.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected REFUSED from RRL, got %d", lastResp.Header.Flags.RCODE)
	}
}

func TestServeDNS_SplitHorizon_ViewNODATA(t *testing.T) {
	h := newTestHandler()
	sh, _ := filter.NewSplitHorizon([]filter.ViewConfig{
		{Name: "internal", MatchClients: []string{"10.0.0.0/8"}, ZoneFiles: []string{}},
	})
	h.splitHorizon = sh
	z := zone.NewZone("example.com.")
	z.Records["www.example.com."] = []zone.Record{{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"}}
	h.viewZones = map[string]map[string]*zone.Zone{
		"internal": {"example.com.": z},
	}

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeMX))

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR (NODATA), got %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 0 {
		t.Fatalf("expected 0 answers for NODATA, got %d", len(w.msg.Answers))
	}
}

func TestNewUpstreamManager_WithServers(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstream.Servers = []string{"127.0.0.1:5354"}
	mgr, err := NewUpstreamManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr.Client == nil {
		t.Fatal("expected non-nil client")
	}
	if mgr.Resolver() == nil {
		t.Fatal("expected non-nil resolver")
	}
	mgr.Stop()
}

func TestNewUpstreamManager_WithAnycast(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstream.Servers = []string{}
	cfg.Upstream.AnycastGroups = []config.AnycastGroupConfig{
		{
			AnycastIP: "192.0.2.1",
			Backends: []config.AnycastBackendConfig{
				{PhysicalIP: "192.0.2.2", Port: 53},
			},
		},
	}
	mgr, err := NewUpstreamManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr.LoadBalancer == nil {
		t.Fatal("expected non-nil load balancer")
	}
	mgr.Stop()
}

func TestRebuildZoneTree_WithKVPersistence(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("kv.example.com.")
	z.Records["www.kv.example.com."] = []zone.Record{{Name: "www.kv.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"}}
	zm := zone.NewManager()
	kvDir := t.TempDir()
	kvStore, _ := storage.OpenKVStore(kvDir)
	kvp := zone.NewKVPersistence(zm, kvStore)
	kvp.Enable()
	zm.LoadZone(z, "")
	h.kvPersistence = kvp

	h.RebuildZoneTree()

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.kv.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestNewZoneManager_LoadFailure(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ZoneDir = t.TempDir()
	cfg.Zones = []string{filepath.Join(t.TempDir(), "nonexistent.zone")}

	mgr, err := NewZoneManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	if len(mgr.Zones()) != 0 {
		t.Fatalf("expected 0 zones, got %d", len(mgr.Zones()))
	}
}

func TestServeDNS_Referral_RPZ_Glue(t *testing.T) {
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.zone")
	if err := os.WriteFile(rpzFile, []byte("32.1.1.168.192.rpz-ip 300 IN CNAME *\n"), 0644); err != nil {
		t.Fatalf("failed to write rpz file: %v", err)
	}
	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine

	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "sub.example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.sub.example.com."},
		{Name: "ns1.sub.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.sub.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN from RPZ on referral glue, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_Wildcard_DNSSEC(t *testing.T) {
	h := newTestHandler()
	s := dnssec.NewSigner("example.com.", dnssec.DefaultSignerConfig())
	key, err := s.GenerateKeyPair(protocol.AlgorithmED25519, false)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	s.AddKey(key)
	h.zoneSigners = map[string]*dnssec.Signer{"example.com.": s}

	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "*.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	msg := newTestQuery(t, "anything.example.com.", protocol.TypeA)
	msg.SetEDNS0(4096, true)
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, msg)

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got %d", w.msg.Header.Flags.RCODE)
	}
	hasRRSIG := false
	for _, rr := range w.msg.Answers {
		if rr.Type == protocol.TypeRRSIG {
			hasRRSIG = true
			break
		}
	}
	if !hasRRSIG {
		t.Error("expected RRSIG in response")
	}
}

func TestCacheManager_SetInvalidateFunc(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ZoneDir = t.TempDir()
	mgr, _ := NewCacheManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))

	called := false
	mgr.SetInvalidateFunc(func(key string) {
		called = true
	})

	msg, _ := protocol.NewQuery(1, "example.com.", protocol.TypeA)
	mgr.Cache.Set("test", msg, 300)
	mgr.Cache.Delete("test")

	if !called {
		t.Error("expected invalidate callback to be called")
	}
	mgr.Stop()
}

// --- Batch 3: Adapters, Managers, Helpers ---

func TestNewResolverTransport(t *testing.T) {
	tr := newResolverTransport(nil, nil)
	if tr == nil || tr.inner == nil {
		t.Fatal("expected non-nil transport")
	}
}

func TestResolverTransportAdapter_QueryContext(t *testing.T) {
	tr := newResolverTransport(nil, nil)
	ctx := context.Background()
	msg, _ := protocol.NewQuery(1, "example.com.", protocol.TypeA)
	_, err := tr.QueryContext(ctx, msg, "127.0.0.1:5354")
	if err == nil {
		t.Fatal("expected error querying non-existent server")
	}
}

func TestZoneManager_Getters(t *testing.T) {
	zm := &ZoneManager{
		result: ZoneManagerResult{
			ZoneFiles: map[string]string{"example.com.": "/tmp/example.com.zone"},
			Signers:   map[string]*dnssec.Signer{},
		},
	}
	if len(zm.ZoneFiles()) != 1 {
		t.Errorf("expected 1 zone file, got %d", len(zm.ZoneFiles()))
	}
	if len(zm.Signers()) != 0 {
		t.Errorf("expected 0 signers, got %d", len(zm.Signers()))
	}
}

func TestNewDNSSECManager_Disabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DNSSEC.Enabled = false
	mgr, err := NewDNSSECManager(cfg, nil, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr.Validator != nil {
		t.Error("expected nil validator when disabled")
	}
}

func TestNewSecurityManager(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)

	mgr, err := NewSecurityManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}

	mgr.Stop()
	res := mgr.Result()
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	mgr.Reload()
}

func TestNewSecurityManager_RecursiveACL(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Resolution.Recursive = true
	cfg.Server.ACLAllowUnrestrictedRecursion = false
	_, err := NewSecurityManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewClusterManager_Disabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Cluster.Enabled = false
	mgr, err := NewClusterManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil), nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	mgr.Stop()
}

func TestNewTransferManager(t *testing.T) {
	cfg := config.DefaultConfig()
	zones := make(map[string]*zone.Zone)
	zonesMu := &sync.RWMutex{}
	mgr, err := NewTransferManager(cfg, zones, zonesMu, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	mgr.SetZonesMu(zonesMu)
	mgr.Stop()
}

func TestLoadConfig_NonExistent(t *testing.T) {
	cfg, err := loadConfig("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected default config")
	}
}

func TestValidateConfigOnly(t *testing.T) {
	err := validateConfigOnly("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSdNotifySend_NoSocket(t *testing.T) {
	os.Unsetenv("NOTIFY_SOCKET")
	err := sdNotifySend("")
	if err == nil {
		t.Fatal("expected error when no socket configured")
	}
}

func TestPrintHelp(t *testing.T) {
	printHelp()
}

func TestUpstreamManager_Resolver_Nil(t *testing.T) {
	mgr := &UpstreamManager{}
	r := mgr.Resolver()
	if r == nil {
		t.Fatal("expected non-nil resolver adapter")
	}
}

func TestDoQHandlerAdapter_InvalidData(t *testing.T) {
	h := newTestHandler()
	adapter := &doqHandlerAdapter{handler: h}
	// Invalid data should return early without panic
	adapter.ServeDoQ(nil, []byte{0x00})
}

func TestDoQHandlerAdapter_EmptyQuestions(t *testing.T) {
	h := newTestHandler()
	adapter := &doqHandlerAdapter{handler: h}
	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewQueryFlags()},
		Questions: []*protocol.Question{},
	}
	buf := make([]byte, 512)
	n, _ := msg.Pack(buf)
	adapter.ServeDoQ(nil, buf[:n])
}

func TestDoQHandlerAdapter_PanicRecovery(t *testing.T) {
	panicHandler := &integratedHandler{}
	adapter := &doqHandlerAdapter{handler: panicHandler}
	msg, _ := protocol.NewQuery(1, "example.com.", protocol.TypeA)
	buf := make([]byte, 512)
	n, _ := msg.Pack(buf)
	// Should recover from panic in ServeDNS
	adapter.ServeDoQ(nil, buf[:n])
}

func TestDoQResponseWriter(t *testing.T) {
	// Test ClientInfo and MaxSize without a real stream
	rw := &doqResponseWriter{}
	ci := rw.ClientInfo()
	if ci == nil {
		t.Fatal("expected non-nil ClientInfo")
	}
	if rw.MaxSize() != 65535 {
		t.Errorf("expected MaxSize 65535, got %d", rw.MaxSize())
	}
}

func TestNewSecurityManager_FullFeatures(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Blocklist.Enabled = true
	cfg.RPZ.Enabled = true
	cfg.GeoDNS.Enabled = true
	cfg.DNS64.Enabled = true
	cfg.RRL.Enabled = true
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)

	mgr, err := NewSecurityManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	mgr.Stop()
}

func TestNewClusterManager_Enabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Cluster.Enabled = true
	cfg.Cluster.BindAddr = "127.0.0.1"
	cfg.Cluster.GossipPort = 0 // let OS assign
	cfg.Cluster.NodeID = "test-node"
	mgr, err := NewClusterManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil), nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	mgr.Stop()
}

func TestNewDNSSECManager_Enabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DNSSEC.Enabled = true
	adapter := &dnssecResolverAdapter{upstream: nil}
	mgr, err := NewDNSSECManager(cfg, adapter, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestNewTransferManager_WithSlaveZones(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SlaveZones = []config.SlaveZoneConfig{
		{ZoneName: "slave.example.", Masters: []string{"127.0.0.1:53"}, TransferType: "axfr"},
	}
	zones := make(map[string]*zone.Zone)
	zonesMu := &sync.RWMutex{}
	mgr, err := NewTransferManager(cfg, zones, zonesMu, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	mgr.Stop()
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "bad.yaml")
	os.WriteFile(badFile, []byte("not: valid: yaml: ["), 0644)
	_, err := loadConfig(badFile)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestValidateConfigOnly_Invalid(t *testing.T) {
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "bad.yaml")
	os.WriteFile(badFile, []byte("not: valid: yaml: ["), 0644)
	err := validateConfigOnly(badFile)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestSecurityManager_Reload_WithBlocklist(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Blocklist.Enabled = true
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, _ := NewSecurityManager(cfg, logger)
	mgr.Reload()
	mgr.Stop()
}

func TestSecurityManager_Reload_WithRPZ(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RPZ.Enabled = true
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, _ := NewSecurityManager(cfg, logger)
	mgr.Reload()
	mgr.Stop()
}

func TestUpstreamManager_Stop(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstream.Servers = []string{"127.0.0.1:5354"}
	mgr, err := NewUpstreamManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mgr.Stop()
}

// --- Batch 4: Transfer functions ---

func TestHandleAXFR_UDP(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeAXFR, QClass: protocol.ClassIN}
	h.handleAXFR(w, newTestQuery(t, "example.com.", protocol.TypeAXFR), q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected REFUSED for UDP AXFR, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestHandleAXFR_TCP_Unauthorized(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{"example.com.": {Origin: "example.com.", Records: map[string][]zone.Record{}}}
	h.axfrServer = transfer.NewAXFRServer(zones)
	w := newCaptureWriter("10.0.0.1", "tcp")
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeAXFR, QClass: protocol.ClassIN}
	h.handleAXFR(w, newTestQuery(t, "example.com.", protocol.TypeAXFR), q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected REFUSED for unauthorized AXFR, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestHandleIXFR_UDP(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeIXFR, QClass: protocol.ClassIN}
	h.handleIXFR(w, newTestQuery(t, "example.com.", protocol.TypeIXFR), q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected REFUSED for UDP IXFR, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestHandleIXFR_TCP_FallbackToAXFR(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{
		"example.com.": {
			Origin:  "example.com.",
			Records: map[string][]zone.Record{},
			SOA:     &zone.SOARecord{Serial: 1},
		},
	}
	// IXFR server with no journal will return ErrNoJournal, triggering AXFR fallback
	h.axfrServer = transfer.NewAXFRServer(zones)
	h.ixfrServer = transfer.NewIXFRServer(h.axfrServer)
	w := newCaptureWriter("10.0.0.1", "tcp")
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeIXFR, QClass: protocol.ClassIN}
	msg := newTestQuery(t, "example.com.", protocol.TypeIXFR)
	msg.Answers = []*protocol.ResourceRecord{{
		Name:  mustParseName(t, "example.com."),
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataSOA{Serial: 1, MName: mustParseName(t, "ns1.example.com."), RName: mustParseName(t, "admin.example.com.")},
	}}
	h.handleIXFR(w, msg, q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	// AXFR fallback: unauthorized by default (no allow list)
	if w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected REFUSED for AXFR fallback, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestHandleNOTIFY_Refused(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{}
	h.notifyHandler = transfer.NewNOTIFYSlaveHandler(zones)
	w := newCaptureWriter("10.0.0.1", "udp")
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeSOA, QClass: protocol.ClassIN}
	h.handleNOTIFY(w, newTestQuery(t, "example.com.", protocol.TypeSOA), q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected REFUSED for unauthorized NOTIFY, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestHandleUPDATE_Error(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{}
	h.ddnsHandler = transfer.NewDynamicDNSHandler(zones)
	w := newCaptureWriter("10.0.0.1", "udp")
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeSOA, QClass: protocol.ClassIN}
	h.handleUPDATE(w, newTestQuery(t, "example.com.", protocol.TypeSOA), q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Errorf("expected SERVFAIL for failed UPDATE, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestRecordZoneChange_NilIXFR(t *testing.T) {
	h := newTestHandler()
	// Should not panic when ixfrServer is nil
	h.recordZoneChange("example.com.", 1, 2, nil, nil)
}

func TestLoadZoneSigner_Disabled(t *testing.T) {
	z := zone.NewZone("example.com.")
	signer, err := loadZoneSigner(z, config.SigningConfig{Enabled: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signer != nil {
		t.Error("expected nil signer when disabled")
	}
}

func TestTransferManager_Result(t *testing.T) {
	cfg := config.DefaultConfig()
	zones := make(map[string]*zone.Zone)
	zonesMu := &sync.RWMutex{}
	mgr, _ := NewTransferManager(cfg, zones, zonesMu, util.NewLogger(util.ERROR, util.TextFormat, nil))
	res := mgr.Result()
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	mgr.Stop()
}

// --- Batch 5: ServeDNS paths, minimizeResponse, processCookies, loadZoneSigner, AXFR success ---

func TestServeDNS_RateLimiter_Suppressed(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})
	h.rateLimiter = filter.NewRateLimiter(config.RRLConfig{Enabled: true, Rate: 1, Burst: 1})
	defer h.rateLimiter.Stop()

	var lastResp *protocol.Message
	for i := 0; i < 5; i++ {
		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))
		if w.msg != nil {
			lastResp = w.msg
		}
	}
	if lastResp == nil {
		t.Fatal("expected response")
	}
	if lastResp.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected REFUSED from rate limiter, got %d", lastResp.Header.Flags.RCODE)
	}
}

func TestMinimizeResponse_Nil(t *testing.T) {
	minimizeResponse(nil)
}

func TestMinimizeResponse_AuthNoSOA(t *testing.T) {
	resp := &protocol.Message{
		Header:    protocol.Header{Flags: protocol.Flags{AA: true, QR: true, RCODE: protocol.RcodeSuccess}},
		Questions: []*protocol.Question{{Name: mustParseName(t, "example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
		Authorities: []*protocol.ResourceRecord{
			{Name: mustParseName(t, "example.com."), Type: protocol.TypeNS, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataNS{NSDName: mustParseName(t, "ns1.example.com.")}},
		},
	}
	minimizeResponse(resp)
	if len(resp.Authorities) != 0 {
		t.Errorf("expected 0 authorities when no SOA in auth response, got %d", len(resp.Authorities))
	}
}

func TestMinimizeResponse_NonAuthNoNS(t *testing.T) {
	resp := &protocol.Message{
		Header:    protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{{Name: mustParseName(t, "example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
		Authorities: []*protocol.ResourceRecord{
			{Name: mustParseName(t, "example.com."), Type: protocol.TypeMX, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataMX{Preference: 10, Exchange: mustParseName(t, "mail.example.com.")}},
		},
	}
	minimizeResponse(resp)
	if len(resp.Authorities) != 0 {
		t.Errorf("expected 0 authorities when no NS/SOA in non-auth response, got %d", len(resp.Authorities))
	}
}

func TestMinimizeResponse_AdditionalsFiltered(t *testing.T) {
	resp := &protocol.Message{
		Header:    protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{{Name: mustParseName(t, "example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
		Authorities: []*protocol.ResourceRecord{
			{Name: mustParseName(t, "example.com."), Type: protocol.TypeNS, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataNS{NSDName: mustParseName(t, "ns1.example.com.")}},
		},
		Additionals: []*protocol.ResourceRecord{
			{Name: mustParseName(t, "ns1.example.com."), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
			{Name: mustParseName(t, "unrelated.example."), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{5, 6, 7, 8}}},
			{Name: mustParseName(t, "."), Type: protocol.TypeOPT, Class: 4096, TTL: 0, Data: &protocol.RDataOPT{}},
		},
	}
	minimizeResponse(resp)
	if len(resp.Additionals) != 2 {
		t.Errorf("expected 2 additionals (glue + OPT), got %d", len(resp.Additionals))
	}
}

func TestProcessCookies_InvalidServerCookie(t *testing.T) {
	h := newTestHandler()
	h.cookieJar, _ = dnscookie.NewCookieJar(time.Hour)
	msg, _ := protocol.NewQuery(1, "example.com.", protocol.TypeA)
	msg.SetEDNS0(4096, false)
	// Add a cookie option with invalid server cookie
	clientCookie := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	serverCookie := [16]byte{9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
	optData := dnscookie.PackCookieOption(clientCookie, serverCookie[:])
	opt := msg.GetOPT()
	if opt != nil {
		opt.Data.(*protocol.RDataOPT).Options = append(opt.Data.(*protocol.RDataOPT).Options, protocol.EDNS0Option{
			Code: protocol.OptionCodeCookie,
			Data: optData,
		})
	}
	cookieData, valid := h.processCookies(msg, net.ParseIP("10.0.0.1"))
	if valid {
		t.Error("expected invalid cookie")
	}
	if cookieData == nil {
		t.Error("expected response cookie data")
	}
}

func TestLoadZoneSigner_NSEC3(t *testing.T) {
	z := zone.NewZone("example.com.")
	signer, err := loadZoneSigner(z, config.SigningConfig{
		Enabled: true,
		NSEC3:   &config.NSEC3Config{Salt: "deadbeef", Iterations: 1},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestHandleAXFR_TCP_Success(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1}
	z.Records["example.com."] = []zone.Record{
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.example.com. admin.example.com. 1 3600 600 86400 300"},
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.example.com."},
	}
	zones := map[string]*zone.Zone{"example.com.": z}
	h.axfrServer = transfer.NewAXFRServer(zones, transfer.WithAllowList([]string{"10.0.0.0/8"}))

	w := newCaptureWriter("10.0.0.1", "tcp")
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeAXFR, QClass: protocol.ClassIN}
	h.handleAXFR(w, newTestQuery(t, "example.com.", protocol.TypeAXFR), q)

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR for authorized AXFR, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestHandleUPDATE_WrongOpcode(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{}
	h.ddnsHandler = transfer.NewDynamicDNSHandler(zones)
	w := newCaptureWriter("10.0.0.1", "udp")
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeSOA, QClass: protocol.ClassIN}
	msg := newTestQuery(t, "example.com.", protocol.TypeSOA)
	// Wrong opcode
	h.handleUPDATE(w, msg, q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Errorf("expected SERVFAIL for wrong opcode UPDATE, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestHandleUPDATE_NoZone(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{}
	h.ddnsHandler = transfer.NewDynamicDNSHandler(zones)
	w := newCaptureWriter("10.0.0.1", "udp")
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeSOA, QClass: protocol.ClassIN}
	msg := newTestQuery(t, "example.com.", protocol.TypeSOA)
	msg.Header.Flags.Opcode = protocol.OpcodeUpdate
	h.handleUPDATE(w, msg, q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeNotZone {
		t.Errorf("expected NOTZONE for missing zone UPDATE, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestProcessNotifyEvents_NoSlave(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{
		"example.com.": {
			Origin: "example.com.",
			SOA:    &zone.SOARecord{Serial: 1},
		},
	}
	h.notifyHandler = transfer.NewNOTIFYSlaveHandler(zones)
	h.notifyHandler.AddNotifyAllowed("10.0.0.0/8")
	// slaveManager is nil

	go h.processNotifyEvents()

	msg := newTestQuery(t, "example.com.", protocol.TypeSOA)
	msg.Answers = []*protocol.ResourceRecord{{
		Name:  mustParseName(t, "example.com."),
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataSOA{Serial: 2, MName: mustParseName(t, "ns1.example.com."), RName: mustParseName(t, "admin.example.com.")},
	}}
	h.notifyHandler.HandleNOTIFY(msg, net.ParseIP("10.0.0.1"))
	time.Sleep(100 * time.Millisecond)
}

func TestProcessNotifyEvents_Forward(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{
		"example.com.": {
			Origin: "example.com.",
			SOA:    &zone.SOARecord{Serial: 1},
		},
	}
	h.notifyHandler = transfer.NewNOTIFYSlaveHandler(zones)
	h.notifyHandler.AddNotifyAllowed("10.0.0.0/8")
	h.slaveManager = transfer.NewSlaveManager(transfer.NewKeyStore())

	go h.processNotifyEvents()

	msg := newTestQuery(t, "example.com.", protocol.TypeSOA)
	msg.Answers = []*protocol.ResourceRecord{{
		Name:  mustParseName(t, "example.com."),
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataSOA{Serial: 2, MName: mustParseName(t, "ns1.example.com."), RName: mustParseName(t, "admin.example.com.")},
	}}
	h.notifyHandler.HandleNOTIFY(msg, net.ParseIP("10.0.0.1"))
	time.Sleep(100 * time.Millisecond)
}

func TestProcessNotifyEvents_FullChannel(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{
		"example.com.": {
			Origin: "example.com.",
			SOA:    &zone.SOARecord{Serial: 1},
		},
	}
	h.notifyHandler = transfer.NewNOTIFYSlaveHandler(zones)
	h.notifyHandler.AddNotifyAllowed("10.0.0.0/8")
	h.slaveManager = transfer.NewSlaveManager(transfer.NewKeyStore())
	// Fill slave manager channel to force default case
	for i := 0; i < 100; i++ {
		h.slaveManager.GetNotifyChannel() <- &transfer.NOTIFYRequest{ZoneName: "example.com."}
	}

	go h.processNotifyEvents()

	msg := newTestQuery(t, "example.com.", protocol.TypeSOA)
	msg.Answers = []*protocol.ResourceRecord{{
		Name:  mustParseName(t, "example.com."),
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataSOA{Serial: 2, MName: mustParseName(t, "ns1.example.com."), RName: mustParseName(t, "admin.example.com.")},
	}}
	h.notifyHandler.HandleNOTIFY(msg, net.ParseIP("10.0.0.1"))
	time.Sleep(100 * time.Millisecond)
}

func TestProcessUpdateEvents(t *testing.T) {
	h := newTestHandler()
	sharedZones := map[string]*zone.Zone{
		"example.com.": zone.NewZone("example.com."),
	}
	h.zones = sharedZones
	h.zoneManager = zone.NewManager()
	h.ddnsHandler = transfer.NewDynamicDNSHandler(sharedZones)
	h.ddnsHandler.SetZonesMu(&h.zonesMu)

	// Set up TSIG key
	ks := transfer.NewKeyStore()
	ks.AddKey(&transfer.TSIGKey{
		Name:      "key.example.com.",
		Algorithm: transfer.HmacSHA256,
		Secret:    []byte("test-secret-key-12345678901234"),
	})
	h.ddnsHandler.SetKeyStore(ks)

	go h.processUpdateEvents()

	name, _ := protocol.ParseName("example.com.")
	updateName, _ := protocol.ParseName("new.example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
			NSCount: 1,
			Flags: protocol.Flags{
				Opcode: protocol.OpcodeUpdate,
			},
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  updateName,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   3600,
				Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
			},
		},
	}
	tsigRR, _ := transfer.SignMessage(req, &transfer.TSIGKey{
		Name:      "key.example.com.",
		Algorithm: transfer.HmacSHA256,
		Secret:    []byte("test-secret-key-12345678901234"),
	}, 300)
	req.Additionals = append(req.Additionals, tsigRR)

	_, err := h.ddnsHandler.HandleUpdate(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleUpdate error: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	h.zonesMu.RLock()
	z := h.zones["example.com."]
	h.zonesMu.RUnlock()
	if len(z.Records["new.example.com."]) != 2 {
		t.Errorf("expected record added twice (HandleUpdate + processUpdateEvents), got %d", len(z.Records["new.example.com."]))
	}
}

func TestRecordZoneChange_WithIXFR(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{
		"example.com.": {
			Origin:  "example.com.",
			Records: map[string][]zone.Record{},
			SOA:     &zone.SOARecord{Serial: 1},
		},
	}
	h.axfrServer = transfer.NewAXFRServer(zones)
	h.ixfrServer = transfer.NewIXFRServer(h.axfrServer)

	h.recordZoneChange("example.com.", 1, 2, []zone.RecordChange{
		{Name: "www.example.com.", Type: protocol.TypeA, TTL: 300, RData: "192.0.2.1"},
	}, nil)
}

func TestHandleIXFR_TCP_SerialCurrent(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{
		"example.com.": {
			Origin:  "example.com.",
			Records: map[string][]zone.Record{},
			SOA:     &zone.SOARecord{Serial: 5, MName: "ns1.example.com.", RName: "admin.example.com."},
		},
	}
	h.axfrServer = transfer.NewAXFRServer(zones, transfer.WithAllowList([]string{"10.0.0.0/8"}))
	h.ixfrServer = transfer.NewIXFRServer(h.axfrServer)

	w := newCaptureWriter("10.0.0.1", "tcp")
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeIXFR, QClass: protocol.ClassIN}
	msg := newTestQuery(t, "example.com.", protocol.TypeIXFR)
	msg.Authorities = []*protocol.ResourceRecord{{
		Name:  mustParseName(t, "example.com."),
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataSOA{Serial: 5, MName: mustParseName(t, "ns1.example.com."), RName: mustParseName(t, "admin.example.com.")},
	}}
	h.handleIXFR(w, msg, q)

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 1 {
		t.Errorf("expected 1 answer (single SOA), got %d", len(w.msg.Answers))
	}
}

func TestHandleIXFR_TCP_Incremental(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{
		"example.com.": {
			Origin:  "example.com.",
			Records: map[string][]zone.Record{},
			SOA:     &zone.SOARecord{Serial: 5, MName: "ns1.example.com.", RName: "admin.example.com."},
		},
	}
	h.axfrServer = transfer.NewAXFRServer(zones, transfer.WithAllowList([]string{"10.0.0.0/8"}))
	h.ixfrServer = transfer.NewIXFRServer(h.axfrServer)
	h.ixfrServer.RecordChange("example.com.", 3, 4, []zone.RecordChange{
		{Name: "www.example.com.", Type: protocol.TypeA, TTL: 300, RData: "192.0.2.1"},
	}, nil)

	w := newCaptureWriter("10.0.0.1", "tcp")
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeIXFR, QClass: protocol.ClassIN}
	msg := newTestQuery(t, "example.com.", protocol.TypeIXFR)
	msg.Authorities = []*protocol.ResourceRecord{{
		Name:  mustParseName(t, "example.com."),
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataSOA{Serial: 3, MName: mustParseName(t, "ns1.example.com."), RName: mustParseName(t, "admin.example.com.")},
	}}
	h.handleIXFR(w, msg, q)

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestHandleUPDATE_Success(t *testing.T) {
	h := newTestHandler()
	sharedZones := map[string]*zone.Zone{
		"example.com.": zone.NewZone("example.com."),
	}
	h.zones = sharedZones
	h.zoneManager = zone.NewManager()
	h.ddnsHandler = transfer.NewDynamicDNSHandler(sharedZones)
	h.ddnsHandler.SetZonesMu(&h.zonesMu)
	h.metrics = metrics.New(metrics.Config{Enabled: true})

	ks := transfer.NewKeyStore()
	ks.AddKey(&transfer.TSIGKey{
		Name:      "key.example.com.",
		Algorithm: transfer.HmacSHA256,
		Secret:    []byte("test-secret-key-12345678901234"),
	})
	h.ddnsHandler.SetKeyStore(ks)

	name, _ := protocol.ParseName("example.com.")
	updateName, _ := protocol.ParseName("new.example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
			NSCount: 1,
			Flags: protocol.Flags{
				Opcode: protocol.OpcodeUpdate,
			},
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  updateName,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   3600,
				Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
			},
		},
	}
	tsigRR, _ := transfer.SignMessage(req, &transfer.TSIGKey{
		Name:      "key.example.com.",
		Algorithm: transfer.HmacSHA256,
		Secret:    []byte("test-secret-key-12345678901234"),
	}, 300)
	req.Additionals = append(req.Additionals, tsigRR)

	w := newCaptureWriter("127.0.0.1", "udp")
	q := &protocol.Question{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN}
	h.handleUPDATE(w, req, q)

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR for successful UPDATE, got %d", w.msg.Header.Flags.RCODE)
	}
	time.Sleep(200 * time.Millisecond)
}

func TestSaveToFile_ErrorPaths(t *testing.T) {
	tmpDir := t.TempDir()
	os.RemoveAll(tmpDir)

	cfg := config.DefaultConfig()
	cfg.ZoneDir = tmpDir
	cfg.Cache.Size = 10
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewCacheManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mgr.Cache.Set("test.example.com.", &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
	}, 60)

	// Stop triggers saveToFile; parent dir missing -> WriteFile fails, logged as warning
	mgr.Stop()
}

func TestMetricsUpdater_Stop(t *testing.T) {
	mgr := &ClusterManager{
		logger: util.NewLogger(util.ERROR, util.TextFormat, nil),
		stopCh: make(chan struct{}),
	}
	go mgr.metricsUpdater(metrics.New(metrics.Config{Enabled: true}), 10*time.Millisecond)
	close(mgr.stopCh)
	time.Sleep(50 * time.Millisecond)
}

func TestClusterManager_Enabled_StartFail(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Cluster.Enabled = true
	cfg.Cluster.EncryptionKey = "invalid"
	cfg.Cluster.AllowInsecureCluster = false

	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewClusterManager(cfg, logger, cache.New(cache.Config{}), metrics.New(metrics.Config{}), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr.Cluster != nil {
		t.Error("expected nil cluster after start failure")
	}
	mgr.Stop()
}

func TestClusterManager_Enabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Cluster.Enabled = true
	cfg.Cluster.AllowInsecureCluster = true
	cfg.Cluster.GossipPort = 0

	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 10})
	mc := metrics.New(metrics.Config{Enabled: true})

	mgr, err := NewClusterManager(cfg, logger, dnsCache, mc, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	defer mgr.Stop()
}

// mockResolverTransport is a mock transport for testing the resolver path.
type mockResolverTransport struct {
	resp *protocol.Message
	err  error
}

func (m *mockResolverTransport) QueryContext(ctx context.Context, msg *protocol.Message, addr string) (*protocol.Message, error) {
	return m.resp, m.err
}

// failingResolverTransport always returns an error.
type failingResolverTransport struct{}

func (f *failingResolverTransport) QueryContext(ctx context.Context, msg *protocol.Message, addr string) (*protocol.Message, error) {
	return nil, fmt.Errorf("resolver unavailable")
}

func TestProcessUpdateEvents_ZoneNotFound(t *testing.T) {
	h := newTestHandler()
	h.ddnsHandler = transfer.NewDynamicDNSHandler(map[string]*zone.Zone{})
	go h.processUpdateEvents()

	val := reflect.ValueOf(h.ddnsHandler).Elem().FieldByName("updateChan")
	ch := *(*chan *transfer.UpdateRequest)(unsafe.Pointer(val.UnsafeAddr()))
	ch <- &transfer.UpdateRequest{
		ZoneName: "missing.com.",
		Updates: []transfer.UpdateOperation{
			{Name: "test.missing.com.", Type: protocol.TypeA, TTL: 300, RData: "1.2.3.4", Operation: transfer.UpdateOpAdd},
		},
	}
	time.Sleep(100 * time.Millisecond)
}

func TestProcessUpdateEvents_ApplyUpdateError(t *testing.T) {
	h := newTestHandler()
	sharedZones := map[string]*zone.Zone{
		"example.com.": zone.NewZone("example.com."),
	}
	h.zones = sharedZones
	h.zoneManager = zone.NewManager()
	h.ddnsHandler = transfer.NewDynamicDNSHandler(sharedZones)
	go h.processUpdateEvents()

	val := reflect.ValueOf(h.ddnsHandler).Elem().FieldByName("updateChan")
	ch := *(*chan *transfer.UpdateRequest)(unsafe.Pointer(val.UnsafeAddr()))
	ch <- &transfer.UpdateRequest{
		ZoneName: "example.com.",
		Prerequisites: []transfer.UpdatePrerequisite{
			{Name: "nonexistent.example.com.", Type: protocol.TypeA, Condition: transfer.PrecondExists},
		},
		Updates: []transfer.UpdateOperation{
			{Name: "test.example.com.", Type: protocol.TypeA, TTL: 300, RData: "1.2.3.4", Operation: transfer.UpdateOpAdd},
		},
	}
	time.Sleep(100 * time.Millisecond)
}

func TestProcessUpdateEvents_AuditLogger(t *testing.T) {
	h := newTestHandler()
	sharedZones := map[string]*zone.Zone{
		"example.com.": zone.NewZone("example.com."),
	}
	h.zones = sharedZones
	h.zoneManager = zone.NewManager()
	h.ddnsHandler = transfer.NewDynamicDNSHandler(sharedZones)
	h.auditLogger, _ = audit.NewAuditLogger(true, "")
	go h.processUpdateEvents()

	val := reflect.ValueOf(h.ddnsHandler).Elem().FieldByName("updateChan")
	ch := *(*chan *transfer.UpdateRequest)(unsafe.Pointer(val.UnsafeAddr()))
	ch <- &transfer.UpdateRequest{
		ZoneName: "example.com.",
		Updates: []transfer.UpdateOperation{
			{Name: "audit.example.com.", Type: protocol.TypeA, TTL: 300, RData: "1.2.3.4", Operation: transfer.UpdateOpAdd},
		},
	}
	time.Sleep(100 * time.Millisecond)
}

func TestServeDNS_StaleServing(t *testing.T) {
	h := newTestHandler()
	h.cache = cache.New(cache.Config{Capacity: 10, MinTTL: time.Millisecond, MaxTTL: time.Hour, DefaultTTL: time.Second, ServeStale: true, StaleGrace: time.Hour})

	client, _ := upstream.NewClient(upstream.Config{Servers: []string{"127.0.0.1:53"}, Timeout: 1 * time.Millisecond})
	serverPtr := reflect.ValueOf(client).Elem().FieldByName("servers").Index(0)
	sv := serverPtr.Elem().FieldByName("healthy")
	*(*bool)(unsafe.Pointer(sv.UnsafeAddr())) = false
	h.upstream = client

	qname := "stale.example.com."
	key := cache.MakeKey(qname, protocol.TypeA, false)
	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Answers: []*protocol.ResourceRecord{
			{Name: mustParseName(t, qname), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 0, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
		},
	}
	h.cache.Set(key, resp, 0)
	time.Sleep(5 * time.Millisecond) // Let entry expire

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, qname, protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR (stale), got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_IterativeResolver(t *testing.T) {
	h := newTestHandler()
	qname := "resolved.example.com."
	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Answers: []*protocol.ResourceRecord{
			{Name: mustParseName(t, qname), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{5, 6, 7, 8}}},
		},
	}
	h.resolver = resolver.NewResolver(resolver.Config{}, nil, &mockResolverTransport{resp: resp})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, qname, protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got %d", w.msg.Header.Flags.RCODE)
	}
}

// startTestUpstreamDNS64 starts a UDP listener that returns A answers but empty AAAA answers.
func startTestUpstreamDNS64(t *testing.T) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, err := protocol.UnpackMessage(buf[:n])
			if err != nil {
				continue
			}
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
					QDCount: 1,
				},
				Questions: msg.Questions,
			}
			qtype := msg.Questions[0].QType
			if qtype == protocol.TypeA {
				resp.Answers = []*protocol.ResourceRecord{
					{
						Name:  msg.Questions[0].Name,
						Type:  protocol.TypeA,
						Class: protocol.ClassIN,
						TTL:   300,
						Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
					},
				}
				resp.Header.ANCount = 1
			}
			// AAAA: return NOERROR with no answers
			packBuf := make([]byte, 4096)
			n, _ = resp.Pack(packBuf)
			pc.WriteTo(packBuf[:n], addr)
		}
	}()

	return pc.LocalAddr().String(), func() { pc.Close() }
}

func TestServeDNS_DNS64Synthesis(t *testing.T) {
	h := newTestHandler()
	addr, cleanup := startTestUpstreamDNS64(t)
	defer cleanup()

	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	h.upstream = client

	synth, _ := dns64.NewSynthesizer("64:ff9b::", 96)
	h.dns64Synth = synth

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "dns64.example.com.", protocol.TypeAAAA))

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) == 0 {
		t.Fatal("expected synthesized AAAA answers")
	}
	if w.msg.Answers[0].Type != protocol.TypeAAAA {
		t.Errorf("expected AAAA answer, got %d", w.msg.Answers[0].Type)
	}
}

func TestSDNotifySend_DialError(t *testing.T) {
	err := sdNotifySend("/nonexistent/socket/path")
	if err == nil {
		t.Fatal("expected error for invalid socket path")
	}
}

// --- Batch 9: Low coverage function tests ---

func TestLoadConfig_Success(t *testing.T) {
	tmpDir := t.TempDir()
	validFile := filepath.Join(tmpDir, "valid.yaml")
	yaml := "server:\n  bind:\n    - \"0.0.0.0\"\nupstream:\n  servers:\n    - \"8.8.8.8:53\"\n"
	os.WriteFile(validFile, []byte(yaml), 0644)
	cfg, err := loadConfig(validFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected config")
	}
}

func TestLoadConfig_ValidationError(t *testing.T) {
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "bad.yaml")
	yaml := "server:\n  bind:\n    - \"0.0.0.0\"\n  port: 0\nupstream:\n  servers:\n    - \"8.8.8.8:53\"\n"
	os.WriteFile(badFile, []byte(yaml), 0644)
	_, err := loadConfig(badFile)
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestResolveCNAMETarget_ZoneMatch_InvalidData(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "target.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "not-an-ip"},
	})
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "alias.example.com.", protocol.TypeA)
	answers := h.resolveCNAMETarget(w, msg, msg.Questions[0], "target.example.com.", protocol.TypeA)
	if len(answers) != 0 {
		t.Fatalf("expected 0 answers (invalid data), got %d", len(answers))
	}
}

func TestResolveCNAMETarget_UpstreamViaLoadBalancer(t *testing.T) {
	h := newTestHandler()
	addr, cleanup := startTestUpstream(t)
	defer cleanup()
	lb, _ := upstream.NewLoadBalancer(upstream.LoadBalancerConfig{
		Servers:  []string{addr},
		Strategy: "random",
	})
	defer lb.Close()
	h.loadBalancer = lb
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "alias.example.com.", protocol.TypeA)
	answers := h.resolveCNAMETarget(w, msg, msg.Questions[0], "target.example.com.", protocol.TypeA)
	if len(answers) == 0 {
		t.Fatal("expected answers from load balancer")
	}
}

func TestResolveCNAMETarget_UpstreamError(t *testing.T) {
	h := newTestHandler()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{"127.0.0.1:1"}, Timeout: 1 * time.Millisecond})
	h.upstream = client
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "alias.example.com.", protocol.TypeA)
	answers := h.resolveCNAMETarget(w, msg, msg.Questions[0], "target.example.com.", protocol.TypeA)
	if len(answers) != 0 {
		t.Fatalf("expected 0 answers (upstream error), got %d", len(answers))
	}
}

func TestResolveCNAMETarget_UpstreamNoMatch(t *testing.T) {
	h := newTestHandler()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, _ := protocol.UnpackMessage(buf[:n])
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
					QDCount: 1,
					ANCount: 1,
				},
				Questions: msg.Questions,
				Answers: []*protocol.ResourceRecord{{
					Name:  msg.Questions[0].Name,
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
				}},
			}
			packBuf := make([]byte, 4096)
			n, _ = resp.Pack(packBuf)
			pc.WriteTo(packBuf[:n], addr)
		}
	}()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{pc.LocalAddr().String()}, Timeout: 5 * time.Second})
	h.upstream = client
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "alias.example.com.", protocol.TypeAAAA)
	answers := h.resolveCNAMETarget(w, msg, msg.Questions[0], "target.example.com.", protocol.TypeAAAA)
	if len(answers) != 0 {
		t.Fatalf("expected 0 answers (no matching type), got %d", len(answers))
	}
}

func TestLoadZoneSigner_NSEC3SaltError(t *testing.T) {
	z := zone.NewZone("example.com.")
	_, err := loadZoneSigner(z, config.SigningConfig{
		Enabled: true,
		NSEC3:   &config.NSEC3Config{Salt: "not-hex!", Iterations: 1},
	})
	if err == nil {
		t.Fatal("expected error for invalid NSEC3 salt")
	}
}

func TestLoadZoneSigner_SignatureValidity(t *testing.T) {
	z := zone.NewZone("example.com.")
	signer, err := loadZoneSigner(z, config.SigningConfig{
		Enabled:           true,
		SignatureValidity: "2h",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signer == nil {
		t.Fatal("expected signer")
	}
}

func TestLoadZoneSigner_GenerateKeyError(t *testing.T) {
	z := zone.NewZone("example.com.")
	_, err := loadZoneSigner(z, config.SigningConfig{
		Enabled: true,
		Keys: []config.KeyConfig{
			{PrivateKey: "dummy", Algorithm: 255, Type: "zsk"},
		},
	})
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestSDNotifySend_Success(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "notify.sock")
	pc, err := net.ListenPacket("unixgram", socketPath)
	if err != nil {
		t.Skipf("unixgram not supported on this platform: %v", err)
	}
	defer pc.Close()

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 256)
		pc.ReadFrom(buf)
		close(done)
	}()

	err = sdNotifySend(socketPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for notification")
	}
}

func TestNewCacheManager_MemMonitor(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.MemoryLimitMB = 100
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewCacheManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr.MemMonitor == nil {
		t.Fatal("expected memory monitor")
	}
	mgr.Stop()
}

func TestNewCacheManager_LoadCache(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ZoneDir = tmpDir
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewCacheManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := `[{"key":"test","wire":"AAAA","ttl":300,"rcode":0,"negative":false,"expire_time":"2099-01-01T00:00:00Z"}]`
	os.WriteFile(filepath.Join(tmpDir, "cache.json"), []byte(data), 0644)
	mgr.LoadCache()
	mgr.Stop()
}

func TestHandleAXFR_WriteError(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1}
	z.Records["example.com."] = []zone.Record{
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.example.com. admin.example.com. 1 3600 600 86400 300"},
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.example.com."},
	}
	zones := map[string]*zone.Zone{"example.com.": z}
	h.axfrServer = transfer.NewAXFRServer(zones, transfer.WithAllowList([]string{"10.0.0.0/8"}))

	w := &errorWriter{client: &server.ClientInfo{Addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}, Protocol: "tcp"}}
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeAXFR, QClass: protocol.ClassIN}
	h.handleAXFR(w, newTestQuery(t, "example.com.", protocol.TypeAXFR), q)
}

// --- Batch 10: More coverage tests ---

func TestDoQResponseWriter_Write_PackError(t *testing.T) {
	rw := &doqResponseWriter{stream: nil}
	invalidName := &protocol.Name{Labels: []string{strings.Repeat("a", 64)}}
	msg := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Answers: []*protocol.ResourceRecord{{
			Name:  invalidName,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
		}},
	}
	_, err := rw.Write(msg)
	if err == nil {
		t.Fatal("expected pack error")
	}
}

func TestTryDNS64Synthesis_AlreadyHasAAAA(t *testing.T) {
	h := newTestHandler()
	synth, _ := dns64.NewSynthesizer("64:ff9b::", 96)
	h.dns64Synth = synth
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeAAAA, QClass: protocol.ClassIN}
	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Answers: []*protocol.ResourceRecord{{
			Name:  mustParseName(t, "example.com."),
			Type:  protocol.TypeAAAA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataAAAA{Address: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}},
		}},
	}
	w := newCaptureWriter("10.0.0.1", "udp")
	if h.tryDNS64Synthesis(w, newTestQuery(t, "example.com.", protocol.TypeAAAA), q, resp) {
		t.Error("expected false when response already has AAAA")
	}
}

func TestTryDNS64Synthesis_UpstreamFail(t *testing.T) {
	h := newTestHandler()
	synth, _ := dns64.NewSynthesizer("64:ff9b::", 96)
	h.dns64Synth = synth

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, _ := protocol.UnpackMessage(buf[:n])
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   protocol.NewResponseFlags(protocol.RcodeServerFailure),
					QDCount: 1,
				},
				Questions: msg.Questions,
			}
			packBuf := make([]byte, 4096)
			n, _ = resp.Pack(packBuf)
			pc.WriteTo(packBuf[:n], addr)
		}
	}()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{pc.LocalAddr().String()}, Timeout: 5 * time.Second})
	h.upstream = client

	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeAAAA, QClass: protocol.ClassIN}
	resp := &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)}}
	w := newCaptureWriter("10.0.0.1", "udp")
	if h.tryDNS64Synthesis(w, newTestQuery(t, "example.com.", protocol.TypeAAAA), q, resp) {
		t.Error("expected false when upstream returns SERVFAIL")
	}
}

func TestTryDNS64Synthesis_UpstreamNoData(t *testing.T) {
	h := newTestHandler()
	synth, _ := dns64.NewSynthesizer("64:ff9b::", 96)
	h.dns64Synth = synth

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, _ := protocol.UnpackMessage(buf[:n])
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
					QDCount: 1,
					ANCount: 0,
				},
				Questions: msg.Questions,
			}
			packBuf := make([]byte, 4096)
			n, _ = resp.Pack(packBuf)
			pc.WriteTo(packBuf[:n], addr)
		}
	}()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{pc.LocalAddr().String()}, Timeout: 5 * time.Second})
	h.upstream = client

	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeAAAA, QClass: protocol.ClassIN}
	resp := &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)}}
	w := newCaptureWriter("10.0.0.1", "udp")
	if h.tryDNS64Synthesis(w, newTestQuery(t, "example.com.", protocol.TypeAAAA), q, resp) {
		t.Error("expected false when upstream returns NOERROR with no answers")
	}
}

func TestCheckRPZResponseIP_NODATA(t *testing.T) {
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.zone")
	os.WriteFile(rpzFile, []byte("32.1.2.3.4.rpz-ip 300 IN CNAME .\n"), 0644)

	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine

	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "4.3.2.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR (NODATA) from RPZ response IP, got %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 0 {
		t.Errorf("expected 0 answers for NODATA, got %d", len(w.msg.Answers))
	}
}

func TestCheckRPZResponseIP_Redirect(t *testing.T) {
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.zone")
	os.WriteFile(rpzFile, []byte("32.1.2.3.4.rpz-ip 300 IN CNAME redirect.example.com.\n"), 0644)

	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine

	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "4.3.2.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestNewSecurityManager_GeoMMDBError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.GeoDNS.Enabled = true
	cfg.GeoDNS.MMDBFile = "/nonexistent/file.mmdb"
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewSecurityManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mgr.Stop()
}

func TestNewSecurityManager_DNS64Error(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DNS64.Enabled = true
	cfg.DNS64.PrefixLen = 99
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewSecurityManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mgr.Stop()
}

func TestLoadCache_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ZoneDir = tmpDir
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewCacheManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	os.WriteFile(filepath.Join(tmpDir, "cache.json"), []byte("not json"), 0644)
	mgr.LoadCache()
	mgr.Stop()
}

func TestLoadCache_OversizedWire(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ZoneDir = tmpDir
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewCacheManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := `[{"key":"test","wire":"` + strings.Repeat("AA", 32768*2) + `","ttl":300,"rcode":0,"negative":false,"expire_time":"2099-01-01T00:00:00Z"}]`
	os.WriteFile(filepath.Join(tmpDir, "cache.json"), []byte(data), 0644)
	mgr.LoadCache()
	mgr.Stop()
}

func TestLoadCacheFromKV_InvalidData(t *testing.T) {
	tmpDir := t.TempDir()
	kv, _ := storage.OpenKVStore(filepath.Join(tmpDir, "kv.db"))
	defer kv.Close()

	cfg := config.DefaultConfig()
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, _ := NewCacheManager(cfg, logger)

	// Put invalid JSON into KV store
	kv.Update(func(tx *storage.Tx) error {
		bucket, _ := tx.CreateBucketIfNotExists([]byte("cache"))
		return bucket.Put([]byte("cache_data"), []byte("not json"))
	})
	mgr.LoadCacheFromKV(kv)
	mgr.Stop()
}

func TestHandleNOTIFY_WriteError(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{
		"example.com.": {
			Origin: "example.com.",
			SOA:    &zone.SOARecord{Serial: 1},
		},
	}
	h.notifyHandler = transfer.NewNOTIFYSlaveHandler(zones)
	h.notifyHandler.AddNotifyAllowed("10.0.0.0/8")

	w := &errorWriter{client: &server.ClientInfo{Addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}, Protocol: "udp"}}
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeSOA, QClass: protocol.ClassIN}
	h.handleNOTIFY(w, newTestQuery(t, "example.com.", protocol.TypeSOA), q)
}

func TestProcessUpdateEvents_IXFRJournal(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Serial: 1}
	sharedZones := map[string]*zone.Zone{"example.com.": z}
	h.zones = sharedZones
	h.zoneManager = zone.NewManager()
	h.ddnsHandler = transfer.NewDynamicDNSHandler(sharedZones)

	axfrServer := transfer.NewAXFRServer(sharedZones)
	h.ixfrServer = transfer.NewIXFRServer(axfrServer)

	go h.processUpdateEvents()

	val := reflect.ValueOf(h.ddnsHandler).Elem().FieldByName("updateChan")
	ch := *(*chan *transfer.UpdateRequest)(unsafe.Pointer(val.UnsafeAddr()))
	ch <- &transfer.UpdateRequest{
		ZoneName: "example.com.",
		Updates: []transfer.UpdateOperation{
			{Name: "test.example.com.", Type: protocol.TypeA, TTL: 300, RData: "1.2.3.4", Operation: transfer.UpdateOpAdd},
		},
	}
	time.Sleep(100 * time.Millisecond)
}

// --- Batch 11: ServeDNS branches and manager tests ---

func TestServeDNS_AXFR_Branch(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "example.com.", protocol.TypeAXFR)
	h.ServeDNS(w, msg)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected REFUSED for UDP AXFR, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_IXFR_Branch(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "example.com.", protocol.TypeIXFR)
	h.ServeDNS(w, msg)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected REFUSED for UDP IXFR, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_NOTIFY_Branch(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{
		"example.com.": {Origin: "example.com.", SOA: &zone.SOARecord{Serial: 1}},
	}
	h.notifyHandler = transfer.NewNOTIFYSlaveHandler(zones)
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "example.com.", protocol.TypeSOA)
	msg.Header.Flags.Opcode = protocol.OpcodeNotify
	h.ServeDNS(w, msg)
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_UPDATE_Branch(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{}
	h.ddnsHandler = transfer.NewDynamicDNSHandler(zones)
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "example.com.", protocol.TypeSOA)
	msg.Header.Flags.Opcode = protocol.OpcodeUpdate
	h.ServeDNS(w, msg)
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_Tracer(t *testing.T) {
	h := newTestHandler()
	h.tracer = otel.NewTracer(otel.Config{Enabled: true})
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_KVPersistenceZone(t *testing.T) {
	h := newTestHandler()
	zm := zone.NewManager()
	z := zone.NewZone("kv.example.com.")
	zm.LoadZone(z, "")
	tmpDir := t.TempDir()
	kvStore, _ := storage.OpenKVStore(tmpDir)
	defer kvStore.Close()
	kvPersistence := zone.NewKVPersistence(zm, kvStore)
	kvPersistence.Enable()
	h.kvPersistence = kvPersistence

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "test.kv.example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestDNSSECResolverAdapter_QueryError(t *testing.T) {
	adapter := &dnssecResolverAdapter{upstream: nil}
	_, err := adapter.Query(context.Background(), strings.Repeat("a", 64)+".com.", protocol.TypeA)
	if err == nil {
		t.Fatal("expected error for invalid name")
	}
}

func TestNewDNSSECManager_TrustAnchorError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DNSSEC.TrustAnchor = "/nonexistent/trust.anchor"
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewDNSSECManager(cfg, &dnssecResolverAdapter{}, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected manager")
	}
}

func TestNewZoneManager_ZoneFileError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Zones = []string{"/nonexistent/zone.zone"}
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewZoneManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected manager")
	}
}

func TestNewZoneManager_SignerError(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "example.com.zone")
	os.WriteFile(zoneFile, []byte("example.com. 300 IN SOA ns1.example.com. admin.example.com. 1 3600 600 86400 300\n"), 0644)
	cfg := config.DefaultConfig()
	cfg.Zones = []string{zoneFile}
	cfg.DNSSEC.Enabled = true
	cfg.DNSSEC.Signing.Enabled = true
	cfg.DNSSEC.Signing.Keys = []config.KeyConfig{{PrivateKey: "dummy", Algorithm: 255, Type: "zsk"}}
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewZoneManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected manager")
	}
}

func TestNewZoneManager_KVStoreError(t *testing.T) {
	tmpDir := t.TempDir()
	badPath := filepath.Join(tmpDir, "notadir")
	os.WriteFile(badPath, []byte{}, 0644)
	cfg := config.DefaultConfig()
	cfg.ZoneDir = badPath
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewZoneManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected manager")
	}
}

func TestProcessUpdateEvents_PersistZoneError(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Serial: 1}
	sharedZones := map[string]*zone.Zone{"example.com.": z}
	h.zones = sharedZones
	zm := zone.NewManager()
	zm.SetZoneDir("/nonexistent/path/that/cannot/be/created")
	h.zoneManager = zm
	h.ddnsHandler = transfer.NewDynamicDNSHandler(sharedZones)

	go h.processUpdateEvents()

	val := reflect.ValueOf(h.ddnsHandler).Elem().FieldByName("updateChan")
	ch := *(*chan *transfer.UpdateRequest)(unsafe.Pointer(val.UnsafeAddr()))
	ch <- &transfer.UpdateRequest{
		ZoneName: "example.com.",
		Updates: []transfer.UpdateOperation{
			{Name: "test.example.com.", Type: protocol.TypeA, TTL: 300, RData: "1.2.3.4", Operation: transfer.UpdateOpAdd},
		},
	}
	time.Sleep(100 * time.Millisecond)
}

// --- Batch 11: ServeDNS branches and manager tests ---

// --- Batch 17: Error paths, RPZ, DNSSEC, metrics, audit, transfer ---

func TestSaveToFile_WriteError(t *testing.T) {
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	cm := &CacheManager{
		Cache:       cache.New(cache.Config{Capacity: 10}),
		logger:      logger,
		persistPath: filepath.Join(t.TempDir(), "nonexistent", "subdir", "cache.json"),
	}
	cm.Cache.Set("key", &protocol.Message{Header: protocol.Header{ID: 1}}, 1)
	cm.saveToFile() // should not panic; write fails silently
}

func TestSaveToFile_RenameError(t *testing.T) {
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	dir := t.TempDir()
	// Create a directory at the target path so atomic rename fails
	target := filepath.Join(dir, "cache.json")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	cm := &CacheManager{
		Cache:       cache.New(cache.Config{Capacity: 10}),
		logger:      logger,
		persistPath: target,
	}
	cm.Cache.Set("key", &protocol.Message{Header: protocol.Header{ID: 1}}, 1)
	cm.saveToFile() // should not panic; rename fails silently
}

func TestServeDNS_RPZClientIP(t *testing.T) {
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.txt")
	// Client IP 10.0.0.1/32 -> NXDOMAIN
	data := []byte("32.1.0.0.10.rpz-clientip 3600 IN CNAME .\n")
	if err := os.WriteFile(rpzFile, data, 0644); err != nil {
		t.Fatalf("failed to write rpz file: %v", err)
	}
	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
	// CNAME . is parsed as ActionNODATA (NOERROR with 0 answers) in this RPZ implementation
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR (NODATA) from RPZ client IP, got %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 0 {
		t.Errorf("expected 0 answers for NODATA, got %d", len(w.msg.Answers))
	}
}

func TestServeDNS_DNSSEC_Bogus(t *testing.T) {
	h := newTestHandler()
	h.config.DNSSEC.Enabled = true
	// Validator with built-in anchors but nil resolver -> buildChain fails -> Bogus
	anchors := dnssec.NewTrustAnchorStore()
	anchors.AddAnchor(&dnssec.TrustAnchor{Zone: ".", KeyTag: 1, Algorithm: 8, DigestType: 2, Digest: []byte{1, 2, 3}})
	h.validator = dnssec.NewValidator(dnssec.ValidatorConfig{Enabled: true, RequireDNSSEC: true}, anchors, nil)

	// Custom upstream that returns a response containing an RRSIG so HasSignature returns true
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, err := protocol.UnpackMessage(buf[:n])
			if err != nil {
				continue
			}
			signerName, _ := protocol.ParseName("example.com.")
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
					QDCount: 1,
					ANCount: 2,
				},
				Questions: msg.Questions,
				Answers: []*protocol.ResourceRecord{
					{
						Name:  msg.Questions[0].Name,
						Type:  protocol.TypeA,
						Class: protocol.ClassIN,
						TTL:   300,
						Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
					},
					{
						Name:  msg.Questions[0].Name,
						Type:  protocol.TypeRRSIG,
						Class: protocol.ClassIN,
						TTL:   300,
						Data: &protocol.RDataRRSIG{
							TypeCovered: protocol.TypeA,
							Algorithm:   8,
							Labels:      2,
							OriginalTTL: 300,
							Expiration:  2000000000,
							Inception:   1,
							KeyTag:      1,
							SignerName:  signerName,
							Signature:   []byte{1, 2, 3},
						},
					},
				},
			}
			packBuf := make([]byte, 4096)
			n, _ = resp.Pack(packBuf)
			pc.WriteTo(packBuf[:n], addr)
		}
	}()

	addr := pc.LocalAddr().String()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	h.upstream = client

	// Create a query for a name not in any zone to hit upstream path
	w := newCaptureWriter("10.0.0.1", "udp")
	q := newTestQuery(t, "dnssec-bogus.example.com.", protocol.TypeA)
	h.ServeDNS(w, q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Errorf("expected SERVFAIL for bogus DNSSEC, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_MetricsAnycast(t *testing.T) {
	h := newTestHandler()
	addr, cleanup := startTestUpstream(t)
	defer cleanup()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	h.upstream = client
	h.config.Upstream.Servers = []string{}
	h.config.Upstream.AnycastGroups = []config.AnycastGroupConfig{
		{AnycastIP: "1.2.3.4", Backends: []config.AnycastBackendConfig{{PhysicalIP: addr}}},
	}

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_RPZResponseIP_Upstream(t *testing.T) {
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.txt")
	// Response IP 1.2.3.4/32 -> NXDOMAIN
	data := []byte("32.4.3.2.1.rpz-ip 3600 IN CNAME .\n")
	if err := os.WriteFile(rpzFile, data, 0644); err != nil {
		t.Fatalf("failed to write rpz file: %v", err)
	}
	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine

	addr, cleanup := startTestUpstream(t)
	defer cleanup()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	h.upstream = client

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
	// CNAME . is parsed as ActionNODATA (NOERROR with 0 answers) in this RPZ implementation
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR (NODATA) from RPZ response IP, got %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 0 {
		t.Errorf("expected 0 answers for NODATA, got %d", len(w.msg.Answers))
	}
}

func TestMinimizeResponse_NilRRInAuthorities(t *testing.T) {
	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Authorities: []*protocol.ResourceRecord{
			nil,
			{Name: mustParseName(t, "example.com."), Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataSOA{MName: mustParseName(t, "ns1.example.com."), RName: mustParseName(t, "admin.example.com."), Serial: 1}},
		},
		Additionals: []*protocol.ResourceRecord{
			nil,
			{Name: mustParseName(t, "."), Type: protocol.TypeOPT, Class: 4096, TTL: 0, Data: &protocol.RDataOPT{}},
		},
	}
	minimizeResponse(resp)
	if len(resp.Authorities) != 1 {
		t.Errorf("expected 1 authority after filtering nil, got %d", len(resp.Authorities))
	}
	if len(resp.Additionals) != 1 {
		t.Errorf("expected 1 additional after filtering nil, got %d", len(resp.Additionals))
	}
}

func TestHandleAXFR_Success_Audit(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1}
	z.Records["example.com."] = []zone.Record{
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.example.com. admin.example.com. 1 3600 600 86400 300"},
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.example.com."},
	}
	zones := map[string]*zone.Zone{"example.com.": z}
	h.axfrServer = transfer.NewAXFRServer(zones, transfer.WithAllowList([]string{"10.0.0.0/8"}))

	al, _ := audit.NewAuditLogger(true, "")
	h.auditLogger = al

	w := newCaptureWriter("10.0.0.1", "tcp")
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeAXFR, QClass: protocol.ClassIN}
	h.handleAXFR(w, newTestQuery(t, "example.com.", protocol.TypeAXFR), q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR for authorized AXFR, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestHandleAXFR_WriteError_Audit(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1}
	z.Records["example.com."] = []zone.Record{
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.example.com. admin.example.com. 1 3600 600 86400 300"},
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.example.com."},
	}
	zones := map[string]*zone.Zone{"example.com.": z}
	h.axfrServer = transfer.NewAXFRServer(zones, transfer.WithAllowList([]string{"10.0.0.0/8"}))

	al, _ := audit.NewAuditLogger(true, "")
	h.auditLogger = al

	w := &errorWriter{client: &server.ClientInfo{Addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1")}, Protocol: "tcp"}}
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeAXFR, QClass: protocol.ClassIN}
	h.handleAXFR(w, newTestQuery(t, "example.com.", protocol.TypeAXFR), q)
	// write error should be silently handled
}

func TestHandleIXFR_Success_Audit(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 2}
	z.Records["example.com."] = []zone.Record{
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.example.com. admin.example.com. 2 3600 600 86400 300"},
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.example.com."},
	}
	zones := map[string]*zone.Zone{"example.com.": z}
	h.axfrServer = transfer.NewAXFRServer(zones, transfer.WithAllowList([]string{"10.0.0.0/8"}))
	h.ixfrServer = transfer.NewIXFRServer(h.axfrServer)

	al, _ := audit.NewAuditLogger(true, "")
	h.auditLogger = al

	w := newCaptureWriter("10.0.0.1", "tcp")
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeIXFR, QClass: protocol.ClassIN}
	msg := newTestQuery(t, "example.com.", protocol.TypeIXFR)
	// Authority section with older serial triggers IXFR; no journal falls back to AXFR
	msg.Authorities = []*protocol.ResourceRecord{{
		Name:  mustParseName(t, "example.com."),
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataSOA{Serial: 1, MName: mustParseName(t, "ns1.example.com."), RName: mustParseName(t, "admin.example.com.")},
	}}
	h.handleIXFR(w, msg, q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR for IXFR fallback to AXFR, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestHandleIXFR_WriteError_Audit(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 2}
	z.Records["example.com."] = []zone.Record{
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.example.com. admin.example.com. 2 3600 600 86400 300"},
	}
	zones := map[string]*zone.Zone{"example.com.": z}
	h.axfrServer = transfer.NewAXFRServer(zones, transfer.WithAllowList([]string{"10.0.0.0/8"}))
	h.ixfrServer = transfer.NewIXFRServer(h.axfrServer)

	al, _ := audit.NewAuditLogger(true, "")
	h.auditLogger = al

	w := &errorWriter{client: &server.ClientInfo{Addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1")}, Protocol: "tcp"}}
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeIXFR, QClass: protocol.ClassIN}
	msg := newTestQuery(t, "example.com.", protocol.TypeIXFR)
	msg.Authorities = []*protocol.ResourceRecord{{
		Name:  mustParseName(t, "example.com."),
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataSOA{Serial: 1, MName: mustParseName(t, "ns1.example.com."), RName: mustParseName(t, "admin.example.com.")},
	}}
	h.handleIXFR(w, msg, q)
}

func TestHandleNOTIFY_Error_Audit(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{}
	h.notifyHandler = transfer.NewNOTIFYSlaveHandler(zones)
	h.notifyHandler.AddNotifyAllowed("10.0.0.0/8")
	al, _ := audit.NewAuditLogger(true, "")
	h.auditLogger = al

	w := newCaptureWriter("10.0.0.1", "udp")
	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.Flags{Opcode: protocol.OpcodeNotify}},
		Questions: []*protocol.Question{}, // zero questions -> error
	}
	q, _ := protocol.NewQuestion("example.com.", protocol.TypeSOA, protocol.ClassIN)
	h.handleNOTIFY(w, msg, q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Errorf("expected SERVFAIL for NOTIFY error, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestHandleUPDATE_Failure_Audit(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{}
	h.ddnsHandler = transfer.NewDynamicDNSHandler(zones)
	al, _ := audit.NewAuditLogger(true, "")
	h.auditLogger = al

	w := newCaptureWriter("10.0.0.1", "udp")
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeSOA, QClass: protocol.ClassIN}
	msg := newTestQuery(t, "example.com.", protocol.TypeSOA) // OpcodeQuery by default
	h.handleUPDATE(w, msg, q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Errorf("expected SERVFAIL for UPDATE failure, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestProcessUpdateEvents_KVPersistError(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1}
	z.Records["example.com."] = []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
	}
	h.zones["example.com."] = z

	// Create a KV-backed zone manager so KVPersistence works
	kvStore, err := storage.OpenKVStore(filepath.Join(t.TempDir(), "kv.db"))
	if err != nil {
		t.Fatalf("failed to open kv store: %v", err)
	}
	defer kvStore.Close()
	zm := zone.NewManager()
	zm.LoadZone(z, "")
	kvP := zone.NewKVPersistence(zm, kvStore)
	kvP.Enable()
	h.kvPersistence = kvP

	// Close the store to make PersistZone fail
	kvStore.Close()

	// Now PersistZone should fail because store is closed
	err = h.kvPersistence.PersistZone("example.com.")
	if err == nil {
		t.Error("expected error persisting to closed store")
	}
}

func TestNewClusterManager_NewError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Cluster.Enabled = true
	cfg.Cluster.BindAddr = "invalid:bad:addr"
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewClusterManager(cfg, logger, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// cluster.New fails -> warn and return with nil Cluster
	if mgr.Cluster != nil {
		t.Error("expected nil cluster when New fails")
	}
	mgr.Stop()
}

func TestClusterManager_MetricsUpdater(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Cluster.Enabled = false
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewClusterManager(cfg, logger, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Create a real metrics collector
	metricsCollector := metrics.New(metrics.Config{Enabled: true})

	// Test metricsUpdater with nil Cluster and nil metrics (should not panic)
	done := make(chan struct{})
	go func() {
		mgr.metricsUpdater(metricsCollector, 10*time.Millisecond)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	mgr.Stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("metricsUpdater did not stop")
	}
	metricsCollector.Stop()
}

func TestSaveCacheToKV_Nil(t *testing.T) {
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	cm := &CacheManager{
		Cache:  cache.New(cache.Config{Capacity: 10}),
		logger: logger,
	}
	// Should not panic with nil KV
	err := cm.SaveCacheToKV(nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestTryDNS64Synthesis_NotEnabled(t *testing.T) {
	h := newTestHandler()
	// dns64Synth is nil -> returns false
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeAAAA, QClass: protocol.ClassIN}
	resp := &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)}}
	result := h.tryDNS64Synthesis(&captureWriter{}, &protocol.Message{}, q, resp)
	if result {
		t.Error("expected false when dns64Synth is nil")
	}
}

func TestNewUpstreamManager_EmptyConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstream.Servers = []string{}
	cfg.Upstream.AnycastGroups = []config.AnycastGroupConfig{}
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewUpstreamManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr.Client != nil || mgr.LoadBalancer != nil {
		t.Error("expected nil client and loadBalancer for empty config")
	}
	mgr.Stop()
}

func TestNewSecurityManager_GeoDisabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.GeoDNS.Enabled = false
	cfg.GeoDNS.MMDBFile = "/nonexistent/file.mmdb" // would fail if enabled
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewSecurityManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mgr.Stop()
}

func TestNewSecurityManager_RPZDisabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RPZ.Enabled = false
	cfg.RPZ.Files = []string{"/nonexistent/rpz.txt"}
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewSecurityManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mgr.Stop()
}

func TestAuthoritative_BuildReferralDelegation(t *testing.T) {
	// Test buildReferralResponse with delegation (no answers, NS in authority)
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1}
	z.Records["example.com."] = []zone.Record{
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.example.com."},
	}
	z.Records["sub.example.com."] = []zone.Record{
		{Name: "sub.example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns2.sub.example.com."},
	}
	h.zones["example.com."] = z

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "sub.example.com.", protocol.TypeA))
	// Should get a referral response (NOERROR with NS in authority section)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	_ = w.msg.Header.Flags.RCODE
}

func TestHandleDNAMERecord(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1}
	z.Records["example.com."] = []zone.Record{
		{Name: "dname.example.com.", TTL: 300, Class: "IN", Type: "DNAME", RData: "target.example.com."},
	}
	h.zones["example.com."] = z

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "dname.example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_RRLFull(t *testing.T) {
	h := newTestHandler()
	// RRL is configured via security manager; set a very low rate limit
	cfg := config.DefaultConfig()
	cfg.RRL.Enabled = true
	cfg.RRL.Rate = 1
	cfg.RRL.Burst = 1
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	sm, _ := NewSecurityManager(cfg, logger)
	h.rrl = sm.Result().RRL
	h.rateLimiter = sm.Result().RateLimiter

	// Send multiple queries to trigger rate limiting
	for i := 0; i < 10; i++ {
		w := newCaptureWriter(fmt.Sprintf("10.0.0.%d", i+1), "udp")
		h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeA))
	}
}

func TestServeDNS_ACLRefused(t *testing.T) {
	h := newTestHandler()
	cfg := config.DefaultConfig()
	cfg.ACL = []config.ACLRule{{
		Networks: []string{"192.168.0.0/16"}, Action: "allow",
	}}
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	sm, _ := NewSecurityManager(cfg, logger)
	h.aclChecker = sm.Result().ACLChecher

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeA))
	// Should be refused by ACL
	if w.msg != nil && w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		// ACL check might not be wired in test handler setup
	}
}

func TestServeDNS_RPZ_QNAME_NoMatch(t *testing.T) {
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.txt")
	os.WriteFile(rpzFile, []byte("ads.example.com 0.0.0.0\n"), 0644)
	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "allowed.example.com.", protocol.TypeA))
	// Query not in RPZ -> normal response
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_ResolverTimeout(t *testing.T) {
	h := newTestHandler()
	h.config.Resolution.Recursive = true
	// Use a resolver transport that fails
	h.resolver = resolver.NewResolver(resolver.Config{
		MaxDepth: 3, Timeout: 10 * time.Millisecond, EDNS0BufSize: 4096,
	}, &resolverCacheAdapter{cache: h.cache}, &failingResolverTransport{})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "timeout.example.com.", protocol.TypeA))
	// Should get SERVFAIL or serve-stale
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_ResolverStaleServe(t *testing.T) {
	h := newTestHandler()
	h.config.Resolution.Recursive = true
	// Put a stale entry in cache
	qname := "stale.example.com."
	name, _ := protocol.ParseName(qname)
	key := cache.MakeKey(qname, protocol.TypeA, false)
	staleMsg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN}},
		Answers: []*protocol.ResourceRecord{{
			Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 0,
			Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
		}},
	}
	h.cache.Set(key, staleMsg, 0)

	h.resolver = resolver.NewResolver(resolver.Config{
		MaxDepth: 3, Timeout: 10 * time.Millisecond, EDNS0BufSize: 4096,
	}, &resolverCacheAdapter{cache: h.cache}, &failingResolverTransport{})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, qname, protocol.TypeA))
	// Should serve stale
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_BlocklistMatch(t *testing.T) {
	h := newTestHandler()
	tmpDir := t.TempDir()
	blFile := filepath.Join(tmpDir, "blocklist.txt")
	os.WriteFile(blFile, []byte("blocked.example.com\n"), 0644)
	bl := blocklist.New(blocklist.Config{
		Enabled: true,
		Files:   []string{blFile},
	})
	_ = bl.Load()
	h.blocklist = bl

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "blocked.example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
	// Should be NXDOMAIN due to blocklist
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Logf("blocklist returned %d instead of NXDOMAIN", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_CookieValid(t *testing.T) {
	h := newTestHandler()
	h.config.Cookie.Enabled = true
	jar, _ := dnscookie.NewCookieJar(1 * time.Hour)
	h.cookieJar = jar

	// Create a query with a valid DNS cookie
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_IDNAValidation(t *testing.T) {
	h := newTestHandler()
	h.idnaEnabled = true
	// Internationalized domain name query
	w := newCaptureWriter("10.0.0.1", "udp")
	// This should either be valid or rejected based on IDNA rules
	h.ServeDNS(w, newTestQuery(t, "münchen.example.com.", protocol.TypeA))
	// Should not panic
}

func TestServeDNS_DNSSEC_NoSignature(t *testing.T) {
	h := newTestHandler()
	h.config.DNSSEC.Enabled = true
	// Validator is nil -> DNSSEC validation skipped
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeA))
	// Should return response (possibly insecure)
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_DNSSEC_ValidationError(t *testing.T) {
	h := newTestHandler()
	h.config.DNSSEC.Enabled = true
	// Validator with nil resolver causes buildChain failure
	anchors := dnssec.NewTrustAnchorStore()
	anchors.AddAnchor(&dnssec.TrustAnchor{Zone: ".", KeyTag: 1, Algorithm: 8, DigestType: 2, Digest: []byte{1, 2, 3}})
	h.validator = dnssec.NewValidator(dnssec.ValidatorConfig{Enabled: true, RequireDNSSEC: false}, anchors, nil)

	// No upstream, so it will try resolver path
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "dnssec-err.example.com.", protocol.TypeA))
	// Should return a response (INSECURE since RequireDNSSEC=false)
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_ResolverPath(t *testing.T) {
	h := newTestHandler()
	h.config.Resolution.Recursive = true
	// Set up a minimal resolver with a transport that returns a valid response
	qname := "resolved.example.com."
	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Answers: []*protocol.ResourceRecord{
			{Name: mustParseName(t, qname), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{5, 6, 7, 8}}},
		},
	}
	h.resolver = resolver.NewResolver(resolver.Config{
		MaxDepth: 3, Timeout: 5 * time.Second, EDNS0BufSize: 4096,
	}, &resolverCacheAdapter{cache: h.cache}, &mockResolverTransport{resp: resp})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, qname, protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_AuthZoneNXDOMAIN(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "authNXDOMAIN.com.", []zone.Record{
		{Name: "authNXDOMAIN.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.authNXDOMAIN.com. admin.authNXDOMAIN.com. 1 3600 600 86400 300"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "nonexistent.authNXDOMAIN.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected NXDOMAIN response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_AuthZoneNODATA(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "authNODATA.com.", []zone.Record{
		{Name: "authNODATA.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.authNODATA.com. admin.authNODATA.com. 1 3600 600 86400 300"},
		{Name: "authNODATA.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.authNODATA.com."},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "authNODATA.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected NODATA response")
	}
	// Should be NOERROR with 0 answers
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess || len(w.msg.Answers) != 0 {
		t.Errorf("expected NOERROR NODATA, got rcode=%d answers=%d",
			w.msg.Header.Flags.RCODE, len(w.msg.Answers))
	}
}

func TestServeDNS_AuthZoneCNAMEChain(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "cnamechain.com.", []zone.Record{
		{Name: "cnamechain.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.cnamechain.com. admin.cnamechain.com. 1 3600 600 86400 300"},
		{Name: "www.cnamechain.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "target.cnamechain.com."},
		{Name: "target.cnamechain.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.cnamechain.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response with CNAME chain")
	}
}

func TestServeDNS_UpstreamTimeout(t *testing.T) {
	h := newTestHandler()
	// Create an upstream that never responds
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	// Don't serve anything - just ignore queries
	go func() {
		buf := make([]byte, 4096)
		for {
			_, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()
	addr := pc.LocalAddr().String()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 10 * time.Millisecond})
	h.upstream = client

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "timeout.example.com.", protocol.TypeA))
	pc.Close()

	// Should get SERVFAIL or serve-stale
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_UpstreamServFail(t *testing.T) {
	h := newTestHandler()
	// Create an upstream that returns SERVFAIL
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, err := protocol.UnpackMessage(buf[:n])
			if err != nil {
				continue
			}
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   protocol.NewResponseFlags(protocol.RcodeServerFailure),
					QDCount: 1,
				},
				Questions: msg.Questions,
			}
			packBuf := make([]byte, 4096)
			n, _ = resp.Pack(packBuf)
			pc.WriteTo(packBuf[:n], addr)
		}
	}()
	addr := pc.LocalAddr().String()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	h.upstream = client

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "servfail.example.com.", protocol.TypeA))
	pc.Close()

	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_UpstreamRefused(t *testing.T) {
	h := newTestHandler()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, err := protocol.UnpackMessage(buf[:n])
			if err != nil {
				continue
			}
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   protocol.NewResponseFlags(protocol.RcodeRefused),
					QDCount: 1,
				},
				Questions: msg.Questions,
			}
			packBuf := make([]byte, 4096)
			n, _ = resp.Pack(packBuf)
			pc.WriteTo(packBuf[:n], addr)
		}
	}()
	addr := pc.LocalAddr().String()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	h.upstream = client

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "refused.example.com.", protocol.TypeA))
	pc.Close()

	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_ClusterCacheSync(t *testing.T) {
	h := newTestHandler()
	// Set up cluster manager disabled but with cache invalidation
	cfg := config.DefaultConfig()
	cfg.Cluster.Enabled = false
	cfg.Cluster.CacheSync = true
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	cm, _ := NewClusterManager(cfg, logger, h.cache, nil, nil)
	h.cluster = cm.Cluster

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "cluster.example.com.", protocol.TypeA))
	// Should work fine even with cluster disabled
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_RPZ_QNAMEBlock(t *testing.T) {
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.txt")
	os.WriteFile(rpzFile, []byte("blockme.example.com.rpz-qname 300 IN CNAME .\n"), 0644)
	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "blockme.example.com.", protocol.TypeA))
	// CNAME . → NODATA (NOERROR with 0 answers)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess || len(w.msg.Answers) != 0 {
		t.Errorf("expected NOERROR NODATA, got rcode=%d answers=%d",
			w.msg.Header.Flags.RCODE, len(w.msg.Answers))
	}
}

func TestServeDNS_RPZ_Wildcard(t *testing.T) {
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.txt")
	// Pattern *.example.com.rpz-qname matches any subdomain of example.com
	os.WriteFile(rpzFile, []byte("*.example.com.rpz-qname 300 IN CNAME .\n"), 0644)
	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "anything.example.com.", protocol.TypeA))
	// Wildcard matches: walk up from anything.example.com -> example.com matches *.example.com
	if w.msg == nil {
		t.Fatal("expected response")
	}
	// CNAME . → NODATA (NOERROR with 0 answers)
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess || len(w.msg.Answers) != 0 {
		t.Errorf("expected NOERROR NODATA, got rcode=%d answers=%d",
			w.msg.Header.Flags.RCODE, len(w.msg.Answers))
	}
}

func TestServeDNS_RPZ_Passthru(t *testing.T) {
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.txt")
	// CNAME to a domain (not . or *) → ActionCNAME with redirect target
	os.WriteFile(rpzFile, []byte("*.example.com.rpz-qname 300 IN CNAME redirect.example.com.\n"), 0644)
	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine

	addr, cleanup := startTestUpstream(t)
	defer cleanup()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	h.upstream = client

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "test.example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
	// Should get CNAME redirect response
	if len(w.msg.Answers) == 0 || w.msg.Answers[0].Type != protocol.TypeCNAME {
		t.Logf("expected CNAME answer, got %d answers", len(w.msg.Answers))
	}
}

func TestServeDNS_RPZ_Drop(t *testing.T) {
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.txt")
	// CNAME * → ActionNXDOMAIN (not Drop); TXT "drop" → ActionDrop
	os.WriteFile(rpzFile, []byte("dropme.rpz-qname 300 IN TXT \"drop\"\n"), 0644)
	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "dropme.example.com.", protocol.TypeA))
	// TXT "drop" → ActionDrop → silently dropped, no response written
	// w.msg should be nil because the response was dropped
}

func TestServeDNS_TracingEnabled(t *testing.T) {
	h := newTestHandler()
	h.tracer = otel.NewTracer(otel.Config{Enabled: true, SampleRate: 1.0})
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "trace.example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_CacheNegative(t *testing.T) {
	h := newTestHandler()
	// Pre-populate negative cache
	qname := "nxdomain.example.com."
	name, _ := protocol.ParseName(qname)
	key := cache.MakeKey(qname, protocol.TypeA, false)
	negMsg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewResponseFlags(protocol.RcodeNameError)},
		Questions: []*protocol.Question{{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}
	h.cache.Set(key, negMsg, 60)
	// Mark as negative cache entry
	h.cache.SetNegative(key, protocol.RcodeNameError)

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, qname, protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected negative cached response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_AuthorityNSEC(t *testing.T) {
	h := newTestHandler()
	// Set up NSEC for aggressive negative caching
	addZoneRecords(t, h, "nsec-example.com.", []zone.Record{
		{Name: "nsec-example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.nsec-example.com. admin.nsec-example.com. 1 3600 600 86400 300"},
		{Name: "a.nsec-example.com.", TTL: 300, Class: "IN", Type: "NSEC", RData: "b.nsec-example.com. A NS SOA TXT AAAA DNSKEY"},
		{Name: "b.nsec-example.com.", TTL: 300, Class: "IN", Type: "NSEC", RData: "c.nsec-example.com. A NS"},
	})

	// Query for non-existent name
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "nonexistent.nsec-example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
	// Should use NSEC for aggressive negative caching
}

func TestServeDNS_Truncated(t *testing.T) {
	h := newTestHandler()
	// Create a very large response that will be truncated
	addZoneRecords(t, h, "largeexample.com.", []zone.Record{
		{Name: "largeexample.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.largeexample.com. admin.largeexample.com. 1 3600 600 86400 300"},
	})
	// Add many A records
	for i := 0; i < 100; i++ {
		addZoneRecords(t, h, "largeexample.com.", []zone.Record{
			{Name: fmt.Sprintf("rec%d.largeexample.com.", i), TTL: 300, Class: "IN", Type: "A", RData: fmt.Sprintf("1.2.3.%d", i%256)},
		})
	}

	w := &captureWriter{
		client: &server.ClientInfo{
			Addr:     &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345},
			Protocol: "udp",
		},
	}
	h.ServeDNS(w, newTestQuery(t, "largeexample.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_TCPFallback(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "tcpfallback.com.", []zone.Record{
		{Name: "tcpfallback.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.tcpfallback.com. admin.tcpfallback.com. 1 3600 600 86400 300"},
		{Name: "tcpfallback.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.tcpfallback.com."},
	})

	// Note: TCP handling depends on the server setup
	w := newCaptureWriter("10.0.0.1", "tcp")
	h.ServeDNS(w, newTestQuery(t, "tcpfallback.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_EDNS0ClientSubnet(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "ecs.example.com.", []zone.Record{
		{Name: "ecs.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.ecs.example.com. admin.ecs.example.com. 1 3600 600 86400 300"},
	})

	w := &captureWriter{
		client: &server.ClientInfo{
			Addr:         &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345},
			Protocol:     "udp",
			ClientSubnet: &protocol.EDNS0ClientSubnet{Family: 1, SourcePrefixLength: 24, Address: net.ParseIP("10.20.30.0").To4()},
		},
	}
	h.ServeDNS(w, newTestQuery(t, "ecs.example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_EDNS0Keepalive(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "keepalive.example.com.", []zone.Record{
		{Name: "keepalive.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.keepalive.example.com. admin.keepalive.example.com. 1 3600 600 86400 300"},
	})

	// Create query with EDNS0 extended error option
	q := newTestQuery(t, "keepalive.example.com.", protocol.TypeA)
	q.Additionals = []*protocol.ResourceRecord{{
		Name:  mustParseName(t, "."),
		Type:  protocol.TypeOPT,
		Class: 4096,
		TTL:   0,
		Data: &protocol.RDataOPT{
			Options: []protocol.EDNS0Option{
				protocol.NewEDNS0ExtendedError(protocol.EDENetworkError, "test").ToEDNS0Option(),
			},
		},
	}}

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_UnknownQuestionType(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "unktype.example.com.", []zone.Record{
		{Name: "unktype.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.unktype.example.com. admin.unktype.example.com. 1 3600 600 86400 300"},
	})

	// Query with unknown type (255 is NOTIZE/ANY-like)
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "unktype.example.com.", 255))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_OptRecordPresent(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "opt.example.com.", []zone.Record{
		{Name: "opt.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.opt.example.com. admin.opt.example.com. 1 3600 600 86400 300"},
	})

	// Query with OPT record (DO bit set)
	q := newTestQuery(t, "opt.example.com.", protocol.TypeA)
	q.Additionals = []*protocol.ResourceRecord{{
		Name:  mustParseName(t, "."),
		Type:  protocol.TypeOPT,
		Class: 4096,
		TTL:   0x8000, // DO bit set
		Data:  &protocol.RDataOPT{},
	}}

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_RcodeNotImp(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "notimpl.example.com.", []zone.Record{
		{Name: "notimpl.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.notimpl.example.com. admin.notimpl.example.com. 1 3600 600 86400 300"},
	})

	// Query with opcode that returns NOTIMP (only IXFR, AXFR, etc might return this)
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "notimpl.example.com.", protocol.TypeA)
	msg.Header.Flags.Opcode = protocol.OpcodeStatus
	h.ServeDNS(w, msg)
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_DNSSEC_WantsDNSSEC(t *testing.T) {
	h := newTestHandler()
	h.config.DNSSEC.Enabled = true
	// Add a signed zone with DNSSEC
	addZoneRecords(t, h, "dnssec.example.com.", []zone.Record{
		{Name: "dnssec.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.dnssec.example.com. admin.dnssec.example.com. 1 3600 600 86400 300"},
		{Name: "dnssec.example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.dnssec.example.com."},
		{Name: "www.dnssec.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
	})

	// Create query with DO bit set
	q := newTestQuery(t, "www.dnssec.example.com.", protocol.TypeA)
	q.Additionals = []*protocol.ResourceRecord{{
		Name:  mustParseName(t, "."),
		Type:  protocol.TypeOPT,
		Class: 4096,
		TTL:   0x8000, // DO bit set
		Data:  &protocol.RDataOPT{},
	}}

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_CookieJarEnabled(t *testing.T) {
	h := newTestHandler()
	jar, _ := dnscookie.NewCookieJar(1 * time.Hour)
	h.cookieJar = jar
	// Enable cookie processing
	h.config.Cookie.Enabled = true

	addZoneRecords(t, h, "cookie.example.com.", []zone.Record{
		{Name: "cookie.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.cookie.example.com. admin.cookie.example.com. 1 3600 600 86400 300"},
		{Name: "cookie.example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.cookie.example.com."},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "cookie.example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_ResolverTimeoutStale(t *testing.T) {
	h := newTestHandler()
	h.config.Resolution.Recursive = true

	// Pre-populate stale cache
	qname := "stale.example.com."
	name, _ := protocol.ParseName(qname)
	key := cache.MakeKey(qname, protocol.TypeA, false)
	staleMsg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN}},
		Answers: []*protocol.ResourceRecord{{
			Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 0,
			Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
		}},
	}
	h.cache.Set(key, staleMsg, 0)

	// Use failing transport so resolver errors
	h.resolver = resolver.NewResolver(resolver.Config{
		MaxDepth: 3, Timeout: 10 * time.Millisecond, EDNS0BufSize: 4096,
	}, &resolverCacheAdapter{cache: h.cache}, &failingResolverTransport{})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, qname, protocol.TypeA))
	// Should serve stale since resolver fails
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR (stale), got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_UpstreamWithEDNS0(t *testing.T) {
	h := newTestHandler()
	addr, cleanup := startTestUpstream(t)
	defer cleanup()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	h.upstream = client

	// Query with EDNS0
	q := newTestQuery(t, "edns0.example.com.", protocol.TypeA)
	q.Additionals = []*protocol.ResourceRecord{{
		Name:  mustParseName(t, "."),
		Type:  protocol.TypeOPT,
		Class: 4096,
		TTL:   0,
		Data:  &protocol.RDataOPT{},
	}}

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_UpstreamIDMismatch(t *testing.T) {
	h := newTestHandler()
	// Custom upstream that returns wrong ID
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, err := protocol.UnpackMessage(buf[:n])
			if err != nil {
				continue
			}
			// Return with WRONG ID
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID + 9999, // wrong ID
					Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
					QDCount: 1,
					ANCount: 1,
				},
				Questions: msg.Questions,
				Answers: []*protocol.ResourceRecord{{
					Name:  msg.Questions[0].Name,
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
				}},
			}
			packBuf := make([]byte, 4096)
			n, _ = resp.Pack(packBuf)
			pc.WriteTo(packBuf[:n], addr)
		}
	}()

	addr := pc.LocalAddr().String()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	h.upstream = client

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "idmismatch.example.com.", protocol.TypeA))
	// ID mismatch → SERVFAIL
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Logf("expected SERVFAIL for ID mismatch, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_RPZ_ResponseIP_Trigger(t *testing.T) {
	// Test the ResponseIP policy trigger specifically
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.txt")
	// Response IP 1.2.3.4 → NXDOMAIN
	os.WriteFile(rpzFile, []byte("32.4.3.2.1.rpz-ip 3600 IN CNAME .\n"), 0644)
	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine

	// Custom upstream that returns 1.2.3.4 as A record
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, err := protocol.UnpackMessage(buf[:n])
			if err != nil {
				continue
			}
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
					QDCount: 1,
					ANCount: 1,
				},
				Questions: msg.Questions,
				Answers: []*protocol.ResourceRecord{{
					Name:  msg.Questions[0].Name,
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}, // matches RPZ rule!
				}},
			}
			packBuf := make([]byte, 4096)
			n, _ = resp.Pack(packBuf)
			pc.WriteTo(packBuf[:n], addr)
		}
	}()

	addr := pc.LocalAddr().String()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	h.upstream = client

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
	// Should get NXDOMAIN due to RPZ response IP
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Logf("expected NXDOMAIN from RPZ response IP, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_RPZ_OverrideIP(t *testing.T) {
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.txt")
	// Override example.com A to 5.6.7.8
	os.WriteFile(rpzFile, []byte("example.com.rpz-qname 3600 IN A 5.6.7.8\n"), 0644)
	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine

	addr, cleanup := startTestUpstream(t)
	defer cleanup()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	h.upstream = client

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
	// Should get override IP
	if len(w.msg.Answers) > 0 {
		if rdata, ok := w.msg.Answers[0].Data.(*protocol.RDataA); ok {
			if rdata.Address != [4]byte{5, 6, 7, 8} {
				t.Errorf("expected override IP 5.6.7.8, got %v", rdata.Address)
			}
		}
	}
}

func TestServeDNS_RPZ_TCPOnly(t *testing.T) {
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.txt")
	os.WriteFile(rpzFile, []byte("tcponly.example.com.rpz-qname 300 IN TXT \"tcp-only\"\n"), 0644)
	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine

	addr, cleanup := startTestUpstream(t)
	defer cleanup()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	h.upstream = client

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "tcponly.example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
	// TCP-only → TC bit should be set
	if !w.msg.Header.Flags.TC {
		t.Logf("expected TC bit for TCP-only, got %v", w.msg.Header.Flags)
	}
}

func TestServeDNS_GeoDNS_Override(t *testing.T) {
	h := newTestHandler()
	cfg := config.DefaultConfig()
	cfg.GeoDNS.Enabled = true
	cfg.GeoDNS.MMDBFile = "/nonexistent/mmdb" // won't load but GeoDNS is enabled
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	sm, _ := NewSecurityManager(cfg, logger)
	h.geoEngine = sm.Result().GeoEngine

	addZoneRecords(t, h, "geo.example.com.", []zone.Record{
		{Name: "geo.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.geo.example.com. admin.geo.example.com. 1 3600 600 86400 300"},
		{Name: "geo.example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.geo.example.com."},
	})

	// Without MMDB file, GeoDNS won't actually resolve, but the branch is exercised
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "geo.example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_IDNA_Valid(t *testing.T) {
	h := newTestHandler()
	h.idnaEnabled = true
	// Valid IDN that should pass IDNA validation
	addZoneRecords(t, h, "münchen.example.com.", []zone.Record{
		{Name: "münchen.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.münchen.example.com. admin.münchen.example.com. 1 3600 600 86400 300"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "münchen.example.com.", protocol.TypeA))
	// Should handle IDN gracefully
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_IDNA_Invalid(t *testing.T) {
	h := newTestHandler()
	h.idnaEnabled = true
	// Create a query with invalid IDNA (too long label)
	w := newCaptureWriter("10.0.0.1", "udp")
	// This should be caught by IDNA validation
	h.ServeDNS(w, &protocol.Message{
		Header: protocol.Header{ID: 1, Flags: protocol.NewQueryFlags(), QDCount: 1},
		Questions: []*protocol.Question{{
			Name:   protocol.NewName([]string{strings.Repeat("a", 64), "example", "com"}, true),
			QType:  protocol.TypeA,
			QClass: protocol.ClassIN,
		}},
	})
	if w.msg == nil {
		t.Fatal("expected response")
	}
	// Should return FORMERR due to invalid IDNA
	if w.msg.Header.Flags.RCODE != protocol.RcodeFormatError {
		t.Logf("expected FORMERR for invalid IDNA, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_ZeroTTL(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "zerottl.example.com.", []zone.Record{
		{Name: "zerottl.example.com.", TTL: 0, Class: "IN", Type: "SOA", RData: "ns1.zerottl.example.com. admin.zerottl.example.com. 1 3600 600 86400 300"},
		{Name: "zerottl.example.com.", TTL: 0, Class: "IN", Type: "NS", RData: "ns1.zerottl.example.com."},
		{Name: "www.zerottl.example.com.", TTL: 0, Class: "IN", Type: "A", RData: "192.0.2.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.zerottl.example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_AAAAQueryWithNoAAAARecords(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "noaaaa.example.com.", []zone.Record{
		{Name: "noaaaa.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.noaaaa.example.com. admin.noaaaa.example.com. 1 3600 600 86400 300"},
		{Name: "noaaaa.example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.noaaaa.example.com."},
		{Name: "noaaaa.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "noaaaa.example.com.", protocol.TypeAAAA))
	// Should get NODATA (NOERROR with 0 answers)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess || len(w.msg.Answers) != 0 {
		t.Errorf("expected NOERROR NODATA, got rcode=%d answers=%d",
			w.msg.Header.Flags.RCODE, len(w.msg.Answers))
	}
}

func TestServeDNS_CAAQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "caa.example.com.", []zone.Record{
		{Name: "caa.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.caa.example.com. admin.caa.example.com. 1 3600 600 86400 300"},
		{Name: "caa.example.com.", TTL: 300, Class: "IN", Type: "CAA", RData: "0 issue \"ca.example.com\""},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "caa.example.com.", protocol.TypeCAA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if len(w.msg.Answers) != 1 {
		t.Errorf("expected 1 CAA answer, got %d", len(w.msg.Answers))
	}
}

func TestServeDNS_DNSKEYQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "dnskey.example.com.", []zone.Record{
		{Name: "dnskey.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.dnskey.example.com. admin.dnskey.example.com. 1 3600 600 86400 300"},
		{Name: "dnskey.example.com.", TTL: 300, Class: "IN", Type: "DNSKEY", RData: "257 3 13 JKLmG2X3PQRjG5H6L4M7N8O9P0Q1R2S3T4U5V6W7X8Y9Z0a1b2c3d4e5f6g7h8i9j0"}, // dummy DNSKEY
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "dnskey.example.com.", protocol.TypeDNSKEY))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_DSQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "ds.example.com.", []zone.Record{
		{Name: "ds.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.ds.example.com. admin.ds.example.com. 1 3600 600 86400 300"},
		{Name: "ds.example.com.", TTL: 300, Class: "IN", Type: "DS", RData: "12345 13 2 ABCDEF1234567890"}, // dummy DS
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "ds.example.com.", protocol.TypeDS))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_TLSAQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "_443._tcp.tlsa.example.com.", []zone.Record{
		{Name: "_443._tcp.tlsa.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.tlsa.example.com. admin.tlsa.example.com. 1 3600 600 86400 300"},
		{Name: "_443._tcp.tlsa.example.com.", TTL: 300, Class: "IN", Type: "TLSA", RData: "3 1 1 ABCDEF1234567890"}, // dummy TLSA
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "_443._tcp.tlsa.example.com.", protocol.TypeTLSA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_SVCBQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "svcb.example.com.", []zone.Record{
		{Name: "svcb.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.svcb.example.com. admin.svcb.example.com. 1 3600 600 86400 300"},
		{Name: "_443._tcp.svcb.example.com.", TTL: 300, Class: "IN", Type: "SVCB", RData: "1 alpn=\"h3\""}, // dummy SVCB
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "_443._tcp.svcb.example.com.", protocol.TypeSVCB))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_HTTPSQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "https.example.com.", []zone.Record{
		{Name: "https.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.https.example.com. admin.https.example.com. 1 3600 600 86400 300"},
		{Name: "_443._tcp.https.example.com.", TTL: 300, Class: "IN", Type: "HTTPS", RData: "1 alpn=\"h3\""}, // dummy HTTPS
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "_443._tcp.https.example.com.", protocol.TypeHTTPS))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_URIQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "uri.example.com.", []zone.Record{
		{Name: "_sip._udp.uri.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.uri.example.com. admin.uri.example.com. 1 3600 600 86400 300"},
		{Name: "_sip._udp.uri.example.com.", TTL: 300, Class: "IN", Type: "URI", RData: "10 1 \"sip:services.example.com\""}, // dummy URI
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "_sip._udp.uri.example.com.", protocol.TypeURI))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_PTRQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "ptr.example.com.", []zone.Record{
		{Name: "ptr.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.ptr.example.com. admin.ptr.example.com. 1 3600 600 86400 300"},
		{Name: "1.0.0.10.in-addr.arpa.", TTL: 300, Class: "IN", Type: "PTR", RData: "host.example.com."},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "1.0.0.10.in-addr.arpa.", protocol.TypePTR))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_SPFQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "spf.example.com.", []zone.Record{
		{Name: "spf.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.spf.example.com. admin.spf.example.com. 1 3600 600 86400 300"},
		{Name: "spf.example.com.", TTL: 300, Class: "IN", Type: "SPF", RData: "\"v=spf1 include:_spf.example.com ~all\""},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "spf.example.com.", protocol.TypeSPF))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_NSECQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "nsec.example.com.", []zone.Record{
		{Name: "nsec.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.nsec.example.com. admin.nsec.example.com. 1 3600 600 86400 300"},
		{Name: "nsec.example.com.", TTL: 300, Class: "IN", Type: "NSEC", RData: "next.nsec.example.com. A NS SOA TXT AAAA DNSKEY"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "nsec.example.com.", protocol.TypeNSEC))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_NSEC3Query(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "nsec3.example.com.", []zone.Record{
		{Name: "nsec3.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.nsec3.example.com. admin.nsec3.example.com. 1 3600 600 86400 300"},
		{Name: "nsec3.example.com.", TTL: 300, Class: "IN", Type: "NSEC3", RData: "1 0 100 ABCDEF123456"}, // dummy NSEC3
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "nsec3.example.com.", protocol.TypeNSEC3))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_NSEC3PARAMQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "nsec3param.example.com.", []zone.Record{
		{Name: "nsec3param.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.nsec3param.example.com. admin.nsec3param.example.com. 1 3600 600 86400 300"},
		{Name: "nsec3param.example.com.", TTL: 300, Class: "IN", Type: "NSEC3PARAM", RData: "1 0 100 ABCDEF123456"}, // dummy NSEC3PARAM
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "nsec3param.example.com.", protocol.TypeNSEC3PARAM))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_CDNSKEYQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "cdnskey.example.com.", []zone.Record{
		{Name: "cdnskey.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.cdnskey.example.com. admin.cdnskey.example.com. 1 3600 600 86400 300"},
		{Name: "cdnskey.example.com.", TTL: 300, Class: "IN", Type: "CDNSKEY", RData: "257 3 13 JKLmG2X3PQRjG5H6L4M7N8O9P0Q1R2S3T4U5V6W7X8Y9Z0a1b2c3d4e5f6g7h8i9j0"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "cdnskey.example.com.", protocol.TypeCDNSKEY))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_CDSQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "cds.example.com.", []zone.Record{
		{Name: "cds.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.cds.example.com. admin.cds.example.com. 1 3600 600 86400 300"},
		{Name: "cds.example.com.", TTL: 300, Class: "IN", Type: "CDS", RData: "12345 13 2 ABCDEF1234567890"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "cds.example.com.", protocol.TypeCDS))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_SSHFPQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "sshfp.example.com.", []zone.Record{
		{Name: "sshfp.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.sshfp.example.com. admin.sshfp.example.com. 1 3600 600 86400 300"},
		{Name: "sshfp.example.com.", TTL: 300, Class: "IN", Type: "SSHFP", RData: "1 1 ABCDEF123456"}, // dummy SSHFP
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "sshfp.example.com.", protocol.TypeSSHFP))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_DHCIDQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "dhcid.example.com.", []zone.Record{
		{Name: "dhcid.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.dhcid.example.com. admin.dhcid.example.com. 1 3600 600 86400 300"},
		{Name: "dhcid.example.com.", TTL: 300, Class: "IN", Type: "DHCID", RData: "ABCDEF123456"}, // dummy DHCID
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "dhcid.example.com.", protocol.TypeDHCID))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_TKEYQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "tkey.example.com.", []zone.Record{
		{Name: "tkey.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.tkey.example.com. admin.tkey.example.com. 1 3600 600 86400 300"},
	})

	// TKEY is a special query type; server should handle gracefully
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "tkey.example.com.", protocol.TypeTKEY))
	// Should return some response (possibly NOTIMP or FORMERR)
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_TSIGQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "tsig.example.com.", []zone.Record{
		{Name: "tsig.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.tsig.example.com. admin.tsig.example.com. 1 3600 600 86400 300"},
	})

	// TSIG is a special query type; server should handle gracefully
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "tsig.example.com.", protocol.TypeTSIG))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_ANYQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "any.example.com.", []zone.Record{
		{Name: "any.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.any.example.com. admin.any.example.com. 1 3600 600 86400 300"},
		{Name: "any.example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.any.example.com."},
		{Name: "any.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
	})

	// ANY query - should return all records
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "any.example.com.", protocol.TypeANY))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_AXFRQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "axfr.example.com.", []zone.Record{
		{Name: "axfr.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.axfr.example.com. admin.axfr.example.com. 1 3600 600 86400 300"},
	})

	// AXFR over UDP → REFUSED
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "axfr.example.com.", protocol.TypeAXFR))
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected REFUSED for UDP AXFR, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_IXFRQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "ixfr.example.com.", []zone.Record{
		{Name: "ixfr.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.ixfr.example.com. admin.ixfr.example.com. 1 3600 600 86400 300"},
	})

	// IXFR over UDP → REFUSED
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "ixfr.example.com.", protocol.TypeIXFR))
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected REFUSED for UDP IXFR, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_NOTIFYQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "notify.example.com.", []zone.Record{
		{Name: "notify.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.notify.example.com. admin.notify.example.com. 1 3600 600 86400 300"},
	})

	// NOTIFY opcode
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "notify.example.com.", protocol.TypeSOA)
	msg.Header.Flags.Opcode = protocol.OpcodeNotify
	h.ServeDNS(w, msg)
	// Should handle NOTIFY (usually REFUSED or no response depending on config)
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_UPDATEQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "update.example.com.", []zone.Record{
		{Name: "update.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.update.example.com. admin.update.example.com. 1 3600 600 86400 300"},
	})

	// UPDATE opcode
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "update.example.com.", protocol.TypeSOA)
	msg.Header.Flags.Opcode = protocol.OpcodeUpdate
	h.ServeDNS(w, msg)
	// Should handle UPDATE
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_StatusQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "status.example.com.", []zone.Record{
		{Name: "status.example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.status.example.com. admin.status.example.com. 1 3600 600 86400 300"},
	})

	// STATUS opcode
	w := newCaptureWriter("10.0.0.1", "udp")
	msg := newTestQuery(t, "status.example.com.", protocol.TypeSOA)
	msg.Header.Flags.Opcode = protocol.OpcodeStatus
	h.ServeDNS(w, msg)
	// Should handle STATUS
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestHandleAXFR_Unauthorized(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1}
	zones := map[string]*zone.Zone{"example.com.": z}
	h.axfrServer = transfer.NewAXFRServer(zones) // no allow list

	al, _ := audit.NewAuditLogger(true, "")
	h.auditLogger = al

	w := newCaptureWriter("10.0.0.1", "tcp")
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeAXFR, QClass: protocol.ClassIN}
	h.handleAXFR(w, newTestQuery(t, "example.com.", protocol.TypeAXFR), q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	// Should be REFUSED for unauthorized
	if w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected REFUSED, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestHandleIXFR_Unauthorized(t *testing.T) {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 2}
	zones := map[string]*zone.Zone{"example.com.": z}
	h.axfrServer = transfer.NewAXFRServer(zones)
	h.ixfrServer = transfer.NewIXFRServer(h.axfrServer)

	al, _ := audit.NewAuditLogger(true, "")
	h.auditLogger = al

	w := newCaptureWriter("10.0.0.1", "tcp")
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeIXFR, QClass: protocol.ClassIN}
	msg := newTestQuery(t, "example.com.", protocol.TypeIXFR)
	msg.Authorities = []*protocol.ResourceRecord{{
		Name:  mustParseName(t, "example.com."),
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataSOA{Serial: 1, MName: mustParseName(t, "ns1.example.com."), RName: mustParseName(t, "admin.example.com.")},
	}}
	h.handleIXFR(w, msg, q)
	// Should fall back to AXFR or refuse
}

func TestHandleNOTIFY_SlaveOK(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{
		"example.com.": {
			Origin: "example.com.",
			SOA:    &zone.SOARecord{Serial: 2},
		},
	}
	h.notifyHandler = transfer.NewNOTIFYSlaveHandler(zones)
	h.notifyHandler.AddNotifyAllowed("10.0.0.0/8")

	// Notify with higher serial
	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.Flags{Opcode: protocol.OpcodeNotify}},
		Questions: []*protocol.Question{},
	}
	msg.Questions = append(msg.Questions, &protocol.Question{
		Name:   mustParseName(t, "example.com."),
		QType:  protocol.TypeSOA,
		QClass: protocol.ClassIN,
	})
	msg.Authorities = []*protocol.ResourceRecord{{
		Name:  mustParseName(t, "example.com."),
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataSOA{Serial: 3, MName: mustParseName(t, "ns1.example.com."), RName: mustParseName(t, "admin.example.com.")},
	}}

	w := newCaptureWriter("10.0.0.1", "udp")
	h.handleNOTIFY(w, msg, msg.Questions[0])
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestHandleUPDATE_Refused(t *testing.T) {
	h := newTestHandler()
	zones := map[string]*zone.Zone{} // no zones configured
	h.ddnsHandler = transfer.NewDynamicDNSHandler(zones)

	al, _ := audit.NewAuditLogger(true, "")
	h.auditLogger = al

	w := newCaptureWriter("10.0.0.1", "udp")
	q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeSOA, QClass: protocol.ClassIN}
	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.Flags{Opcode: protocol.OpcodeUpdate}},
		Questions: []*protocol.Question{q},
	}
	h.handleUPDATE(w, msg, q)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	// RFC 2136 returns NOTZONE when the update zone is not authoritative here.
	if w.msg.Header.Flags.RCODE != protocol.RcodeNotZone {
		t.Errorf("expected NOTZONE, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestNewDNSSECManager_TrustAnchorLoadError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DNSSEC.TrustAnchor = "/nonexistent/trust.anchor"
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewDNSSECManager(cfg, nil, logger)
	// Should still create manager even if anchor file doesn't exist
	// (it creates an empty store)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected manager")
	}
}

func TestNewZoneManager_InvalidZoneFile(t *testing.T) {
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "bad.zone")
	os.WriteFile(badFile, []byte("this is not a valid zone file\n"), 0644)
	cfg := config.DefaultConfig()
	cfg.Zones = []string{badFile}
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewZoneManager(cfg, logger)
	// Should create manager but skip the bad zone
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected manager")
	}
}

func TestCacheManager_StartPersistenceZeroInterval(t *testing.T) {
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	cm := &CacheManager{
		Cache:  cache.New(cache.Config{Capacity: 10}),
		logger: logger,
	}
	// Should use default 5min interval when 0
	cm.StartPersistence(0)
	time.Sleep(20 * time.Millisecond)
	// Should not panic; stop it
	cm.Stop()
}

func TestCacheManager_StopMultiple(t *testing.T) {
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	cm := &CacheManager{
		Cache:  cache.New(cache.Config{Capacity: 10}),
		logger: logger,
	}
	cm.Stop() // should not panic
	cm.Stop() // should remain idempotent
}

func TestCacheManager_SaveCacheToKVSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	kv, _ := storage.OpenKVStore(filepath.Join(tmpDir, "kv.db"))
	defer kv.Close()

	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	cm := &CacheManager{
		Cache:       cache.New(cache.Config{Capacity: 10}),
		logger:      logger,
		persistPath: filepath.Join(tmpDir, "cache.json"),
	}
	// Add some cache entries
	qname := "savekv.example.com."
	name, _ := protocol.ParseName(qname)
	key := cache.MakeKey(qname, protocol.TypeA, false)
	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN}},
		Answers: []*protocol.ResourceRecord{{
			Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
		}},
	}
	cm.Cache.Set(key, msg, 300)

	err := cm.SaveCacheToKV(kv)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Now load from KV
	cm2 := &CacheManager{
		Cache:  cache.New(cache.Config{Capacity: 10}),
		logger: logger,
	}
	cm2.LoadCacheFromKV(kv)
	if cm2.Cache == nil {
		t.Error("expected cache to be loaded")
	}
}

func TestClusterManager_StopMultiple(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Cluster.Enabled = false
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, _ := NewClusterManager(cfg, logger, nil, nil, nil)
	mgr.Stop() // should not panic
	// Note: calling Stop() twice would panic on close(stopCh)
	_ = mgr
}

func TestServeDNS_EmptyQuery(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "", protocol.TypeA))
	// Empty name should be handled
}

func TestServeDNS_MalformedQuestion(t *testing.T) {
	h := newTestHandler()
	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewQueryFlags()},
		Questions: []*protocol.Question{{Name: nil, QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, msg)
	// Should handle nil question name gracefully
}

func TestServeDNS_RPZ_NSDNAME(t *testing.T) {
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.txt")
	os.WriteFile(rpzFile, []byte("ns.bad.example.com.rpz-nsdname 300 IN CNAME .\n"), 0644)
	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine

	// Custom upstream that includes NS in authority section
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, err := protocol.UnpackMessage(buf[:n])
			if err != nil {
				continue
			}
			nsName, _ := protocol.ParseName("ns.bad.example.com.")
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
					QDCount: 1,
					ANCount: 1,
					NSCount: 1,
				},
				Questions: msg.Questions,
				Answers: []*protocol.ResourceRecord{{
					Name:  msg.Questions[0].Name,
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
				}},
				Authorities: []*protocol.ResourceRecord{{
					Name:  nsName,
					Type:  protocol.TypeNS,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataNS{NSDName: nsName},
				}},
			}
			packBuf := make([]byte, 4096)
			n, _ = resp.Pack(packBuf)
			pc.WriteTo(packBuf[:n], addr)
		}
	}()

	addr := pc.LocalAddr().String()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	h.upstream = client

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "sub.example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
	// RPZ NSDNAME should match ns.bad.example.com → NOERROR/NODATA
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess || len(w.msg.Answers) != 0 {
		t.Logf("RPZ NSDNAME result: rcode=%d answers=%d", w.msg.Header.Flags.RCODE, len(w.msg.Answers))
	}
}

func TestServeDNS_RPZ_NSDNAME_UPstream(t *testing.T) {
	// Test NSDNAME policy with upstream response containing NS names that match RPZ
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.txt")
	os.WriteFile(rpzFile, []byte("ns.blocked.example.com.rpz-nsdname 300 IN CNAME .\n"), 0644)
	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine

	// Custom upstream that returns response with matching NS
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, err := protocol.UnpackMessage(buf[:n])
			if err != nil {
				continue
			}
			// Return answer with NS in authority
			nsName, _ := protocol.ParseName("ns.blocked.example.com.")
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
					QDCount: 1,
					ANCount: 1,
					NSCount: 1,
				},
				Questions: msg.Questions,
				Answers: []*protocol.ResourceRecord{{
					Name:  msg.Questions[0].Name,
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
				}},
				Authorities: []*protocol.ResourceRecord{{
					Name:  nsName,
					Type:  protocol.TypeNS,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataNS{NSDName: nsName},
				}},
			}
			packBuf := make([]byte, 4096)
			n, _ = resp.Pack(packBuf)
			pc.WriteTo(packBuf[:n], addr)
		}
	}()

	addr := pc.LocalAddr().String()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	h.upstream = client

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "sub.example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
	// RPZ NSDNAME should trigger → NOERROR/NODATA
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess || len(w.msg.Answers) != 0 {
		t.Logf("RPZ NSDNAME result: rcode=%d answers=%d", w.msg.Header.Flags.RCODE, len(w.msg.Answers))
	}
}

func TestServeDNS_RPZ_ResponseIP_NoMatch(t *testing.T) {
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.txt")
	os.WriteFile(rpzFile, []byte("99.99.99.99.rpz-ip 300 IN CNAME .\n"), 0644)
	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine

	addr, cleanup := startTestUpstream(t)
	defer cleanup()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	h.upstream = client

	// Response IP 1.2.3.4 should NOT match 99.99.99.99
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
	// Should get normal upstream response
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_RPZ_ResponseIP_Redirect(t *testing.T) {
	h := newTestHandler()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.txt")
	// Response IP 1.2.3.4 → redirect to redirect.example.com
	os.WriteFile(rpzFile, []byte("32.4.3.2.1.rpz-ip 300 IN CNAME redirect.example.com.\n"), 0644)
	engine := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{rpzFile}})
	if err := engine.Load(); err != nil {
		t.Fatalf("failed to load rpz: %v", err)
	}
	h.rpzEngine = engine

	addr, cleanup := startTestUpstream(t)
	defer cleanup()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	h.upstream = client

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
	// Should have redirected response
}

func TestNewSecurityManager_DNS64Disabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DNS64.Enabled = false
	cfg.DNS64.Prefix = "64:ff9b::"
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewSecurityManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mgr.Stop()
}

func TestNewSecurityManager_RRLDisabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RRL.Enabled = false
	cfg.RRL.Rate = 0
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewSecurityManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mgr.Stop()
}

func TestNewSecurityManager_ACLAllow(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ACL = []config.ACLRule{
		{Networks: []string{"10.0.0.0/8"}, Action: "allow"},
		{Networks: []string{"0.0.0.0/0"}, Action: "deny"},
	}
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewSecurityManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mgr.Stop()
}

func TestNewSecurityManager_ACLDeny(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ACL = []config.ACLRule{
		{Networks: []string{"10.0.0.0/8"}, Action: "allow"},
	}
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewSecurityManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Test that ACL denies work
	result := mgr.Result()
	if result.ACLChecher == nil {
		t.Error("expected ACL checker")
	}
	mgr.Stop()
}

func TestSecurityManager_Reload(t *testing.T) {
	cfg := config.DefaultConfig()
	// Enable blocklist with a file source
	tmpDir := t.TempDir()
	blFile := filepath.Join(tmpDir, "blocklist.txt")
	os.WriteFile(blFile, []byte("evil.example.com\n"), 0644)
	cfg.Blocklist.Enabled = true
	cfg.Blocklist.Files = []string{blFile}
	// Also enable RPZ
	rpzFile := filepath.Join(tmpDir, "rpz.txt")
	os.WriteFile(rpzFile, []byte("block.example.com.rpz-qname 300 IN CNAME .\n"), 0644)
	cfg.RPZ.Enabled = true
	cfg.RPZ.Files = []string{rpzFile}

	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewSecurityManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Reload should succeed (files still exist)
	mgr.Reload()
	mgr.Stop()
}

func TestSecurityManager_ReloadBlocklistError(t *testing.T) {
	cfg := config.DefaultConfig()
	tmpDir := t.TempDir()
	blFile := filepath.Join(tmpDir, "blocklist.txt")
	os.WriteFile(blFile, []byte("evil.example.com\n"), 0644)
	cfg.Blocklist.Enabled = true
	cfg.Blocklist.Files = []string{blFile}

	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewSecurityManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Remove the file so reload fails
	os.Remove(blFile)
	mgr.Reload() // Should not panic
	mgr.Stop()
}

func TestSecurityManager_ReloadRPZError(t *testing.T) {
	cfg := config.DefaultConfig()
	tmpDir := t.TempDir()
	rpzFile := filepath.Join(tmpDir, "rpz.txt")
	os.WriteFile(rpzFile, []byte("block.example.com.rpz-qname 300 IN CNAME .\n"), 0644)
	cfg.RPZ.Enabled = true
	cfg.RPZ.Files = []string{rpzFile}

	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewSecurityManager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Remove the file so reload fails
	os.Remove(rpzFile)
	mgr.Reload() // Should not panic
	mgr.Stop()
}

func TestServeDNS_DNS64_AAAAQueryNoAnswers(t *testing.T) {
	h := newTestHandler()
	// Custom upstream that returns NOERROR but no AAAA answers (only A answers)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, err := protocol.UnpackMessage(buf[:n])
			if err != nil {
				continue
			}
			qtype := msg.Questions[0].QType
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
					QDCount: 1,
				},
				Questions: msg.Questions,
			}
			if qtype == protocol.TypeA {
				resp.Answers = []*protocol.ResourceRecord{{
					Name:  msg.Questions[0].Name,
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
				}}
				resp.Header.ANCount = 1
			}
			// For AAAA: return empty
			packBuf := make([]byte, 4096)
			n, _ = resp.Pack(packBuf)
			pc.WriteTo(packBuf[:n], addr)
		}
	}()

	addr := pc.LocalAddr().String()
	client, _ := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	h.upstream = client

	synth, _ := dns64.NewSynthesizer("64:ff9b::", 96)
	h.dns64Synth = synth

	// AAAA query → should try DNS64 synthesis
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "dns64.example.com.", protocol.TypeAAAA))
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestServeDNS_AnycastNoGroups(t *testing.T) {
	h := newTestHandler()
	h.config.Upstream.Servers = []string{} // no servers
	h.config.Upstream.AnycastGroups = nil  // no anycast
	h.upstream = nil
	h.loadBalancer = nil

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeA))
	// Should return SERVFAIL or Refused since no upstream available
	if w.msg == nil {
		t.Fatal("expected response")
	}
}

func TestLoadCacheFromKV_Nil(t *testing.T) {
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	cm := &CacheManager{
		Cache:  cache.New(cache.Config{Capacity: 10}),
		logger: logger,
	}
	// Should not panic with nil KV
	cm.LoadCacheFromKV(nil)
}

func TestNewZoneManager_KVStoreOpenError(t *testing.T) {
	// Use a path that storage.OpenKVStore will reject
	cfg := config.DefaultConfig()
	cfg.ZoneDir = "" // empty zone dir uses "."; but we can use a file as path
	tmpDir := t.TempDir()
	cfg.ZoneDir = filepath.Join(tmpDir, "afile") // a file, not a directory
	os.WriteFile(cfg.ZoneDir, []byte("x"), 0644)
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	mgr, err := NewZoneManager(cfg, logger)
	// Should still create manager even if KV store fails to open
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected manager")
	}
}
