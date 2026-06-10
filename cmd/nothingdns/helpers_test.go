package main

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestIsSubdomainRequiresLabelBoundary(t *testing.T) {
	cases := []struct {
		name          string
		child, parent string
		want          bool
	}{
		{name: "exact", child: "example.com.", parent: "example.com.", want: true},
		{name: "child label", child: "www.example.com.", parent: "example.com.", want: true},
		{name: "root owns all", child: "anything.example.", parent: ".", want: true},
		{name: "case and missing dot", child: "WWW.EXAMPLE.COM", parent: "example.com", want: true},
		{name: "suffix without label boundary", child: "badexample.com.", parent: "example.com.", want: false},
		{name: "long suffix without label boundary", child: "evilbadexample.com.", parent: "example.com.", want: false},
		{name: "different parent", child: "example.net.", parent: "example.com.", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSubdomain(tc.child, tc.parent); got != tc.want {
				t.Fatalf("isSubdomain(%q, %q) = %v, want %v", tc.child, tc.parent, got, tc.want)
			}
		})
	}
}

func TestExtractTTLNilAndNilAnswers(t *testing.T) {
	if got := extractTTL(nil); got != 300 {
		t.Fatalf("extractTTL(nil) = %d, want 300", got)
	}

	resp := &protocol.Message{
		Answers: []*protocol.ResourceRecord{
			nil,
			{TTL: 0},
			{TTL: 120},
		},
	}
	if got := extractTTL(resp); got != 120 {
		t.Fatalf("extractTTL with nil/zero answers = %d, want first positive TTL 120", got)
	}
}

func TestHasDOBitNilSafe(t *testing.T) {
	if hasDOBit(nil) {
		t.Fatal("hasDOBit(nil) = true, want false")
	}

	msg := &protocol.Message{
		Additionals: []*protocol.ResourceRecord{
			nil,
			{Type: protocol.TypeA, TTL: 0x8000},
			{Type: protocol.TypeOPT, TTL: 0x8000},
		},
	}
	if !hasDOBit(msg) {
		t.Fatal("hasDOBit with nil non-OPT before OPT = false, want true")
	}
}

func TestParseRDataDNAME(t *testing.T) {
	rd := parseRData("DNAME", "target.example.com.")
	dname, ok := rd.(*protocol.RDataDNAME)
	if !ok {
		t.Fatalf("parseRData(DNAME) = %T, want *protocol.RDataDNAME", rd)
	}
	if dname.DName == nil || dname.DName.String() != "target.example.com." {
		t.Fatalf("DNAME target = %v, want target.example.com.", dname.DName)
	}

	if rd := parseRData("DNAME", string(make([]byte, 300))); rd != nil {
		t.Fatalf("parseRData(invalid DNAME) = %T, want nil", rd)
	}
}

func TestParseRDataNAPTR(t *testing.T) {
	rd := parseRData("NAPTR", `100 10 "U" "E2U+sip" "!^.*$!sip:info@example.com!" .`)
	naptr, ok := rd.(*protocol.RDataNAPTR)
	if !ok {
		t.Fatalf("parseRData(NAPTR) = %T, want *protocol.RDataNAPTR", rd)
	}
	if naptr.Order != 100 || naptr.Preference != 10 {
		t.Fatalf("NAPTR order/preference = %d %d, want 100 10", naptr.Order, naptr.Preference)
	}
	if naptr.Flags != "U" || naptr.Service != "E2U+sip" || naptr.Regexp != "!^.*$!sip:info@example.com!" {
		t.Fatalf("NAPTR strings = %q %q %q", naptr.Flags, naptr.Service, naptr.Regexp)
	}
	if naptr.Replacement == nil || naptr.Replacement.String() != "." {
		t.Fatalf("NAPTR replacement = %v, want root", naptr.Replacement)
	}
	if got, want := naptr.String(), `100 10 "U" "E2U+sip" "!^.*$!sip:info@example.com!" .`; got != want {
		t.Fatalf("NAPTR String() = %q, want %q", got, want)
	}
	if !rdataPacks(naptr) {
		t.Fatal("parsed NAPTR does not pack")
	}

	rd = parseRData("NAPTR", `10 20 "S" "SIP+D2U" "" _sip._udp.example.com.`)
	naptr, ok = rd.(*protocol.RDataNAPTR)
	if !ok {
		t.Fatalf("parseRData(NAPTR empty regexp) = %T, want *protocol.RDataNAPTR", rd)
	}
	if naptr.Regexp != "" || naptr.Replacement == nil || naptr.Replacement.String() != "_sip._udp.example.com." {
		t.Fatalf("NAPTR empty regexp/replacement = %q %v", naptr.Regexp, naptr.Replacement)
	}

	invalid := []string{
		`100 10 "U" "E2U+sip"`,
		`65536 10 "U" "E2U+sip" "" .`,
		`100 65536 "U" "E2U+sip" "" .`,
		`100 10 "U" "E2U+sip" "" ` + strings.Repeat("a", 64) + `.example.com.`,
		`100 10 "` + strings.Repeat("u", 256) + `" "E2U+sip" "" .`,
		`100 10 "U" "E2U+sip" "unterminated .`,
		`100 10 "U" "E2U+sip" "" . extra`,
	}
	for _, rdata := range invalid {
		if rd := parseRData("NAPTR", rdata); rd != nil {
			t.Fatalf("parseRData(NAPTR, %q) = %T, want nil", rdata, rd)
		}
	}
}

func TestParseRDataSPF(t *testing.T) {
	rd := parseRData("SPF", `"v=spf1 include:_spf.example.com ~all"`)
	spf, ok := rd.(*protocol.RDataTXT)
	if !ok {
		t.Fatalf("parseRData(SPF) = %T, want *protocol.RDataTXT", rd)
	}
	if len(spf.Strings) != 1 || spf.Strings[0] != "v=spf1 include:_spf.example.com ~all" {
		t.Fatalf("SPF strings = %v, want unquoted SPF policy", spf.Strings)
	}
	if !rdataPacks(spf) {
		t.Fatal("parsed SPF does not pack")
	}

	longPolicy := strings.Repeat("x", 300)
	rd = parseRData("SPF", longPolicy)
	spf, ok = rd.(*protocol.RDataTXT)
	if !ok {
		t.Fatalf("parseRData(long SPF) = %T, want *protocol.RDataTXT", rd)
	}
	if got, want := len(spf.Strings), 2; got != want {
		t.Fatalf("long SPF chunk count = %d, want %d", got, want)
	}
	if got, want := len(spf.Strings[0]), 255; got != want {
		t.Fatalf("long SPF first chunk length = %d, want %d", got, want)
	}
	if got, want := len(spf.Strings[1]), 45; got != want {
		t.Fatalf("long SPF second chunk length = %d, want %d", got, want)
	}
	if !rdataPacks(spf) {
		t.Fatal("parsed long SPF does not pack")
	}

	// Unbalanced quotes are not presentation form — stored rdata may
	// legitimately contain a literal quote. Served verbatim, not dropped.
	rd = parseRData("SPF", `"unterminated`)
	spf, ok = rd.(*protocol.RDataTXT)
	if !ok {
		t.Fatalf("parseRData(unbalanced-quote SPF) = %T, want *protocol.RDataTXT", rd)
	}
	if len(spf.Strings) != 1 || spf.Strings[0] != `"unterminated` {
		t.Fatalf("unbalanced-quote SPF strings = %v, want verbatim single string", spf.Strings)
	}
}

func TestParseRDataSSHFP(t *testing.T) {
	rd := parseRData("SSHFP", "1 1 ABCDEF 123456")
	sshfp, ok := rd.(*protocol.RDataSSHFP)
	if !ok {
		t.Fatalf("parseRData(SSHFP) = %T, want *protocol.RDataSSHFP", rd)
	}
	if sshfp.Algorithm != 1 || sshfp.FPType != 1 {
		t.Fatalf("SSHFP header = %d %d, want 1 1", sshfp.Algorithm, sshfp.FPType)
	}
	if got, want := sshfp.String(), "1 1 abcdef123456"; got != want {
		t.Fatalf("SSHFP String() = %q, want %q", got, want)
	}

	invalid := []string{
		"1",
		"256 1 abcdef",
		"1 256 abcdef",
		"1 1 not-hex",
	}
	for _, rdata := range invalid {
		if rd := parseRData("SSHFP", rdata); rd != nil {
			t.Fatalf("parseRData(SSHFP, %q) = %T, want nil", rdata, rd)
		}
	}
}

func TestParseRDataTLSA(t *testing.T) {
	rd := parseRData("TLSA", "3 1 1 ABCDEF 1234567890")
	tlsa, ok := rd.(*protocol.RDataTLSA)
	if !ok {
		t.Fatalf("parseRData(TLSA) = %T, want *protocol.RDataTLSA", rd)
	}
	if tlsa.Usage != 3 || tlsa.Selector != 1 || tlsa.MatchingType != 1 {
		t.Fatalf("TLSA header = %d %d %d, want 3 1 1", tlsa.Usage, tlsa.Selector, tlsa.MatchingType)
	}
	if got, want := tlsa.String(), "3 1 1 abcdef1234567890"; got != want {
		t.Fatalf("TLSA String() = %q, want %q", got, want)
	}

	invalid := []string{
		"3 1",
		"256 1 1 abcdef",
		"3 256 1 abcdef",
		"3 1 256 abcdef",
		"3 1 1 not-hex",
	}
	for _, rdata := range invalid {
		if rd := parseRData("TLSA", rdata); rd != nil {
			t.Fatalf("parseRData(TLSA, %q) = %T, want nil", rdata, rd)
		}
	}
}

func TestParseRDataDS(t *testing.T) {
	rd := parseRData("DS", "60485 13 2 ABCDEF 1234567890")
	ds, ok := rd.(*protocol.RDataDS)
	if !ok {
		t.Fatalf("parseRData(DS) = %T, want *protocol.RDataDS", rd)
	}
	if ds.KeyTag != 60485 || ds.Algorithm != 13 || ds.DigestType != 2 {
		t.Fatalf("DS header = %d %d %d, want 60485 13 2", ds.KeyTag, ds.Algorithm, ds.DigestType)
	}
	if got, want := ds.String(), "60485 13 2 abcdef1234567890"; got != want {
		t.Fatalf("DS String() = %q, want %q", got, want)
	}
	if !rdataPacks(ds) {
		t.Fatal("parsed DS does not pack")
	}

	invalid := []string{
		"60485 13",
		"65536 13 2 abcdef",
		"60485 256 2 abcdef",
		"60485 13 256 abcdef",
		"60485 13 2 not-hex",
	}
	for _, rdata := range invalid {
		if rd := parseRData("DS", rdata); rd != nil {
			t.Fatalf("parseRData(DS, %q) = %T, want nil", rdata, rd)
		}
	}
}

func TestParseRDataDNSKEY(t *testing.T) {
	rd := parseRData("DNSKEY", "257 3 13 AQID BAUG")
	dnskey, ok := rd.(*protocol.RDataDNSKEY)
	if !ok {
		t.Fatalf("parseRData(DNSKEY) = %T, want *protocol.RDataDNSKEY", rd)
	}
	if dnskey.Flags != 257 || dnskey.Protocol != 3 || dnskey.Algorithm != 13 {
		t.Fatalf("DNSKEY header = %d %d %d, want 257 3 13", dnskey.Flags, dnskey.Protocol, dnskey.Algorithm)
	}
	if got, want := dnskey.String(), "257 3 13 AQIDBAUG"; got != want {
		t.Fatalf("DNSKEY String() = %q, want %q", got, want)
	}
	if !rdataPacks(dnskey) {
		t.Fatal("parsed DNSKEY does not pack")
	}

	invalid := []string{
		"257 3",
		"65536 3 13 AQID",
		"257 256 13 AQID",
		"257 3 256 AQID",
		"257 3 13 not-base64!",
	}
	for _, rdata := range invalid {
		if rd := parseRData("DNSKEY", rdata); rd != nil {
			t.Fatalf("parseRData(DNSKEY, %q) = %T, want nil", rdata, rd)
		}
	}
}

func TestParseRDataRRSIG(t *testing.T) {
	rd := parseRData("RRSIG", "A 13 2 3600 20260609010203 20250609010203 60485 example.com. AQID BAUG")
	rrsig, ok := rd.(*protocol.RDataRRSIG)
	if !ok {
		t.Fatalf("parseRData(RRSIG) = %T, want *protocol.RDataRRSIG", rd)
	}
	if rrsig.TypeCovered != protocol.TypeA || rrsig.Algorithm != 13 || rrsig.Labels != 2 {
		t.Fatalf("RRSIG header = %d %d %d, want A 13 2", rrsig.TypeCovered, rrsig.Algorithm, rrsig.Labels)
	}
	if rrsig.OriginalTTL != 3600 || rrsig.KeyTag != 60485 {
		t.Fatalf("RRSIG ttl/keytag = %d %d, want 3600 60485", rrsig.OriginalTTL, rrsig.KeyTag)
	}
	if rrsig.SignerName == nil || rrsig.SignerName.String() != "example.com." {
		t.Fatalf("RRSIG signer = %v, want example.com.", rrsig.SignerName)
	}
	if got, want := rrsig.String(), "A 13 2 3600 20260609010203 20250609010203 60485 example.com. AQIDBAUG"; got != want {
		t.Fatalf("RRSIG String() = %q, want %q", got, want)
	}
	if !rdataPacks(rrsig) {
		t.Fatal("parsed RRSIG does not pack")
	}

	rd = parseRData("RRSIG", "TYPE123 8 1 300 1780977600 1749441600 12345 example.com. AQIDBA")
	rrsig, ok = rd.(*protocol.RDataRRSIG)
	if !ok {
		t.Fatalf("parseRData(RRSIG unix/raw) = %T, want *protocol.RDataRRSIG", rd)
	}
	if rrsig.TypeCovered != 123 || rrsig.Expiration != 1780977600 || rrsig.Inception != 1749441600 {
		t.Fatalf("RRSIG unix fields = %d %d %d, want 123 1780977600 1749441600", rrsig.TypeCovered, rrsig.Expiration, rrsig.Inception)
	}

	invalid := []string{
		"A 13 2 3600 20260609010203 20250609010203 60485 example.com.",
		"NOTATYPE 13 2 3600 20260609010203 20250609010203 60485 example.com. AQID",
		"A 256 2 3600 20260609010203 20250609010203 60485 example.com. AQID",
		"A 13 256 3600 20260609010203 20250609010203 60485 example.com. AQID",
		"A 13 2 4294967296 20260609010203 20250609010203 60485 example.com. AQID",
		"A 13 2 3600 20261309010203 20250609010203 60485 example.com. AQID",
		"A 13 2 3600 20260609010203 20251309010203 60485 example.com. AQID",
		"A 13 2 3600 20260609010203 20250609010203 65536 example.com. AQID",
		"A 13 2 3600 20260609010203 20250609010203 60485 " + strings.Repeat("a", 64) + ".example.com. AQID",
		"A 13 2 3600 20260609010203 20250609010203 60485 example.com. not-base64!",
	}
	for _, rdata := range invalid {
		if rd := parseRData("RRSIG", rdata); rd != nil {
			t.Fatalf("parseRData(RRSIG, %q) = %T, want nil", rdata, rd)
		}
	}
}

func TestParseRDataZONEMD(t *testing.T) {
	rd := parseRData("ZONEMD", "2024060901 1 1 ABCDEF 1234567890")
	zonemd, ok := rd.(*protocol.RDataZONEMD)
	if !ok {
		t.Fatalf("parseRData(ZONEMD) = %T, want *protocol.RDataZONEMD", rd)
	}
	if zonemd.Serial != 2024060901 || zonemd.Scheme != 1 || zonemd.Algorithm != 1 {
		t.Fatalf("ZONEMD header = %d %d %d, want 2024060901 1 1", zonemd.Serial, zonemd.Scheme, zonemd.Algorithm)
	}
	if got, want := zonemd.String(), "2024060901 1 1 abcdef1234567890"; got != want {
		t.Fatalf("ZONEMD String() = %q, want %q", got, want)
	}
	if !rdataPacks(zonemd) {
		t.Fatal("parsed ZONEMD does not pack")
	}

	invalid := []string{
		"2024060901 1",
		"4294967296 1 1 abcdef",
		"2024060901 256 1 abcdef",
		"2024060901 1 256 abcdef",
		"2024060901 1 1 not-hex",
	}
	for _, rdata := range invalid {
		if rd := parseRData("ZONEMD", rdata); rd != nil {
			t.Fatalf("parseRData(ZONEMD, %q) = %T, want nil", rdata, rd)
		}
	}
}

func TestParseRDataNSEC(t *testing.T) {
	rd := parseRData("NSEC", "next.example.com. TXT A DNSKEY TYPE123")
	nsec, ok := rd.(*protocol.RDataNSEC)
	if !ok {
		t.Fatalf("parseRData(NSEC) = %T, want *protocol.RDataNSEC", rd)
	}
	if nsec.NextDomain == nil || nsec.NextDomain.String() != "next.example.com." {
		t.Fatalf("NSEC next domain = %v, want next.example.com.", nsec.NextDomain)
	}
	if got, want := nsec.String(), "next.example.com. A TXT DNSKEY TYPE123"; got != want {
		t.Fatalf("NSEC String() = %q, want %q", got, want)
	}
	if !rdataPacks(nsec) {
		t.Fatal("parsed NSEC does not pack")
	}

	invalid := []string{
		"next.example.com.",
		strings.Repeat("a", 64) + ".example.com. A",
		"next.example.com. NOTATYPE",
		"next.example.com. TYPE0",
		"next.example.com. TYPE65536",
	}
	for _, rdata := range invalid {
		if rd := parseRData("NSEC", rdata); rd != nil {
			t.Fatalf("parseRData(NSEC, %q) = %T, want nil", rdata, rd)
		}
	}
}

func TestParseRDataNSEC3(t *testing.T) {
	nextHash := protocol.Base32Encode([]byte{1, 2, 3})
	rd := parseRData("NSEC3", "1 1 10 A1B2 "+nextHash+" TXT A DNSKEY TYPE123")
	nsec3, ok := rd.(*protocol.RDataNSEC3)
	if !ok {
		t.Fatalf("parseRData(NSEC3) = %T, want *protocol.RDataNSEC3", rd)
	}
	if nsec3.HashAlgorithm != 1 || nsec3.Flags != 1 || nsec3.Iterations != 10 {
		t.Fatalf("NSEC3 header = %d %d %d, want 1 1 10", nsec3.HashAlgorithm, nsec3.Flags, nsec3.Iterations)
	}
	if got, want := nsec3.String(), "1 1 10 a1b2 "+nextHash+" A TXT DNSKEY TYPE123"; got != want {
		t.Fatalf("NSEC3 String() = %q, want %q", got, want)
	}
	if !rdataPacks(nsec3) {
		t.Fatal("parsed NSEC3 does not pack")
	}

	invalid := []string{
		"1 0 10 a1b2",
		"256 0 10 a1b2 " + nextHash,
		"1 256 10 a1b2 " + nextHash,
		"1 0 65536 a1b2 " + nextHash,
		"1 0 10 not-hex " + nextHash,
		"1 0 10 a1b2 not-base32!",
		"1 0 10 a1b2 " + nextHash + " NOTATYPE",
		"1 0 10 a1b2 " + protocol.Base32Encode(make([]byte, 256)),
	}
	for _, rdata := range invalid {
		if rd := parseRData("NSEC3", rdata); rd != nil {
			t.Fatalf("parseRData(NSEC3, %q) = %T, want nil", rdata, rd)
		}
	}
}

func TestParseRDataNSEC3PARAM(t *testing.T) {
	rd := parseRData("NSEC3PARAM", "1 1 10 A1B2 C3")
	nsec3param, ok := rd.(*protocol.RDataNSEC3PARAM)
	if !ok {
		t.Fatalf("parseRData(NSEC3PARAM) = %T, want *protocol.RDataNSEC3PARAM", rd)
	}
	if nsec3param.HashAlgorithm != 1 || nsec3param.Flags != 1 || nsec3param.Iterations != 10 {
		t.Fatalf("NSEC3PARAM header = %d %d %d, want 1 1 10", nsec3param.HashAlgorithm, nsec3param.Flags, nsec3param.Iterations)
	}
	if got, want := nsec3param.String(), "1 1 10 a1b2c3"; got != want {
		t.Fatalf("NSEC3PARAM String() = %q, want %q", got, want)
	}
	if !rdataPacks(nsec3param) {
		t.Fatal("parsed NSEC3PARAM does not pack")
	}

	rd = parseRData("NSEC3PARAM", "1 0 0 -")
	nsec3param, ok = rd.(*protocol.RDataNSEC3PARAM)
	if !ok {
		t.Fatalf("parseRData(NSEC3PARAM empty salt) = %T, want *protocol.RDataNSEC3PARAM", rd)
	}
	if got, want := nsec3param.String(), "1 0 0 -"; got != want {
		t.Fatalf("NSEC3PARAM empty salt String() = %q, want %q", got, want)
	}

	invalid := []string{
		"1 0",
		"256 0 10 a1b2",
		"1 256 10 a1b2",
		"1 0 65536 a1b2",
		"1 0 10 not-hex",
		"1 0 10 " + strings.Repeat("aa", 256),
	}
	for _, rdata := range invalid {
		if rd := parseRData("NSEC3PARAM", rdata); rd != nil {
			t.Fatalf("parseRData(NSEC3PARAM, %q) = %T, want nil", rdata, rd)
		}
	}
}

func TestParseRDataSVCB(t *testing.T) {
	rd := parseRData("SVCB", `1 svc.example.com. port=8443 alpn="h2,h3" ipv4hint=192.0.2.1,192.0.2.2`)
	svcb, ok := rd.(*protocol.RDataSVCB)
	if !ok {
		t.Fatalf("parseRData(SVCB) = %T, want *protocol.RDataSVCB", rd)
	}
	if svcb.Priority != 1 || svcb.Target == nil || svcb.Target.String() != "svc.example.com." {
		t.Fatalf("SVCB priority/target = %d %v, want 1 svc.example.com.", svcb.Priority, svcb.Target)
	}
	if got, want := svcb.String(), `1 svc.example.com. alpn="h2,h3" port=8443 ipv4hint=192.0.2.1,192.0.2.2`; got != want {
		t.Fatalf("SVCB String() = %q, want %q", got, want)
	}
	if !rdataPacks(svcb) {
		t.Fatal("parsed SVCB does not pack")
	}
}

func TestParseRDataHTTPSAliasMode(t *testing.T) {
	rd := parseRData("HTTPS", "0 target.example.com.")
	https, ok := rd.(*protocol.RDataHTTPS)
	if !ok {
		t.Fatalf("parseRData(HTTPS) = %T, want *protocol.RDataHTTPS", rd)
	}
	if https.Priority != 0 || https.Target == nil || https.Target.String() != "target.example.com." {
		t.Fatalf("HTTPS priority/target = %d %v, want 0 target.example.com.", https.Priority, https.Target)
	}
	if got, want := https.String(), "0 target.example.com."; got != want {
		t.Fatalf("HTTPS String() = %q, want %q", got, want)
	}
	if !rdataPacks(https) {
		t.Fatal("parsed HTTPS does not pack")
	}
}

func TestParseRDataSVCBHTTPSInvalid(t *testing.T) {
	invalid := []struct {
		rtype string
		rdata string
	}{
		{rtype: "SVCB", rdata: "1"},
		{rtype: "SVCB", rdata: "not-a-number svc.example.com."},
		{rtype: "SVCB", rdata: "1 " + strings.Repeat("a", 64) + ".example.com."},
		{rtype: "SVCB", rdata: `0 target.example.com. alpn="h2"`},
		{rtype: "SVCB", rdata: "1 svc.example.com. port=bad"},
		{rtype: "SVCB", rdata: "1 svc.example.com. ipv4hint=2001:db8::1"},
		{rtype: "HTTPS", rdata: "1 svc.example.com. no-default-alpn"},
		{rtype: "HTTPS", rdata: `1 svc.example.com. mandatory=ipv4hint alpn="h2"`},
	}

	for _, tc := range invalid {
		if rd := parseRData(tc.rtype, tc.rdata); rd != nil {
			t.Fatalf("parseRData(%s, %q) = %T, want nil", tc.rtype, tc.rdata, rd)
		}
	}
}

// TestResolveDashboardBearer_NeverReturnsAuthSecret regresses
// SECURITY-REPORT.md H-1. Before the fix, an empty AuthToken caused
// main() to fall back to AuthSecret as the dashboard bearer, conflating
// the HMAC-SHA512 session-signing key with a routine credential.
// Leaking the dashboard bearer would then also leak the token-forgery
// key. The helper must return AuthToken verbatim — empty when AuthToken
// is empty, never AuthSecret.
func TestResolveDashboardBearer_NeverReturnsAuthSecret(t *testing.T) {
	const secret = "super-secret-hmac-signing-key-must-not-leak"

	cases := []struct {
		name string
		cfg  config.HTTPConfig
		want string
	}{
		{
			name: "empty AuthToken, populated AuthSecret",
			cfg:  config.HTTPConfig{AuthToken: "", AuthSecret: secret},
			want: "",
		},
		{
			name: "empty AuthToken, empty AuthSecret",
			cfg:  config.HTTPConfig{AuthToken: "", AuthSecret: ""},
			want: "",
		},
		{
			name: "populated AuthToken, populated AuthSecret",
			cfg:  config.HTTPConfig{AuthToken: "explicit-bearer", AuthSecret: secret},
			want: "explicit-bearer",
		},
		{
			name: "populated AuthToken, empty AuthSecret",
			cfg:  config.HTTPConfig{AuthToken: "explicit-bearer", AuthSecret: ""},
			want: "explicit-bearer",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveDashboardBearer(tc.cfg)
			if got != tc.want {
				t.Errorf("resolveDashboardBearer = %q, want %q", got, tc.want)
			}
			if tc.cfg.AuthSecret != "" && got == tc.cfg.AuthSecret {
				t.Errorf("resolveDashboardBearer returned AuthSecret — this is the H-1 regression")
			}
		})
	}
}

// TestValidateAuthPersistenceConfig regresses SECURITY-REPORT.md L-4:
// TokenPersistencePath without an explicit AuthSecret must fail at
// startup, not silently boot with an empty token map.
func TestValidateAuthPersistenceConfig(t *testing.T) {
	cases := []struct {
		name      string
		cfg       config.HTTPConfig
		wantError bool
	}{
		{
			name:      "persistence path set, no auth_secret — must fail",
			cfg:       config.HTTPConfig{TokenPersistencePath: "/var/lib/ndns/tokens", AuthSecret: ""},
			wantError: true,
		},
		{
			name:      "persistence path set, auth_secret set — ok",
			cfg:       config.HTTPConfig{TokenPersistencePath: "/var/lib/ndns/tokens", AuthSecret: "stable-secret"},
			wantError: false,
		},
		{
			name:      "no persistence path — ok regardless of auth_secret",
			cfg:       config.HTTPConfig{},
			wantError: false,
		},
		{
			name:      "no persistence path, auth_secret set — ok",
			cfg:       config.HTTPConfig{AuthSecret: "stable-secret"},
			wantError: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAuthPersistenceConfig(tc.cfg)
			if (err != nil) != tc.wantError {
				t.Errorf("got err=%v, wantError=%v", err, tc.wantError)
			}
		})
	}
}

// TestParseRDataLOCMinimalForms verifies RFC 1876 §3 optional components:
// minutes, seconds, size, and precisions may all be omitted. The minimal
// valid form is `d1 {N|S} d2 {E|W} alt` — five fields.
func TestParseRDataLOCMinimalForms(t *testing.T) {
	for _, rdata := range []string{
		"31 N 106 W 100m",                       // 5 fields: degrees only
		"31 20 N 106 W 100m",                    // 6 fields: minutes on latitude
		"42 21 54 N 71 06 18 W -24m",            // full coordinates, no size/precision
		"42 21 54 N 71 06 18 W -24m 30m 10m 0m", // zero vertical precision
	} {
		if rd := parseRData("LOC", rdata); rd == nil {
			t.Errorf("parseRData(LOC, %q) = nil, want parsed RData", rdata)
		} else if !rdataPacks(rd) {
			t.Errorf("parseRData(LOC, %q) does not pack", rdata)
		}
	}
	for _, rdata := range []string{
		"31 N 106 W",     // missing altitude
		"31 X 106 W 10m", // bad hemisphere
		"",
	} {
		if rd := parseRData("LOC", rdata); rd != nil {
			t.Errorf("parseRData(LOC, %q) = %T, want nil", rdata, rd)
		}
	}
}

// TestParseTXTRDataVerbatimFallback: stored rdata containing a literal,
// unbalanced double-quote (e.g. unescaped from a zone file `"ab\"cd"`) must
// be served verbatim, not silently dropped.
func TestParseTXTRDataVerbatimFallback(t *testing.T) {
	rd := parseRData("TXT", `ab"cd`)
	txt, ok := rd.(*protocol.RDataTXT)
	if !ok {
		t.Fatalf("parseRData(TXT, unbalanced quote) = %T, want *protocol.RDataTXT", rd)
	}
	if len(txt.Strings) != 1 || txt.Strings[0] != `ab"cd` {
		t.Fatalf("TXT strings = %v, want verbatim single string", txt.Strings)
	}

	// Balanced presentation form still splits into character-strings.
	rd = parseRData("TXT", `"part one" "part two"`)
	txt, ok = rd.(*protocol.RDataTXT)
	if !ok {
		t.Fatalf("parseRData(TXT, quoted) = %T, want *protocol.RDataTXT", rd)
	}
	if len(txt.Strings) != 2 || txt.Strings[0] != "part one" || txt.Strings[1] != "part two" {
		t.Fatalf("TXT strings = %v, want two character-strings", txt.Strings)
	}
}
