package server

import (
	"os"
	"strings"
	"testing"
)

// TestL2_PanicRecoveryPresent_InTCPAndUDP regresses SECURITY-REPORT.md
// L-2 with a static-grep tripwire. The TCP and UDP per-message entry
// points (handleMessage and handleRequest) MUST install their own
// defer recover() — they execute UnpackMessage / EDNS0 parsing
// BEFORE handing off to ServeDNS, so the integratedHandler's
// recover at cmd/nothingdns/handler.go doesn't cover them. A panic
// in UnpackMessage would otherwise propagate to the goroutine and
// crash the daemon.
//
// A proper test that injects a real panic would need to monkey-patch
// UnpackMessage (it's hardened by fuzz coverage and not a realistic
// panic source today); the tripwire flags any future refactor that
// removes the recover. If the architecture changes such that
// UnpackMessage is moved behind a global recover, replace this
// tripwire with the appropriate integration test.
func TestL2_PanicRecoveryPresent_InTCPAndUDP(t *testing.T) {
	cases := []struct {
		file   string
		anchor string
		needle string
	}{
		{
			file:   "tcp.go",
			anchor: "func (s *TCPServer) handleMessage(",
			needle: "if r := recover(); r != nil",
		},
		{
			file:   "udp.go",
			anchor: "func (s *UDPServer) handleRequest(",
			needle: "if r := recover(); r != nil",
		},
	}

	for _, tc := range cases {
		src, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		body := string(src)
		anchorAt := strings.Index(body, tc.anchor)
		if anchorAt < 0 {
			t.Errorf("%s: anchor %q not found — has the function been renamed? Update this tripwire and re-verify L-2", tc.file, tc.anchor)
			continue
		}
		// Look for the recover within the first 500 bytes after the
		// function declaration — i.e. the defer block at the top, not
		// some unrelated recover further down.
		window := body[anchorAt:]
		if len(window) > 500 {
			window = window[:500]
		}
		if !strings.Contains(window, tc.needle) {
			t.Errorf("%s: %q is missing %q in the first 500 bytes — L-2 regression: UnpackMessage / EDNS0 panic can crash the daemon", tc.file, tc.anchor, tc.needle)
		}
	}
}
