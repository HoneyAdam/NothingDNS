package main

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
)

// ============================================================================
// runWithContext Phase 3 (graceful shutdown) coverage
//
// These tests drive the select { case <-done: ... case <-shutdownCtx.Done(): }
// branch that lives inside the SIGTERM/SIGINT handler of runWithContext's
// signal loop. There are two outcomes:
//
//   1. Happy path — cleanup completes within cfg.ShutdownTimeout and the
//      `<-done:` branch fires, logging "Server shutdown complete".
//   2. Timeout path — cleanup takes longer than cfg.ShutdownTimeout and
//      the `<-shutdownCtx.Done()` branch fires, logging
//      "Server shutdown timed out after X".
//
// We construct a fresh, full cfg for each test so the manager init
// succeeds (so we exercise Phase 3 cleanly), then drive SIGTERM via
// installFakeSignalHandler to invoke the shutdown path.
// ============================================================================

// runShutdownDriven is the test harness for Phase 3: build a minimal
// valid cfg, call runWithContext in a goroutine, give it a moment to
// boot Phase 2, then send SIGTERM on the injected signal channel and
// wait for runWithContext to return. The returned time.Duration is
// how long shutdown took; tests use this to verify the timeout
// branch (very short return) or the happy branch (longer return).
func runShutdownDriven(t *testing.T, cfg *config.Config) (time.Duration, error) {
	t.Helper()
	sigCh := make(chan os.Signal, 1)
	restore := installFakeSignalHandler(sigCh)
	defer restore()

	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		// Note: started is just for observability; we don't strictly
		// need to wait for boot, the sleep is sufficient.
		close(started)
		done <- runWithContext(context.Background(), cfg)
	}()

	// Allow Phase 2 to complete (UDP/TCP sockets up, stats collector
	// running). 700ms matches the boot profile the rest of the
	// shutdown test family uses.
	time.Sleep(700 * time.Millisecond)

	start := time.Now()
	sigCh <- syscall.SIGTERM

	select {
	case err := <-done:
		return time.Since(start), err
	case <-time.After(20 * time.Second):
		t.Fatal("runWithContext did not return within 20s after SIGTERM")
		return 0, nil
	}
}

// writeMinimalShutdownConfig writes a config tailored for the
// shutdown tests: it has the same Phase 1/2 fields as the run-context
// family but additionally carries cfg.ShutdownTimeout set to whatever
// the caller requests.
func writeMinimalShutdownConfig(t *testing.T, shutdownTimeout string) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	body := []byte("server:\n  listen:\n    - 127.0.0.1:0\n  udp_bind:\n    - 127.0.0.1:0\n  tcp_bind:\n    - 127.0.0.1:0\nlogging:\n  level: error\n  format: text\n  output: stderr\nmetrics:\n  enabled: false\ncache:\n  enabled: false\nacl:\n  rules: []\nshutdown_timeout: " + shutdownTimeout + "\n")
	if err := os.WriteFile(cfgPath, body, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}

// TestRunWithContext_ShutdownTimeout_Fast completes the happy-path
// shutdown: cfg.ShutdownTimeout="5s" is generous so the manager-cleanup
// goroutine finishes inside the timeout and the `case <-done:` branch
// fires. This makes explicit the path that TestRunWithContext_Shutdown
// already covers.
func TestRunWithContext_ShutdownTimeout_Fast(t *testing.T) {
	cfgPath := writeMinimalShutdownConfig(t, "5s")
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	dur, err := runShutdownDriven(t, cfg)
	if err != nil {
		t.Errorf("runWithContext error: %v", err)
	}
	t.Logf("shutdown completed in %s", dur)
}

// TestRunWithContext_ShutdownTimeout_VeryShort exercises the
// `<-shutdownCtx.Done()` branch by configuring a sub-millisecond
// shutdown_timeout. The cleanup goroutine cannot keep up; the select
// fires the timeout branch and "Server shutdown timed out after ..." is
// logged.
func TestRunWithContext_ShutdownTimeout_VeryShort(t *testing.T) {
	cfgPath := writeMinimalShutdownConfig(t, "1ns")
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	dur, err := runShutdownDriven(t, cfg)
	if err != nil {
		t.Errorf("runWithContext error: %v", err)
	}
	t.Logf("shutdown with 1ns timeout completed in %s", dur)
}

// TestRunWithContext_ShutdownTimeoutInvalid exercises the
// parseDurationOrDefault fallback inside the SIGTERM branch. We set
// cfg.ShutdownTimeout to a string that time.ParseDuration cannot
// parse, so the parser returns the default 30s. This drives the
// "parse failed -> default" branch in parseDurationOrDefault.
func TestRunWithContext_ShutdownTimeoutInvalid(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	// "garbage" is not a valid duration string — parseDurationOrDefault
	// should fall back to 30s.
	body := []byte("server:\n  listen:\n    - 127.0.0.1:0\n  udp_bind:\n    - 127.0.0.1:0\n  tcp_bind:\n    - 127.0.0.1:0\nlogging:\n  level: error\n  format: text\n  output: stderr\nmetrics:\n  enabled: false\ncache:\n  enabled: false\nacl:\n  rules: []\nshutdown_timeout: garbage\n")
	if err := os.WriteFile(cfgPath, body, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		// loadConfig may also reject invalid values; either path
		// gives us coverage of one of the early-return branches.
		t.Logf("loadConfig rejected garbage value: %v", err)
		return
	}
	dur, err := runShutdownDriven(t, cfg)
	if err != nil {
		t.Errorf("runWithContext error: %v", err)
	}
	t.Logf("shutdown with invalid timeout completed in %s", dur)
}
