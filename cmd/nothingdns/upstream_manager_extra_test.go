package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/util"
)

func TestLogManagerStopErrorWritesWarning(t *testing.T) {
	var buf bytes.Buffer
	logger := util.NewLogger(util.WARN, util.TextFormat, &buf)
	closeErr := errors.New("close failed")

	logManagerStopError(logger, "upstream client", closeErr)

	logged := buf.String()
	if !strings.Contains(logged, "WARN") {
		t.Fatalf("log output missing warning level: %q", logged)
	}
	if !strings.Contains(logged, "Failed to stop upstream client: close failed") {
		t.Fatalf("log output missing close error: %q", logged)
	}
}

func TestLogManagerStopErrorIgnoresNilError(t *testing.T) {
	var buf bytes.Buffer
	logger := util.NewLogger(util.WARN, util.TextFormat, &buf)

	logManagerStopError(logger, "upstream client", nil)

	if logged := buf.String(); logged != "" {
		t.Fatalf("expected no log output for nil error, got %q", logged)
	}
}

func TestUpstreamManagerStopNilReceiver(t *testing.T) {
	var mgr *UpstreamManager
	mgr.Stop()
}

func TestClusterManagerStopNilReceiver(t *testing.T) {
	var mgr *ClusterManager
	mgr.Stop()
}
