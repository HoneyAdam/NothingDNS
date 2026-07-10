package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var errAuditWrite = errors.New("audit write failed")

type failingAuditWriter struct{}

func (failingAuditWriter) Write([]byte) (int, error) {
	return 0, errAuditWrite
}

func TestNewAuditLogger_Disabled(t *testing.T) {
	al, err := NewAuditLogger(false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if al.enabled.Load() {
		t.Error("logger should be disabled")
	}
}

func TestAuditLogger_LogQuery_Disabled(t *testing.T) {
	al, _ := NewAuditLogger(false, "")
	// Should not panic
	al.LogQuery(QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		ClientIP:  "10.0.0.1",
		QueryName: "example.com",
		QueryType: "A",
	})
}

// TestAuditLogger_Disabled_NoWrite asserts that a disabled logger never
// touches its output writer, even if one is wired up, for every Log* entry
// point. Extreme inputs (huge strings, control characters) must neither
// panic nor produce output.
func TestAuditLogger_Disabled_NoWrite(t *testing.T) {
	al, err := NewAuditLogger(false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var buf bytes.Buffer
	al.output = &buf

	huge := strings.Repeat("x", 1<<16) + "\n\r\x00"
	al.LogQuery(QueryAuditEntry{ClientIP: huge, QueryName: huge, QueryType: huge})
	al.LogAXFR(AXFRAuditEntry{ClientIP: huge, Zone: huge})
	al.LogIXFR(IXFRAuditEntry{ClientIP: huge, Zone: huge})
	al.LogNOTIFY(NOTIFYAuditEntry{ClientIP: huge, Zone: huge})
	al.LogUpdate(UpdateAuditEntry{ClientIP: huge, Zone: huge})
	al.LogReload(ReloadAuditEntry{Error: huge})

	al.Sync()
	if buf.Len() != 0 {
		al.Sync()
		t.Errorf("disabled logger wrote %d bytes, want 0", buf.Len())
	}
	if al.LastError() != nil {
		t.Errorf("disabled logger recorded error: %v", al.LastError())
	}
}

// TestAuditLogger_LogQuery_Disabled_NoFormatting asserts the disabled
// fast path does no formatting work: formatQueryAuditLine allocates
// (fmt.Sprintf + sanitizeLogField), so zero allocations proves it was
// never called.
func TestAuditLogger_LogQuery_Disabled_NoFormatting(t *testing.T) {
	al, _ := NewAuditLogger(false, "")
	entry := QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		ClientIP:  "10.0.0.1\nfake line",
		QueryName: strings.Repeat("a", 4096) + ".example.com",
		QueryType: "A",
		Rcode:     "0",
		Latency:   5 * time.Millisecond,
		Upstream:  "8.8.8.8:53",
	}

	allocs := testing.AllocsPerRun(100, func() {
		al.LogQuery(entry)
	})
	if allocs != 0 {
		t.Errorf("LogQuery on disabled logger allocated %v times per run, want 0 (formatting must be skipped)", allocs)
	}
}

// TestAuditLogger_LogAfterClose asserts that Log* calls after Close are
// silent no-ops (Close flips the enabled flag).
func TestAuditLogger_LogAfterClose(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	var buf bytes.Buffer
	al.output = &buf
	al.Close()

	al.LogQuery(QueryAuditEntry{QueryName: "after-close.example.com", QueryType: "A"})
	al.Sync()
	if buf.Len() != 0 {
		al.Sync()
		t.Errorf("logger wrote %d bytes after Close, want 0", buf.Len())
	}
}

func BenchmarkLogQuery_Disabled(b *testing.B) {
	al, _ := NewAuditLogger(false, "")
	entry := QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		ClientIP:  "10.0.0.1",
		QueryName: "example.com",
		QueryType: "A",
		Rcode:     "0",
		Latency:   5 * time.Millisecond,
		Upstream:  "8.8.8.8:53",
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			al.LogQuery(entry)
		}
	})
}

func TestAuditLogger_LogQuery_Stdout(t *testing.T) {
	al, err := NewAuditLogger(true, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer al.Close()

	// Redirect output for testing
	var buf bytes.Buffer
	al.output = &buf

	al.LogQuery(QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		ClientIP:  "10.0.0.1",
		QueryName: "example.com",
		QueryType: "A",
		Rcode:     "0",
		Latency:   5 * time.Millisecond,
		CacheHit:  false,
		Upstream:  "8.8.8.8:53",
	})

	al.Sync()
	output := buf.String()
	if !strings.Contains(output, "client=10.0.0.1") {
		t.Errorf("expected client IP in output, got: %s", output)
	}
	if !strings.Contains(output, "query=example.com") {
		t.Errorf("expected query name in output, got: %s", output)
	}
	if !strings.Contains(output, "type=A") {
		t.Errorf("expected query type in output, got: %s", output)
	}
	if !strings.Contains(output, "cache=miss") {
		t.Errorf("expected cache=miss in output, got: %s", output)
	}
	if !strings.Contains(output, "upstream=8.8.8.8:53") {
		t.Errorf("expected upstream in output, got: %s", output)
	}
}

func TestAuditLogger_LogQuery_CacheHit(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	defer al.Close()

	var buf bytes.Buffer
	al.output = &buf

	al.LogQuery(QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		ClientIP:  "10.0.0.1",
		QueryName: "example.com",
		QueryType: "A",
		Rcode:     "0",
		CacheHit:  true,
	})

	al.Sync()
	output := buf.String()
	if !strings.Contains(output, "cache=hit") {
		t.Errorf("expected cache=hit in output, got: %s", output)
	}
}

func TestAuditLogger_LogQuery_NoUpstream(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	defer al.Close()

	var buf bytes.Buffer
	al.output = &buf

	al.LogQuery(QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		ClientIP:  "10.0.0.1",
		QueryName: "example.com",
		QueryType: "AAAA",
		Rcode:     "0",
	})

	al.Sync()
	output := buf.String()
	if !strings.Contains(output, "upstream=-") {
		t.Errorf("expected upstream=- in output, got: %s", output)
	}
}

func TestAuditLogger_LogQuery_RecordsWriteError(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	defer al.Close()
	al.output = failingAuditWriter{}

	al.LogQuery(QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		ClientIP:  "10.0.0.1",
		QueryName: "example.com",
		QueryType: "A",
		Rcode:     "0",
	})
	al.Sync() // let the background writer attempt (and fail) the write

	if !errors.Is(al.LastError(), errAuditWrite) {
		t.Fatalf("LastError() = %v, want %v", al.LastError(), errAuditWrite)
	}
}

func TestAuditLogger_LogQuery_FileOutput(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "query.log")

	al, err := NewAuditLogger(true, logFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	al.LogQuery(QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		ClientIP:  "10.0.0.1",
		QueryName: "example.com",
		QueryType: "A",
		Rcode:     "0",
		Latency:   1 * time.Millisecond,
	})
	al.Close()

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("reading log file: %v", err)
	}

	if !strings.Contains(string(data), "client=10.0.0.1") {
		t.Errorf("expected client IP in file output, got: %s", string(data))
	}
}

func TestNewAuditLogger_FilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "query.log")

	al, err := NewAuditLogger(true, logFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	al.Close()

	info, err := os.Stat(logFile)
	if err != nil {
		t.Fatalf("stat log file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("new log file mode = %o, want 0600", got)
	}

	if err := os.Chmod(logFile, 0644); err != nil {
		t.Fatalf("chmod log file: %v", err)
	}
	al, err = NewAuditLogger(true, logFile)
	if err != nil {
		t.Fatalf("unexpected error reopening log file: %v", err)
	}
	al.Close()

	info, err = os.Stat(logFile)
	if err != nil {
		t.Fatalf("stat reopened log file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("reopened log file mode = %o, want 0600", got)
	}
}

func TestAuditLogger_LogQuery_Append(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "query.log")

	al1, _ := NewAuditLogger(true, logFile)
	al1.LogQuery(QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		QueryName: "first.example.com",
		QueryType: "A",
		Rcode:     "0",
	})
	al1.Close()

	al2, _ := NewAuditLogger(true, logFile)
	al2.LogQuery(QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:01Z",
		QueryName: "second.example.com",
		QueryType: "A",
		Rcode:     "0",
	})
	al2.Close()

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("reading log file: %v", err)
	}

	if !strings.Contains(string(data), "first.example.com") {
		t.Error("expected first query in log")
	}
	if !strings.Contains(string(data), "second.example.com") {
		t.Error("expected second query in log")
	}
}

func TestFormatAuditLine(t *testing.T) {
	entry := QueryAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		ClientIP:  "192.168.1.1",
		QueryName: "test.example.com.",
		QueryType: "MX",
		Rcode:     "0",
		Latency:   1234 * time.Microsecond,
		CacheHit:  true,
		Upstream:  "1.1.1.1:53",
	}

	line := formatQueryAuditLine(entry)

	if !strings.Contains(line, "2026-04-02T12:00:00Z") {
		t.Error("expected timestamp in line")
	}
	if !strings.Contains(line, "client=192.168.1.1") {
		t.Error("expected client IP in line")
	}
	if !strings.Contains(line, "type=MX") {
		t.Error("expected MX type in line")
	}
	if !strings.Contains(line, "cache=hit") {
		t.Error("expected cache=hit in line")
	}
	if !strings.Contains(line, "upstream=1.1.1.1:53") {
		t.Error("expected upstream in line")
	}
}

func TestLogAXFR(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	defer al.Close()

	var buf bytes.Buffer
	al.output = &buf

	al.LogAXFR(AXFRAuditEntry{
		Timestamp:   "2026-04-02T12:00:00Z",
		ClientIP:    "10.0.0.1",
		Zone:        "example.com.",
		Action:      "completed",
		RecordCount: 100,
		Latency:     50 * time.Millisecond,
	})

	al.Sync()
	line := buf.String()
	if !strings.Contains(line, "zone=example.com.") {
		t.Error("expected zone in line")
	}
	if !strings.Contains(line, "action=completed") {
		t.Error("expected action in line")
	}
	if !strings.Contains(line, "records=100") {
		t.Error("expected record count in line")
	}
}

func TestLogIXFR(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	defer al.Close()

	var buf bytes.Buffer
	al.output = &buf

	al.LogIXFR(IXFRAuditEntry{
		Timestamp:   "2026-04-02T12:00:00Z",
		ClientIP:    "10.0.0.2",
		Zone:        "test.com.",
		Action:      "request",
		RecordCount: 5,
		Latency:     10 * time.Millisecond,
	})

	al.Sync()
	line := buf.String()
	if !strings.Contains(line, "zone=test.com.") {
		t.Error("expected zone in line")
	}
}

func TestLogNOTIFY(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	defer al.Close()

	var buf bytes.Buffer
	al.output = &buf

	al.LogNOTIFY(NOTIFYAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		ClientIP:  "192.168.1.1",
		Zone:      "example.com.",
		Action:    "received",
	})

	al.Sync()
	line := buf.String()
	if !strings.Contains(line, "zone=example.com.") {
		t.Error("expected zone in line")
	}
	if !strings.Contains(line, "action=received") {
		t.Error("expected action in line")
	}
}

func TestLogUpdate(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	defer al.Close()

	var buf bytes.Buffer
	al.output = &buf

	al.LogUpdate(UpdateAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		ClientIP:  "10.0.0.3",
		Zone:      "dyn.example.com.",
		Action:    "completed",
		Rcode:     "0",
		Added:     2,
		Deleted:   1,
	})

	al.Sync()
	line := buf.String()
	if !strings.Contains(line, "zone=dyn.example.com.") {
		t.Error("expected zone in line")
	}
	if !strings.Contains(line, "added=2") {
		t.Error("expected added count in line")
	}
	if !strings.Contains(line, "deleted=1") {
		t.Error("expected deleted count in line")
	}
}

func TestLogReload(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	defer al.Close()

	var buf bytes.Buffer
	al.output = &buf

	al.LogReload(ReloadAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		Action:    "start",
		Zones:     5,
		Error:     "",
	})

	al.Sync()
	line := buf.String()
	if !strings.Contains(line, "zones=5") {
		t.Error("expected zones count in line")
	}
}

func TestLogReload_WithError(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	defer al.Close()

	var buf bytes.Buffer
	al.output = &buf

	al.LogReload(ReloadAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		Action:    "failed",
		Zones:     3,
		Error:     "parse error at line 10",
	})

	al.Sync()
	line := buf.String()
	if !strings.Contains(line, "error=parse error at line 10") {
		t.Error("expected error in line")
	}
}

func TestFormatAXFRAuditLine(t *testing.T) {
	line := formatAXFRAuditLine(AXFRAuditEntry{
		Timestamp:   "2026-04-02T12:00:00Z",
		ClientIP:    "10.0.0.1",
		Zone:        "example.com.",
		Action:      "completed",
		RecordCount: 100,
		Latency:     50 * time.Millisecond,
	})

	if !strings.Contains(line, "zone=example.com.") {
		t.Error("expected zone in line")
	}
}

func TestFormatIXFRAuditLine(t *testing.T) {
	line := formatIXFRAuditLine(IXFRAuditEntry{
		Timestamp:   "2026-04-02T12:00:00Z",
		ClientIP:    "10.0.0.1",
		Zone:        "example.com.",
		Action:      "request",
		RecordCount: 5,
		Latency:     10 * time.Millisecond,
	})

	if !strings.Contains(line, "zone=example.com.") {
		t.Error("expected zone in line")
	}
}

func TestFormatNOTIFYAuditLine(t *testing.T) {
	line := formatNOTIFYAuditLine(NOTIFYAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		ClientIP:  "192.168.1.1",
		Zone:      "example.com.",
		Action:    "received",
	})

	if !strings.Contains(line, "zone=example.com.") {
		t.Error("expected zone in line")
	}
}

func TestFormatUpdateAuditLine(t *testing.T) {
	line := formatUpdateAuditLine(UpdateAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		ClientIP:  "10.0.0.3",
		Zone:      "dyn.example.com.",
		Action:    "completed",
		Rcode:     "0",
		Added:     2,
		Deleted:   1,
	})

	if !strings.Contains(line, "zone=dyn.example.com.") {
		t.Error("expected zone in line")
	}
}

func TestFormatReloadAuditLine(t *testing.T) {
	line := formatReloadAuditLine(ReloadAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		Action:    "start",
		Zones:     5,
		Error:     "",
	})

	if !strings.Contains(line, "zones=5") {
		t.Error("expected zones in line")
	}
}

func TestFormatReloadAuditLine_WithError(t *testing.T) {
	line := formatReloadAuditLine(ReloadAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		Action:    "failed",
		Zones:     3,
		Error:     "zone not found",
	})

	if !strings.Contains(line, "error=zone not found") {
		t.Error("expected error in line")
	}
}
