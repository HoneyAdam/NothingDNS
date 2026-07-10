package otel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// ExporterConfig holds OTLP exporter configuration.
type ExporterConfig struct {
	Endpoint     string        // OTLP collector endpoint (e.g., "http://localhost:4318")
	Protocol     string        // "http/protobuf" or "grpc"
	BatchSize    int           // Max spans per batch (default 100)
	BatchTimeout time.Duration // Flush interval (default 5s)
}

// OTLPExporter exports spans to an OTLP collector.
type OTLPExporter struct {
	config   ExporterConfig
	client   *http.Client
	batch    []*Span
	batchMu  sync.Mutex
	ticker   *time.Ticker
	stopCh   chan struct{}
	stopOnce sync.Once // guards Close() against second-call panic
	wg       sync.WaitGroup
}

// NewOTLPExporter creates a new OTLP exporter.
func NewOTLPExporter(cfg ExporterConfig) *OTLPExporter {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.BatchTimeout <= 0 {
		cfg.BatchTimeout = 5 * time.Second
	}
	if cfg.Protocol == "" {
		cfg.Protocol = "http/protobuf"
	}

	exporter := &OTLPExporter{
		config: cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		batch:  make([]*Span, 0, cfg.BatchSize),
		stopCh: make(chan struct{}),
	}

	// Start background batch flusher
	exporter.ticker = time.NewTicker(cfg.BatchTimeout)
	exporter.wg.Add(1)
	go exporter.batchFlusher()

	return exporter
}

// batchFlusher periodically flushes the batch.
func (e *OTLPExporter) batchFlusher() {
	defer e.wg.Done()
	for {
		select {
		case <-e.ticker.C:
			e.Flush()
		case <-e.stopCh:
			return
		}
	}
}

// Export adds a span to the batch and flushes if batch is full.
// maxExporterBatchSpans bounds an exporter's retained batch so that a
// persistently-unreachable collector (flush keeps failing / Flush is never
// called) cannot make the batch grow without bound (OOM). When exceeded, the
// oldest spans are dropped.
const maxExporterBatchSpans = 8192

func capBatch(batch []*Span) []*Span {
	if len(batch) <= maxExporterBatchSpans {
		return batch
	}
	drop := len(batch) - maxExporterBatchSpans
	return append(batch[:0], batch[drop:]...)
}

func (e *OTLPExporter) Export(span *Span) {
	e.batchMu.Lock()
	defer e.batchMu.Unlock()

	e.batch = append(e.batch, span)
	if len(e.batch) >= e.config.BatchSize {
		e.flushLocked()
	}
	// flushLocked keeps the batch on send failure (retry); bound it so a
	// down collector can't drive unbounded growth.
	e.batch = capBatch(e.batch)
}

// Flush exports all pending spans immediately.
func (e *OTLPExporter) Flush() {
	e.batchMu.Lock()
	defer e.batchMu.Unlock()
	e.flushLocked()
}

// flushLocked exports the current batch (must hold lock).
func (e *OTLPExporter) flushLocked() {
	if len(e.batch) == 0 {
		return
	}

	// Convert spans to OTLP format
	payload := e.toOTLPRequest(e.batch)

	// Send to collector
	err := e.sendPayload(payload)
	if err != nil {
		// On failure, keep spans for retry (simple approach)
		return
	}

	e.batch = e.batch[:0]
}

// toOTLPRequest converts spans to OTLP JSON format.
func (e *OTLPExporter) toOTLPRequest(spans []*Span) []byte {
	resourceSpans := make([]map[string]interface{}, 0, 1)

	// Single resource spans with instrumentation library
	scopeSpans := make([]map[string]interface{}, 0, len(spans))
	for _, span := range spans {
		otlpSpan := map[string]interface{}{
			"trace_id":             bytesToHex(span.TraceID[:]),
			"span_id":              bytesToHex(span.SpanID[:]),
			"name":                 span.Name,
			"start_time_unix_nano": span.StartTime.UnixNano(),
			"end_time_unix_nano":   span.EndTime.UnixNano(),
			"attributes":           convertAttrs(span.Attrs),
		}

		if span.ParentID != ([8]byte{}) {
			otlpSpan["parent_span_id"] = bytesToHex(span.ParentID[:])
		}

		scopeSpans = append(scopeSpans, map[string]interface{}{
			"spans": []map[string]interface{}{otlpSpan},
		})
	}

	resourceSpans = append(resourceSpans, map[string]interface{}{
		"scope_spans": scopeSpans,
	})

	req := map[string]interface{}{
		"resourceSpans": resourceSpans,
	}

	data, _ := json.Marshal(req)
	return data
}

// sendPayload sends the payload to the OTLP collector.
func (e *OTLPExporter) sendPayload(payload []byte) error {
	endpoint := e.config.Endpoint
	if endpoint == "" {
		return nil // No endpoint configured
	}

	// Determine path based on protocol
	path := "/v1/traces"
	if e.config.Protocol == "grpc" {
		path = "/v1/traces"
	}

	url := endpoint + path
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("OTLP exporter error: %s", resp.Status)
	}

	return nil
}

// Close shuts down the exporter gracefully. Idempotent: a second
// call returns without re-closing the stop channel (would panic) or
// re-stopping the ticker (no-op but unnecessary).
func (e *OTLPExporter) Close() {
	closed := false
	e.stopOnce.Do(func() {
		close(e.stopCh)
		closed = true
	})
	if !closed {
		return
	}
	e.ticker.Stop()
	e.Flush() // Final flush
	e.wg.Wait()
}

// bytesToHex converts a byte slice to a hex string.
func bytesToHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0x0f]
	}
	return string(result)
}

// convertAttrs converts span attributes to OTLP format.
func convertAttrs(attrs []Attr) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(attrs))
	for _, attr := range attrs {
		result = append(result, map[string]interface{}{
			"key":   attr.Key,
			"value": attr.Value,
		})
	}
	return result
}

// JaegerExporter exports spans in Jaeger Thrift format.
type JaegerExporter struct {
	endpoint string
	client   *http.Client
	batch    []*Span
	batchMu  sync.Mutex
	stopCh   chan struct{}
	stopOnce sync.Once // guards Close() against second-call panic
	ticker   *time.Ticker
	wg       sync.WaitGroup
}

// NewJaegerExporter creates a Jaeger exporter with background flushing.
func NewJaegerExporter(endpoint string) *JaegerExporter {
	return newJaegerExporterWithInterval(endpoint, 5*time.Second)
}

// newJaegerExporterWithInterval lets tests pick a short flush interval
// without mutating e.ticker after the batchFlusher goroutine has
// started — which would race against the goroutine's select.
func newJaegerExporterWithInterval(endpoint string, flushInterval time.Duration) *JaegerExporter {
	e := &JaegerExporter{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 10 * time.Second},
		stopCh:   make(chan struct{}),
		ticker:   time.NewTicker(flushInterval),
	}
	e.wg.Add(1)
	go e.batchFlusher()
	return e
}

// batchFlusher periodically flushes the batch.
func (e *JaegerExporter) batchFlusher() {
	defer e.wg.Done()
	for {
		select {
		case <-e.ticker.C:
			e.Flush()
		case <-e.stopCh:
			return
		}
	}
}

// Export exports a span to Jaeger.
func (e *JaegerExporter) Export(span *Span) {
	e.batchMu.Lock()
	defer e.batchMu.Unlock()
	e.batch = append(e.batch, span)
	// Bound retention: Jaeger's batch only drains on Flush; cap it so a stalled
	// flusher can't grow it without bound.
	e.batch = capBatch(e.batch)
}

// Flush exports all pending spans to Jaeger.
func (e *JaegerExporter) Flush() {
	e.batchMu.Lock()
	defer e.batchMu.Unlock()

	if len(e.batch) == 0 {
		return
	}

	// Convert to Jaeger Thrift format (simplified JSON over HTTP)
	data, _ := json.Marshal(e.batch)
	resp, err := e.client.Post(e.endpoint+"/api/traces", "application/json", bytes.NewReader(data))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return
	}
	if resp.StatusCode >= 400 {
		return
	}

	e.batch = e.batch[:0]
}

// Close flushes and closes the exporter. Idempotent: a second call
// returns without re-closing the stop channel (would panic) or
// double-flushing. Also stops the background ticker so the time.Ticker
// goroutine isn't leaked when callers Close before process exit.
func (e *JaegerExporter) Close() {
	closed := false
	e.stopOnce.Do(func() {
		close(e.stopCh)
		closed = true
	})
	if !closed {
		return
	}
	e.wg.Wait()
	if e.ticker != nil {
		e.ticker.Stop()
	}
	e.Flush()
}
