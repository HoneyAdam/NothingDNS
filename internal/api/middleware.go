package api

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// rateLimitMiddleware applies per-IP rate limiting before auth runs.
// This ensures that unauthenticated scan/brute-force attempts also consume
// rate-limit budget (VULN-055). Rate-limited responses use writeErrorJSON
// for consistent JSON shape.
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply rate limit to all /api/ requests regardless of auth status.
		// DoWS has its own in-path rate limit (see authMiddleware).
		if strings.HasPrefix(r.URL.Path, "/api/") {
			ip := getClientIP(r)
			if s.apiRateLimiter.checkRateLimit(ip) {
				resetTime := s.apiRateLimiter.getResetTime(ip)
				w.Header().Set("Retry-After", retryAfterSeconds(resetTime))
				writeErrorJSON(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs every HTTP request: method, path, status, latency.
// Logs at Info level for non-GET, Debug for GET health checks.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		latency := time.Since(start)
		status := wrapped.status
		path := r.URL.Path
		if path == "/health" || path == "/livez" || path == "/readyz" {
			util.Debugf("%s %s %d %v", r.Method, path, status, latency)
		} else {
			util.Infof("%s %s %d %v", r.Method, path, status, latency)
		}
	})
}

// statusRecorder wraps http.ResponseWriter to capture the actual status code
// written, since the status may be set after the call to WriteHeader.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == http.StatusOK && r.Header().Get("Content-Type") == "" {
		// WriteHeader may not have been called; set OK as default
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijacking")
	}
	return hijacker.Hijack()
}
