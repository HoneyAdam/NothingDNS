package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
)

func newCacheConfigServer(t *testing.T) (*Server, *auth.User) {
	t.Helper()
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	s := NewServer(cfg, nil, cache.New(cache.Config{Capacity: 100}), nil, nil, nil, nil)
	s.authStore = store
	admin, err := store.GetUser("admin")
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}
	return s, admin
}

func putCacheConfig(t *testing.T, s *Server, admin *auth.User, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/config/cache", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(WithUser(req.Context(), admin))
	rec := httptest.NewRecorder()
	s.handleConfigCache(rec, req)
	return rec
}

// A request to DISABLE a running cache must be rejected with 400, not silently
// accepted with 200 — the cache lifecycle is fixed at startup.
func TestHandleConfigCache_RejectsRuntimeDisable(t *testing.T) {
	s, admin := newCacheConfigServer(t)
	rec := putCacheConfig(t, s, admin, `{"enabled":false}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when disabling cache at runtime, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] == "" {
		t.Errorf("expected an error message, got %v", resp)
	}
}

// Sending the current value (enabled:true) is a no-op and must be accepted, so
// the settings form (which always sends enabled) keeps working.
func TestHandleConfigCache_AcceptsEnabledTrue(t *testing.T) {
	s, admin := newCacheConfigServer(t)
	rec := putCacheConfig(t, s, admin, `{"enabled":true,"size":100,"default_ttl":300,"max_ttl":86400,"min_ttl":5,"negative_ttl":60}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for enabled:true no-op, got %d: %s", rec.Code, rec.Body.String())
	}
}

// A PUT that omits `enabled` entirely must also succeed (patch semantics).
func TestHandleConfigCache_OmittedEnabledOK(t *testing.T) {
	s, admin := newCacheConfigServer(t)
	rec := putCacheConfig(t, s, admin, `{"size":200}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 when enabled is omitted, got %d: %s", rec.Code, rec.Body.String())
	}
}

// handleServerConfig must report the real listen port and log level from the
// config getter, not the placeholder 0 / "" it used to hardcode.
func TestHandleServerConfig_PopulatesPortAndLogLevel(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	s := NewServer(cfg, nil, nil, nil, nil, nil, nil)
	s.authStore = store
	full := &config.Config{}
	full.Server.Port = 5353
	full.Logging.Level = "debug"
	s.WithConfigGetter(func() *config.Config { return full })

	admin, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/config", nil)
	req = req.WithContext(WithUser(req.Context(), admin))
	rec := httptest.NewRecorder()
	s.handleServerConfig(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp ServerConfigResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ListenPort != 5353 {
		t.Errorf("ListenPort = %d, want 5353 (was hardcoded 0)", resp.ListenPort)
	}
	if resp.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want \"debug\" (was hardcoded \"\")", resp.LogLevel)
	}
}
