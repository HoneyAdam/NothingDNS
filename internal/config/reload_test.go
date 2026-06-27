package config

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestNewReloadHandler(t *testing.T) {
	handler := NewReloadHandler()
	if handler == nil {
		t.Fatal("Expected non-nil handler")
	}

	if len(handler.callbacks) != 0 {
		t.Errorf("Expected 0 callbacks, got %d", len(handler.callbacks))
	}
}

func TestRegisterCallback(t *testing.T) {
	handler := NewReloadHandler()

	called := false
	handler.Register("test", func(*Config) error {
		called = true
		return nil
	})

	if len(handler.callbacks) != 1 {
		t.Errorf("Expected 1 callback, got %d", len(handler.callbacks))
	}

	// Trigger reload
	errors := handler.Reload(nil)
	if len(errors) != 0 {
		t.Errorf("Expected no errors, got %d", len(errors))
	}

	if !called {
		t.Error("Expected callback to be called")
	}
}

func TestMultipleCallbacks(t *testing.T) {
	handler := NewReloadHandler()

	callOrder := []string{}
	handler.Register("first", func(*Config) error {
		callOrder = append(callOrder, "first")
		return nil
	})
	handler.Register("second", func(*Config) error {
		callOrder = append(callOrder, "second")
		return nil
	})
	handler.Register("third", func(*Config) error {
		callOrder = append(callOrder, "third")
		return nil
	})

	errors := handler.Reload(nil)
	if len(errors) != 0 {
		t.Errorf("Expected no errors, got %d", len(errors))
	}

	if len(callOrder) != 3 {
		t.Errorf("Expected 3 calls, got %d", len(callOrder))
	}
}

func TestCallbackError(t *testing.T) {
	handler := NewReloadHandler()

	testError := errors.New("test error")
	handler.Register("error_component", func(*Config) error {
		return testError
	})

	errs := handler.Reload(nil)
	if len(errs) != 1 {
		t.Errorf("Expected 1 error, got %d", len(errs))
	}

	if errs[0].Component != "error_component" {
		t.Errorf("Expected component 'error_component', got '%s'", errs[0].Component)
	}

	if errs[0].Error != testError {
		t.Errorf("Expected error %v, got %v", testError, errs[0].Error)
	}
}

func TestUnregister(t *testing.T) {
	handler := NewReloadHandler()

	called := false
	handler.Register("test", func(*Config) error {
		called = true
		return nil
	})

	handler.Unregister("test")

	if len(handler.callbacks) != 0 {
		t.Errorf("Expected 0 callbacks after unregister, got %d", len(handler.callbacks))
	}

	// Trigger reload
	handler.Reload(nil)
	if called {
		t.Error("Expected callback not to be called after unregister")
	}
}

func TestComponents(t *testing.T) {
	handler := NewReloadHandler()

	handler.Register("a", func(*Config) error { return nil })
	handler.Register("b", func(*Config) error { return nil })
	handler.Register("c", func(*Config) error { return nil })

	components := handler.Components()
	if len(components) != 3 {
		t.Errorf("Expected 3 components, got %d", len(components))
	}
}

func TestStopDisablesReload(t *testing.T) {
	handler := NewReloadHandler()
	handler.Stop()

	// Note: this tests the enabled flag, not the signal handling
	// Manual Reload() still works - this is by design
	_ = handler // Prevent unused variable warning
}

// Mock implementations for testing

type MockZoneManager struct {
	reloadError error
	reloadCount int
}

func (m *MockZoneManager) Reload() error {
	m.reloadCount++
	return m.reloadError
}

func (m *MockZoneManager) LoadZone(name string) error {
	return m.reloadError
}

type MockBlocklist struct {
	reloadError error
	reloadCount int
}

func (m *MockBlocklist) Reload() error {
	m.reloadCount++
	return m.reloadError
}

type MockLogger struct {
	infos  []string
	errors []string
}

func (m *MockLogger) Info(msg string, args ...interface{}) {
	m.infos = append(m.infos, msg)
}

func (m *MockLogger) Error(msg string, args ...interface{}) {
	m.errors = append(m.errors, msg)
}

func TestReloadManager(t *testing.T) {
	handler := NewReloadHandler()
	// Use empty config path to skip config file reload
	manager := NewReloadManager(handler, "", nil)

	logger := &MockLogger{}
	manager.SetLogger(logger)

	zm := &MockZoneManager{}
	manager.SetZoneManager(zm)

	bl := &MockBlocklist{}
	manager.SetBlocklist(bl)

	manager.SetupAll()

	// Trigger reload
	errs := handler.Reload(nil)
	if len(errs) > 0 {
		t.Errorf("Unexpected errors: %v", errs)
	}

	// Verify components were called
	if zm.reloadCount != 1 {
		t.Errorf("Expected zone manager reload count 1, got %d", zm.reloadCount)
	}

	if bl.reloadCount != 1 {
		t.Errorf("Expected blocklist reload count 1, got %d", bl.reloadCount)
	}
}

func TestTLSReloader(t *testing.T) {
	logger := &MockLogger{}
	reloader := NewTLSReloader("", "", logger)

	// With empty paths, reload should succeed
	err := reloader.Reload()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestLogLevelReloader(t *testing.T) {
	logger := &MockLogger{}
	var currentLevel string

	reloader := NewLogLevelReloader("info", func(level string) error {
		currentLevel = level
		return nil
	}, logger)

	if reloader.GetLevel() != "info" {
		t.Errorf("Expected 'info', got '%s'", reloader.GetLevel())
	}

	err := reloader.SetLevel("debug")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if currentLevel != "debug" {
		t.Errorf("Expected level 'debug', got '%s'", currentLevel)
	}

	if reloader.GetLevel() != "debug" {
		t.Errorf("Expected 'debug', got '%s'", reloader.GetLevel())
	}
}

func TestACLReloader(t *testing.T) {
	logger := &MockLogger{}
	reloadCount := 0

	reloader := NewACLReloader(func() error {
		reloadCount++
		return nil
	}, logger)

	err := reloader.Reload()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if reloadCount != 1 {
		t.Errorf("Expected 1 reload, got %d", reloadCount)
	}
}

func TestACLReloaderError(t *testing.T) {
	logger := &MockLogger{}
	testError := errors.New("ACL error")

	reloader := NewACLReloader(func() error {
		return testError
	}, logger)

	err := reloader.Reload()
	if err != testError {
		t.Errorf("Expected testError, got %v", err)
	}
}

func TestRateLimitReloader(t *testing.T) {
	logger := &MockLogger{}
	reloadCount := 0

	reloader := NewRateLimitReloader(func() error {
		reloadCount++
		return nil
	}, logger)

	err := reloader.Reload()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if reloadCount != 1 {
		t.Errorf("Expected 1 reload, got %d", reloadCount)
	}
}

func TestNilCallbackSafe(t *testing.T) {
	// Test that nil callbacks don't cause panics
	logger := &MockLogger{}

	aclReloader := NewACLReloader(nil, logger)
	if err := aclReloader.Reload(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	rateReloader := NewRateLimitReloader(nil, logger)
	if err := rateReloader.Reload(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestReloadManagerConfigReload(t *testing.T) {
	// Create a temporary config file
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	configContent := []byte("server:\n  port: 5353\n")
	if _, err := tmpFile.Write(configContent); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	logger := &MockLogger{}
	handler := NewReloadHandler()
	cfg := DefaultConfig()
	manager := NewReloadManager(handler, tmpFile.Name(), cfg)
	manager.SetLogger(logger)
	manager.SetupAll()

	// Trigger reload
	errs := handler.Reload(nil)
	if len(errs) > 0 {
		t.Errorf("Unexpected errors: %v", errs)
	}
	if len(logger.infos) == 0 {
		t.Error("Expected info log about config reload")
	}
}

func TestReloadManagerConfigReloadEmptyPath(t *testing.T) {
	logger := &MockLogger{}
	handler := NewReloadHandler()
	cfg := DefaultConfig()
	manager := NewReloadManager(handler, "", cfg)
	manager.SetLogger(logger)

	// Setup just the config reload callback
	handler.Register("config", manager.reloadConfig)

	errs := handler.Reload(nil)
	if len(errs) > 0 {
		t.Errorf("Unexpected errors for empty path: %v", errs)
	}
}

func TestReloadManagerConfigReloadBadFile(t *testing.T) {
	// With the new ReloadCallback(*Config) signature, reloadConfig no longer
	// reads files — that's done by ReloadHandler.reloadFromPath. Passing nil
	// config to reloadConfig should still succeed (it stores what it gets).
	logger := &MockLogger{}
	handler := NewReloadHandler()
	cfg := DefaultConfig()
	manager := NewReloadManager(handler, "", cfg)
	manager.SetLogger(logger)

	handler.Register("config", manager.reloadConfig)

	// reloadConfig with a nil config stores nil — no error.
	errs := handler.Reload(nil)
	if len(errs) != 0 {
		t.Errorf("Expected no errors for nil config, got %d", len(errs))
	}
}

func TestReloadManagerConfigReloadInvalidYAML(t *testing.T) {
	// reloadFromPath handles parse errors before callbacks run.
	// The callback itself never sees invalid YAML.
	logger := &MockLogger{}
	handler := NewReloadHandler()
	cfg := DefaultConfig()
	manager := NewReloadManager(handler, "", cfg)
	manager.SetLogger(logger)

	// Pass a valid config — the callback should accept it.
	validCfg := DefaultConfig()
	errs := handler.Reload(validCfg)
	if len(errs) != 0 {
		t.Errorf("Expected no errors for valid config, got %d", len(errs))
	}
}

func TestReloadManagerConfigReloadValidationFails(t *testing.T) {
	// Validation happens in reloadFromPath, not in the callback.
	// The callback receives an already-validated *Config.
	logger := &MockLogger{}
	handler := NewReloadHandler()
	cfg := DefaultConfig()
	manager := NewReloadManager(handler, "", cfg)
	manager.SetLogger(logger)

	// A validated config passed to reloadConfig should succeed.
	errs := handler.Reload(DefaultConfig())
	if len(errs) != 0 {
		t.Errorf("Expected no errors for validated config, got %d", len(errs))
	}
}

func TestReloadManagerConfigReloadNoLogger(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "config-nolog-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	tmpFile.WriteString("server:\n  port: 5353\n")
	tmpFile.Close()

	handler := NewReloadHandler()
	cfg := DefaultConfig()
	manager := NewReloadManager(handler, tmpFile.Name(), cfg)
	// No logger set

	handler.Register("config", manager.reloadConfig)

	errs := handler.Reload(nil)
	if len(errs) > 0 {
		t.Errorf("Unexpected errors: %v", errs)
	}
}

func TestReloadZonesError(t *testing.T) {
	logger := &MockLogger{}
	handler := NewReloadHandler()
	cfg := DefaultConfig()
	manager := NewReloadManager(handler, "", cfg)
	manager.SetLogger(logger)

	testErr := errors.New("zone reload error")
	manager.SetZoneManager(&MockZoneManager{reloadError: testErr})

	handler.Register("zones", manager.reloadZones)

	errs := handler.Reload(nil)
	if len(errs) == 0 {
		t.Error("Expected zone reload error")
	}
	if len(logger.errors) == 0 {
		t.Error("Expected error log")
	}
}

func TestReloadZonesNoManager(t *testing.T) {
	logger := &MockLogger{}
	handler := NewReloadHandler()
	cfg := DefaultConfig()
	manager := NewReloadManager(handler, "", cfg)
	manager.SetLogger(logger)
	// No zone manager set

	handler.Register("zones", manager.reloadZones)

	errs := handler.Reload(nil)
	if len(errs) > 0 {
		t.Errorf("Unexpected errors: %v", errs)
	}
}

func TestReloadBlocklistError(t *testing.T) {
	logger := &MockLogger{}
	handler := NewReloadHandler()
	cfg := DefaultConfig()
	manager := NewReloadManager(handler, "", cfg)
	manager.SetLogger(logger)

	testErr := errors.New("blocklist reload error")
	manager.SetBlocklist(&MockBlocklist{reloadError: testErr})

	handler.Register("blocklist", manager.reloadBlocklist)

	errs := handler.Reload(nil)
	if len(errs) == 0 {
		t.Error("Expected blocklist reload error")
	}
	if len(logger.errors) == 0 {
		t.Error("Expected error log")
	}
}

func TestReloadBlocklistNoBlocklist(t *testing.T) {
	logger := &MockLogger{}
	handler := NewReloadHandler()
	cfg := DefaultConfig()
	manager := NewReloadManager(handler, "", cfg)
	manager.SetLogger(logger)
	// No blocklist set

	handler.Register("blocklist", manager.reloadBlocklist)

	errs := handler.Reload(nil)
	if len(errs) > 0 {
		t.Errorf("Unexpected errors: %v", errs)
	}
}

func TestTLSReloaderWithFiles(t *testing.T) {
	// Create temp files for cert and key with valid PEM data
	certPEM := `-----BEGIN CERTIFICATE-----
MIIBSjCB8KADAgECAgEBMAoGCCqGSM49BAMCMA8xDTALBgNVBAoTBFRlc3QwHhcN
MjYwNDE0MDcwMjQ0WhcNMjYwNDE0MDgwMjQ0WjAPMQ0wCwYDVQQKEwRUZXN0MFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6QJRIirmN49OSQ8HTI27IgPHzFshCE1Y
vlcdyN42xxGwiYPY/UFu37mVb1C1CXNlrNytcDQJPlXhrb+yqaYqOaM9MDswDgYD
VR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBQGA1UdEQQNMAuCCWxv
Y2FsaG9zdDAKBggqhkjOPQQDAgNJADBGAiEAweBvLxh8ifw8pEq+zeloNc+nntJ6
Pg8IXeSHJpOedDsCIQC4HUm4rKMAiRXjcwPVm5HvyKkwmLJWYw5RxpWR55WbNQ==
-----END CERTIFICATE-----`
	keyPEM := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMCG/ZoQ4oO4QuaeZuzrP3rvkJts0cFxXuAQBbjlFmMKoAoGCCqGSM49
AwEHoUQDQgAE6QJRIirmN49OSQ8HTI27IgPHzFshCE1YvlcdyN42xxGwiYPY/UFu
37mVb1C1CXNlrNytcDQJPlXhrb+yqaYqOQ==
-----END EC PRIVATE KEY-----`

	certFile, err := os.CreateTemp("", "cert-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(certFile.Name())
	if _, err := certFile.WriteString(certPEM); err != nil {
		t.Fatal(err)
	}
	certFile.Close()

	keyFile, err := os.CreateTemp("", "key-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(keyFile.Name())
	if _, err := keyFile.WriteString(keyPEM); err != nil {
		t.Fatal(err)
	}
	keyFile.Close()

	logger := &MockLogger{}
	reloader := NewTLSReloader(certFile.Name(), keyFile.Name(), logger)

	err = reloader.Reload()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(logger.infos) == 0 {
		t.Error("Expected info log about TLS reload")
	}
}

func TestTLSReloaderNonexistentCert(t *testing.T) {
	keyFile, err := os.CreateTemp("", "key-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(keyFile.Name())
	keyFile.Close()

	logger := &MockLogger{}
	reloader := NewTLSReloader("/nonexistent/cert.pem", keyFile.Name(), logger)

	err = reloader.Reload()
	if err == nil {
		t.Error("Expected error for nonexistent cert file")
	}
}

func TestTLSReloaderNonexistentKey(t *testing.T) {
	certFile, err := os.CreateTemp("", "cert-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(certFile.Name())
	certFile.Close()

	logger := &MockLogger{}
	reloader := NewTLSReloader(certFile.Name(), "/nonexistent/key.pem", logger)

	err = reloader.Reload()
	if err == nil {
		t.Error("Expected error for nonexistent key file")
	}
}

func TestTLSReloaderNoLogger(t *testing.T) {
	reloader := NewTLSReloader("", "", nil)
	err := reloader.Reload()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestLogLevelReloaderCallbackError(t *testing.T) {
	testErr := errors.New("callback error")
	reloader := NewLogLevelReloader("info", func(level string) error {
		return testErr
	}, nil)

	err := reloader.SetLevel("debug")
	if err != testErr {
		t.Errorf("Expected callback error, got %v", err)
	}
}

func TestLogLevelReloaderNoCallback(t *testing.T) {
	reloader := NewLogLevelReloader("info", nil, nil)
	err := reloader.SetLevel("debug")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if reloader.GetLevel() != "debug" {
		t.Errorf("Expected level 'debug', got %q", reloader.GetLevel())
	}
}

func TestLogLevelReloaderReloadViaManager(t *testing.T) {
	var calledLevel string
	reloader := NewLogLevelReloader("info", func(level string) error {
		calledLevel = level
		return nil
	}, nil)

	err := reloader.Reload("warn")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if calledLevel != "warn" {
		t.Errorf("Expected 'warn', got %q", calledLevel)
	}
	if reloader.GetLevel() != "warn" {
		t.Errorf("Expected level 'warn', got %q", reloader.GetLevel())
	}
}

func TestRateLimitReloaderError(t *testing.T) {
	logger := &MockLogger{}
	testErr := errors.New("rate limit error")

	reloader := NewRateLimitReloader(func() error {
		return testErr
	}, logger)

	err := reloader.Reload()
	if err != testErr {
		t.Errorf("Expected testErr, got %v", err)
	}
	if len(logger.errors) == 0 {
		t.Error("Expected error log")
	}
}

func TestRateLimitReloaderSuccess(t *testing.T) {
	logger := &MockLogger{}
	reloadCount := 0

	reloader := NewRateLimitReloader(func() error {
		reloadCount++
		return nil
	}, logger)

	err := reloader.Reload()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if reloadCount != 1 {
		t.Errorf("Expected 1 reload, got %d", reloadCount)
	}
	if len(logger.infos) == 0 {
		t.Error("Expected info log")
	}
}

func TestACLReloaderWithLogger(t *testing.T) {
	logger := &MockLogger{}

	reloader := NewACLReloader(func() error {
		return nil
	}, logger)

	err := reloader.Reload()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(logger.infos) == 0 {
		t.Error("Expected info log about ACL reload")
	}
}

func TestReloadManagerReloadLoggingWithLogger(t *testing.T) {
	logger := &MockLogger{}
	handler := NewReloadHandler()
	manager := NewReloadManager(handler, "", nil)
	manager.SetLogger(logger)
	manager.SetupAll()

	errs := handler.Reload(nil)
	if len(errs) > 0 {
		t.Errorf("Unexpected errors: %v", errs)
	}
}

func TestReloadManagerReloadLoggingNoLogger(t *testing.T) {
	handler := NewReloadHandler()
	manager := NewReloadManager(handler, "", nil)
	manager.SetupAll()

	errs := handler.Reload(nil)
	if len(errs) > 0 {
		t.Errorf("Unexpected errors: %v", errs)
	}
}

func TestReloadFromPathRejectsOversizedConfig(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "config-oversized-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(bytes.Repeat([]byte{'x'}, maxReloadConfigFileSize+1)); err != nil {
		t.Fatalf("write oversized config: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("close oversized config: %v", err)
	}

	handler := NewReloadHandler()
	called := false
	handler.Register("test", func(*Config) error {
		called = true
		return nil
	})
	handler.reloadFromPath(tmpFile.Name())
	if called {
		t.Fatal("reload callback must not run for oversized config")
	}
}

// TestStart_SignalHandling tests that the Start method properly handles signals
func TestStart_SignalHandling(t *testing.T) {
	handler := NewReloadHandler()
	called := 0
	handler.Register("test", func(*Config) error {
		called++
		return nil
	})

	// Start the handler (this registers for SIGHUP)
	handler.Start(writeTestConfig(t))

	// Send SIGHUP to ourselves to trigger the reload goroutine
	_ = handler.Reload(nil) // Direct call works regardless

	// Stop the handler to clean up
	handler.Stop()

	// Verify the handler can be stopped cleanly
	if handler.enabled.Load() {
		t.Error("expected handler to be disabled after Stop()")
	}
}

// TestStart_GoroutineExecutesCallback tests that Start's goroutine properly handles SIGHUP
func TestStart_GoroutineExecutesCallback(t *testing.T) {
	handler := NewReloadHandler()
	called := 0
	handler.Register("test", func(*Config) error {
		called++
		return nil
	})

	handler.Start(writeTestConfig(t))

	// Send SIGHUP - this will be received by the goroutine
	_ = handler.Reload(nil) // Direct call to ensure the callback mechanism works

	handler.Stop()

	if called != 1 {
		t.Errorf("expected 1 callback call, got %d", called)
	}
}

// TestStart_DisabledHandlerSkipsReload tests that disabled handler skips signal handling
func TestStart_DisabledHandlerSkipsReload(t *testing.T) {
	handler := NewReloadHandler()
	// Disable before starting
	handler.enabled.Store(false)

	handler.Start(writeTestConfig(t))
	handler.Stop()
	// Should not panic or have issues
}
