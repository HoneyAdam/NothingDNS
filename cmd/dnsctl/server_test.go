package main

import (
	"testing"
)

func TestLookupConfigPath(t *testing.T) {
	data := map[string]interface{}{
		"Server": map[string]interface{}{
			"Port": 53,
			"Name": "test",
		},
		"Logging": map[string]interface{}{
			"Level": "info",
		},
	}

	// Basic nested lookup
	v, ok := lookupConfigPath(data, "Server.Port")
	if !ok || v != 53 {
		t.Errorf("Server.Port = %v, want 53", v)
	}

	// Case-insensitive lookup
	v, ok = lookupConfigPath(data, "server.port")
	if !ok || v != 53 {
		t.Errorf("server.port = %v, want 53", v)
	}

	// String value
	v, ok = lookupConfigPath(data, "Logging.Level")
	if !ok || v != "info" {
		t.Errorf("Logging.Level = %v, want info", v)
	}

	// Non-existent path
	_, ok = lookupConfigPath(data, "Server.Nonexistent")
	if ok {
		t.Error("expected false for nonexistent path")
	}

	// Empty path returns root
	v, ok = lookupConfigPath(data, "")
	if !ok || v == nil {
		t.Errorf("empty path = %v, want root", v)
	}

	// Walk into non-map returns false
	_, ok = lookupConfigPath(data, "Server.Port.Inner")
	if ok {
		t.Error("expected false when walking into non-map")
	}

	// Nil root
	_, ok = lookupConfigPath(nil, "path")
	if ok {
		t.Error("expected false for nil root")
	}
}
