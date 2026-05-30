package api

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/blocklist"
)

func TestBlocklistService_GetStats_NilBlocklist(t *testing.T) {
	s := NewBlocklistService(nil)
	stats := s.GetStats()
	if stats.Enabled {
		t.Error("Expected Enabled=false for nil blocklist")
	}
	if stats.TotalRules != 0 {
		t.Errorf("Expected TotalRules=0, got %d", stats.TotalRules)
	}
}

func TestBlocklistService_IsBlocked_NilBlocklist(t *testing.T) {
	s := NewBlocklistService(nil)
	if s.IsBlocked("example.com") {
		t.Error("Expected false for nil blocklist")
	}
}

func TestBlocklistService_Toggle_NilBlocklist(t *testing.T) {
	s := NewBlocklistService(nil)
	if s.Toggle() {
		t.Error("Expected false for nil blocklist")
	}
}

func TestBlocklistService_Available(t *testing.T) {
	if NewBlocklistService(nil).Available() {
		t.Error("Expected false for nil blocklist")
	}
	bl := blocklist.New(blocklist.Config{Enabled: true})
	if !NewBlocklistService(bl).Available() {
		t.Error("Expected true for real blocklist")
	}
}
