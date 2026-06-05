package api

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/cache"
)

func TestCacheService_GetStats_NilCache(t *testing.T) {
	s := NewCacheService(nil)
	stats := s.GetStats()
	if stats.Size != 0 {
		t.Errorf("Expected size 0, got %d", stats.Size)
	}
}

func TestCacheService_GetStats_WithCache(t *testing.T) {
	c := cache.New(cache.Config{Capacity: 1000})
	c.Stats() // populate some stats
	s := NewCacheService(c)
	stats := s.GetStats()
	if stats.Capacity == 0 {
		t.Error("Expected non-zero capacity")
	}
}

func TestCacheService_Flush_NilCache(t *testing.T) {
	s := NewCacheService(nil)
	if err := s.Flush(); err != nil {
		t.Errorf("Flush on nil cache returned error: %v", err)
	}
}

func TestCacheService_Flush_WithCache(t *testing.T) {
	c := cache.New(cache.Config{Capacity: 1000})
	s := NewCacheService(c)
	if err := s.Flush(); err != nil {
		t.Errorf("Flush returned error: %v", err)
	}
}

func TestCacheService_Available(t *testing.T) {
	if NewCacheService(nil).Available() {
		t.Error("Expected false for nil cache")
	}
	c := cache.New(cache.Config{Capacity: 1000})
	if !NewCacheService(c).Available() {
		t.Error("Expected true for real cache")
	}
}
