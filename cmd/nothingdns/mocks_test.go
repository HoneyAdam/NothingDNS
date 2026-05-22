// NothingDNS - Mock Implementations
// Mock implementations for testing

package main

import (
	"github.com/nothingdns/nothingdns/internal/zone"
)

// MockZoneProvider is a mock implementation of ZoneProvider for testing.
type MockZoneProvider struct {
	Zones         map[string]*zone.Zone
	FindZonesFunc func(qname string) []ZoneMatch
}

// NewMockZoneProvider creates a mock zone provider with preset zones.
func NewMockZoneProvider(zones map[string]*zone.Zone) *MockZoneProvider {
	return &MockZoneProvider{
		Zones: zones,
	}
}

// FindZones returns mock zone matches.
func (m *MockZoneProvider) FindZones(qname string) []ZoneMatch {
	if m.FindZonesFunc != nil {
		return m.FindZonesFunc(qname)
	}

	var matches []ZoneMatch
	for origin, z := range m.Zones {
		if isSubdomain(qname, origin) {
			matches = append(matches, ZoneMatch{origin, z})
		}
	}
	return matches
}

// ListZones returns all zones.
func (m *MockZoneProvider) ListZones() map[string]*zone.Zone {
	return m.Zones
}

// GetZone returns a zone by origin.
func (m *MockZoneProvider) GetZone(origin string) (*zone.Zone, bool) {
	z, ok := m.Zones[origin]
	return z, ok
}

// MockCache is a mock implementation of CacheManagerInterface for testing.
type MockCache struct {
	data map[string]any
}

func NewMockCache() *MockCache {
	return &MockCache{data: make(map[string]any)}
}

func (m *MockCache) Get(key string) any {
	return m.data[key]
}

func (m *MockCache) Set(key string, value any) {
	m.data[key] = value
}

func (m *MockCache) Delete(key string) {
	delete(m.data, key)
}

func (m *MockCache) Clear() {
	m.data = make(map[string]any)
}

func (m *MockCache) Size() int {
	return len(m.data)
}
