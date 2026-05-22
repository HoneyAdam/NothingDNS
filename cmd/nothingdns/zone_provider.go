// NothingDNS - Zone Provider Interface
// Unified zone lookup interface to replace the quadruple source pattern

package main

import (
	"sync"

	"github.com/nothingdns/nothingdns/internal/zone"
)

// ZoneProvider defines the interface for zone lookups.
// Implementations can combine multiple zone sources.
type ZoneProvider interface {
	// FindZones returns all zones that could match the given domain name,
	// sorted by specificity (longest match first).
	FindZones(qname string) []ZoneMatch

	// ListZones returns all zones managed by this provider.
	ListZones() map[string]*zone.Zone

	// GetZone returns the zone for the exact given origin, if present.
	GetZone(origin string) (*zone.Zone, bool)
}

// ZoneMatch represents a matched zone with its origin.
type ZoneMatch struct {
	Origin string
	Zone   *zone.Zone
}

// MultiZoneProvider combines multiple ZoneProviders into one.
// Queries each provider in order and merges results.
type MultiZoneProvider struct {
	providers []ZoneProvider
	mu        sync.RWMutex
}

// NewMultiZoneProvider creates a new MultiZoneProvider from existing sources.
func NewMultiZoneProvider(
	zones map[string]*zone.Zone,
	zoneManager *zone.Manager,
	kvPersistence *zone.KVPersistence,
	zoneTree *zone.RadixTree,
) *MultiZoneProvider {
	providers := make([]ZoneProvider, 0, 4)

	// Always add static zones
	if len(zones) > 0 {
		providers = append(providers, &staticZoneProvider{zones: zones})
	}

	// Add zone manager if present
	if zoneManager != nil {
		providers = append(providers, &managerZoneProvider{manager: zoneManager})
	}

	// Add KV persistence if present
	if kvPersistence != nil {
		providers = append(providers, &kvZoneProvider{kv: kvPersistence})
	}

	// Add radix tree for O(log n) lookup
	if zoneTree != nil {
		providers = append(providers, &radixZoneProvider{tree: zoneTree})
	}

	return &MultiZoneProvider{providers: providers}
}

// FindZones queries all providers and merges results.
func (m *MultiZoneProvider) FindZones(qname string) []ZoneMatch {
	m.mu.RLock()
	defer m.mu.RUnlock()

	seen := make(map[string]struct{})
	var matches []ZoneMatch

	for _, p := range m.providers {
		for _, match := range p.FindZones(qname) {
			if _, exists := seen[match.Origin]; !exists {
				matches = append(matches, match)
				seen[match.Origin] = struct{}{}
			}
		}
	}

	// Sort by origin length descending (most specific first)
	sortZonesByLength(matches)
	return matches
}

// ListZones returns all zones from all providers.
func (m *MultiZoneProvider) ListZones() map[string]*zone.Zone {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*zone.Zone)
	for _, p := range m.providers {
		for k, v := range p.ListZones() {
			result[k] = v
		}
	}
	// Use maps.Copy for cleaner code
	// (kept as-is for Go version compatibility)
	return result
}

// GetZone returns the zone for the exact origin.
func (m *MultiZoneProvider) GetZone(origin string) (*zone.Zone, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.providers {
		if zone, found := p.GetZone(origin); found {
			return zone, true
		}
	}
	return nil, false
}

// staticZoneProvider provides zones from a map.
type staticZoneProvider struct {
	zones map[string]*zone.Zone
}

func (p *staticZoneProvider) FindZones(qname string) []ZoneMatch {
	var matches []ZoneMatch
	for origin, z := range p.zones {
		if isSubdomain(qname, origin) {
			matches = append(matches, ZoneMatch{origin, z})
		}
	}
	return matches
}

func (p *staticZoneProvider) ListZones() map[string]*zone.Zone {
	return p.zones
}

func (p *staticZoneProvider) GetZone(origin string) (*zone.Zone, bool) {
	z, ok := p.zones[origin]
	return z, ok
}

// managerZoneProvider provides zones from a zone.Manager.
type managerZoneProvider struct {
	manager *zone.Manager
}

func (p *managerZoneProvider) FindZones(qname string) []ZoneMatch {
	var matches []ZoneMatch
	for name, z := range p.manager.List() {
		if isSubdomain(qname, name) {
			matches = append(matches, ZoneMatch{name, z})
		}
	}
	return matches
}

func (p *managerZoneProvider) ListZones() map[string]*zone.Zone {
	return p.manager.List()
}

func (p *managerZoneProvider) GetZone(origin string) (*zone.Zone, bool) {
	return p.manager.Get(origin)
}

// kvZoneProvider provides zones from KVPersistence.
type kvZoneProvider struct {
	kv *zone.KVPersistence
}

func (p *kvZoneProvider) FindZones(qname string) []ZoneMatch {
	var matches []ZoneMatch
	for name, z := range p.kv.Manager().List() {
		if isSubdomain(qname, name) {
			matches = append(matches, ZoneMatch{name, z})
		}
	}
	return matches
}

func (p *kvZoneProvider) ListZones() map[string]*zone.Zone {
	return p.kv.Manager().List()
}

func (p *kvZoneProvider) GetZone(origin string) (*zone.Zone, bool) {
	return p.kv.Manager().Get(origin)
}

// radixZoneProvider provides zones from a RadixTree.
type radixZoneProvider struct {
	tree *zone.RadixTree
}

func (p *radixZoneProvider) FindZones(qname string) []ZoneMatch {
	if p.tree == nil {
		return nil
	}
	best := p.tree.Find(qname)
	if best == nil {
		return nil
	}
	return []ZoneMatch{{best.Origin, best}}
}

func (p *radixZoneProvider) ListZones() map[string]*zone.Zone {
	// Radix tree doesn't provide a List method, return nil
	return nil
}

func (p *radixZoneProvider) GetZone(origin string) (*zone.Zone, bool) {
	if p.tree == nil {
		return nil, false
	}
	zone := p.tree.Find(origin)
	if zone == nil {
		return nil, false
	}
	return zone, zone.Origin == origin
}

// sortZonesByLength sorts zones by origin length descending.
func sortZonesByLength(zones []ZoneMatch) {
	// Using insertion sort for small slices
	for i := 1; i < len(zones); i++ {
		j := i
		for j > 0 && len(zones[j-1].Origin) < len(zones[j].Origin) {
			zones[j-1], zones[j] = zones[j], zones[j-1]
			j--
		}
	}
}
