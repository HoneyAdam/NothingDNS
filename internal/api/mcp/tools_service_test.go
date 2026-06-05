package mcp

import (
	"encoding/json"
	"testing"

	"github.com/nothingdns/nothingdns/internal/api"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// TestCallZoneList_ViaZoneService tests that zone_list uses ZoneService.ListZones().
func TestCallZoneList_ViaZoneService(t *testing.T) {
	zm := zone.NewManager()
	zs := api.NewZoneService(zm)
	h := NewDNSToolsHandler(zs, nil, nil, nil, nil, nil)

	result, err := h.CallTool("zone_list", nil)
	if err != nil {
		t.Fatalf("CallTool zone_list failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("Expected non-error result, got: %+v", result)
	}

	var resp api.ZoneListResponse
	if err := json.Unmarshal([]byte(result.Content[0].Text), &resp); err != nil {
		t.Fatalf("Failed to parse zone_list response: %v", err)
	}
	if resp.Total != 0 {
		t.Fatalf("Expected 0 zones, got %d", resp.Total)
	}
}

// TestCallZoneGet_ViaZoneService tests that zone_get uses ZoneService.GetZone()
// (returns IsError for nonexistent zone via ZoneService).
func TestCallZoneGet_ViaZoneService(t *testing.T) {
	zm := zone.NewManager()
	zs := api.NewZoneService(zm)
	h := NewDNSToolsHandler(zs, nil, nil, nil, nil, nil)

	result, err := h.CallTool("zone_get", map[string]interface{}{"name": "nonexistent"})
	if err != nil {
		t.Fatalf("CallTool zone_get failed: %v", err)
	}
	if !result.IsError {
		t.Error("Expected error result for nonexistent zone")
	}
}

// TestCallZoneList_NilService tests that a nil zoneService produces an error result.
func TestCallZoneList_NilService(t *testing.T) {
	h := NewDNSToolsHandler(nil, nil, nil, nil, nil, nil)

	result, err := h.CallTool("zone_list", nil)
	if err != nil {
		t.Fatalf("CallTool zone_list failed: %v", err)
	}
	if !result.IsError {
		t.Error("Expected error result when zone service is nil")
	}
}

// TestCallZoneGet_NilService tests that a nil zoneService produces an error result.
func TestCallZoneGet_NilService(t *testing.T) {
	h := NewDNSToolsHandler(nil, nil, nil, nil, nil, nil)

	result, err := h.CallTool("zone_get", map[string]interface{}{"name": "example.com"})
	if err != nil {
		t.Fatalf("CallTool zone_get failed: %v", err)
	}
	if !result.IsError {
		t.Error("Expected error result when zone service is nil")
	}
}

// TestListResources_ViaZoneService tests that ListResources uses ZoneService.
func TestListResources_ViaZoneService(t *testing.T) {
	zm := zone.NewManager()
	zs := api.NewZoneService(zm)
	h := NewDNSToolsHandler(zs, nil, nil, nil, nil, nil)

	resources, err := h.ListResources()
	if err != nil {
		t.Fatalf("ListResources failed: %v", err)
	}
	// No zones loaded — should return server/status + cache/stats only
	if len(resources) != 2 {
		t.Errorf("Expected 2 resources (server/status + cache/stats), got %d", len(resources))
	}
}

// TestReadResource_Zone_ViaZoneService tests that ReadResource uses ZoneService.
func TestReadResource_Zone_ViaZoneService(t *testing.T) {
	zm := zone.NewManager()
	zs := api.NewZoneService(zm)
	h := NewDNSToolsHandler(zs, nil, nil, nil, nil, nil)

	_, err := h.ReadResource("dns://zone/nonexistent.com")
	if err == nil {
		t.Error("Expected error for nonexistent zone, got nil")
	}
}

// TestReadResource_InvalidScheme tests ReadResource error handling.
func TestReadResource_InvalidScheme(t *testing.T) {
	h := NewDNSToolsHandler(nil, nil, nil, nil, nil, nil)

	_, err := h.ReadResource("http://example.com")
	if err == nil {
		t.Error("Expected error for invalid scheme")
	}
}
