package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ---------------------------------------------------------------------------
// handleBulkPTR
// ---------------------------------------------------------------------------

func newServerWithReverseZone(t *testing.T) (*Server, *auth.User) {
	return newServerWithReverseZoneOrigin(t, "1.168.192.in-addr.arpa.")
}

func newServerWithReverseZoneOrigin(t *testing.T, origin string) (*Server, *auth.User) {
	t.Helper()
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.zoneManager = zone.NewManager()

	// Create a reverse zone for bulk PTR tests.
	soa := &zone.SOARecord{
		TTL:     3600,
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}
	nsRecords := []zone.NSRecord{
		{TTL: 3600, NSDName: "ns1.example.com."},
	}
	if err := s.zoneManager.CreateZone(origin, 3600, soa, nsRecords); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}

	user, _ := store.GetUser("admin")
	return s, user
}

func TestHandleBulkPTR_Preview(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"192.168.1.0/30","pattern":"host-[A]-[B]-[C]-[D].example.com.","preview":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	if resp["preview"] != true {
		t.Error("expected preview=true")
	}
	if resp["total"] != float64(4) { // /30 = 4 IPs
		t.Errorf("expected total=4, got %v", resp["total"])
	}
	if resp["willAdd"] != float64(4) {
		t.Errorf("expected willAdd=4, got %v", resp["willAdd"])
	}
}

func TestHandleBulkPTR_Apply(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"192.168.1.0/30","pattern":"host-[A]-[B]-[C]-[D].example.com."}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	if resp["added"] != float64(4) {
		t.Errorf("expected added=4, got %v", resp["added"])
	}
}

func TestHandleBulkPTR_ApplyUsesReverseRelativeOwnerInParentZone(t *testing.T) {
	s, user := newServerWithReverseZoneOrigin(t, "168.192.in-addr.arpa.")

	body := `{"cidr":"192.168.1.0/30","pattern":"host-[A]-[B]-[C]-[D].example.com."}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	z, ok := s.zoneManager.Get("168.192.in-addr.arpa.")
	if !ok {
		t.Fatal("expected reverse zone")
	}
	z.RLock()
	records := append([]zone.Record(nil), z.Records["0.1.168.192.in-addr.arpa."]...)
	wrongRecords := append([]zone.Record(nil), z.Records["1.0.168.192.in-addr.arpa."]...)
	z.RUnlock()

	if len(records) != 1 {
		t.Fatalf("expected PTR at 0.1.168.192.in-addr.arpa., got %d records", len(records))
	}
	if records[0].Type != "PTR" || records[0].RData != "host-192-168-1-0.example.com." {
		t.Fatalf("unexpected PTR record: %+v", records[0])
	}
	if len(wrongRecords) != 0 {
		t.Fatalf("unexpected PTR at old reversed owner 1.0.168.192.in-addr.arpa.: %+v", wrongRecords)
	}
}

func TestHandleBulkPTR_PreviewFindsExistingPTRByOwner(t *testing.T) {
	s, user := newServerWithReverseZone(t)
	if err := s.zoneManager.AddRecord("1.168.192.in-addr.arpa.", zone.Record{
		Name:  "0",
		Type:  "PTR",
		Class: "IN",
		TTL:   3600,
		RData: "existing.example.com.",
	}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	body := `{"cidr":"192.168.1.0/32","pattern":"host-[A]-[B]-[C]-[D].example.com.","preview":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp ReverseDNSPreviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	if resp.WillSkip != 1 || resp.WillAdd != 0 {
		t.Fatalf("preview counts: willSkip=%d willAdd=%d, want 1/0", resp.WillSkip, resp.WillAdd)
	}
	if len(resp.Changes) != 1 || !resp.Changes[0].PTRExist || resp.Changes[0].OldPTR != "existing.example.com." {
		t.Fatalf("preview change = %+v, want existing PTR details", resp.Changes)
	}
}

func TestHandleBulkPTR_OverrideReplacesExistingPTRByOwner(t *testing.T) {
	s, user := newServerWithReverseZone(t)
	if err := s.zoneManager.AddRecord("1.168.192.in-addr.arpa.", zone.Record{
		Name:  "0",
		Type:  "PTR",
		Class: "IN",
		TTL:   3600,
		RData: "old.example.com.",
	}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	body := `{"cidr":"192.168.1.0/32","pattern":"host-[A]-[B]-[C]-[D].example.com.","override":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	z, ok := s.zoneManager.Get("1.168.192.in-addr.arpa.")
	if !ok {
		t.Fatal("expected reverse zone")
	}
	z.RLock()
	records := append([]zone.Record(nil), z.Records["0.1.168.192.in-addr.arpa."]...)
	z.RUnlock()

	if len(records) != 1 {
		t.Fatalf("expected one PTR after override, got %+v", records)
	}
	if records[0].RData != "host-192-168-1-0.example.com." {
		t.Fatalf("PTR RData = %q, want updated host", records[0].RData)
	}
}

func TestHandleBulkPTR_WithAddA(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"192.168.1.0/30","pattern":"host-[A]-[B]-[C]-[D].example.com.","addA":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleBulkPTR_AddAExistingADoesNotSkipPTR(t *testing.T) {
	s, user := newServerWithReverseZone(t)
	existingName := "host-192-168-1-0.example.com."
	if err := s.zoneManager.AddRecord("1.168.192.in-addr.arpa.", zone.Record{
		Name:  existingName,
		Type:  "A",
		Class: "IN",
		TTL:   3600,
		RData: "192.168.1.0",
	}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	body := `{"cidr":"192.168.1.0/32","pattern":"host-[A]-[B]-[C]-[D].example.com.","addA":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp BulkPTRResultResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	if resp.Added != 1 || resp.AddedA != 0 || resp.ExistsA != 1 || resp.Skipped != 0 {
		t.Fatalf("bulk result = %+v, want added PTR and existing A", resp)
	}

	z, ok := s.zoneManager.Get("1.168.192.in-addr.arpa.")
	if !ok {
		t.Fatal("expected reverse zone")
	}
	z.RLock()
	ptrRecords := append([]zone.Record(nil), z.Records["0.1.168.192.in-addr.arpa."]...)
	aRecords := append([]zone.Record(nil), z.Records[existingName]...)
	z.RUnlock()

	if len(ptrRecords) != 1 || ptrRecords[0].Type != "PTR" {
		t.Fatalf("PTR records = %+v, want one PTR", ptrRecords)
	}
	if len(aRecords) != 1 {
		t.Fatalf("A records = %+v, want existing A without duplicate", aRecords)
	}
}

// Regression test: in non-override mode, an entry whose PTR already exists is
// reported as "skipped" and must not be mutated at all — in particular, no
// forward A record may be created even when addA=true and the A is missing.
func TestHandleBulkPTR_AddASkipEntryDoesNotCreateA(t *testing.T) {
	s, user := newServerWithReverseZone(t)
	if err := s.zoneManager.AddRecord("1.168.192.in-addr.arpa.", zone.Record{
		Name:  "0",
		Type:  "PTR",
		Class: "IN",
		TTL:   3600,
		RData: "host-192-168-1-0.example.com.",
	}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	body := `{"cidr":"192.168.1.0/32","pattern":"host-[A]-[B]-[C]-[D].example.com.","addA":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp BulkPTRResultResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	if resp.Added != 0 || resp.AddedA != 0 || resp.Skipped != 1 {
		t.Fatalf("bulk result = %+v, want skipped PTR and no A added", resp)
	}

	z, ok := s.zoneManager.Get("1.168.192.in-addr.arpa.")
	if !ok {
		t.Fatal("expected reverse zone")
	}
	z.RLock()
	aRecords := append([]zone.Record(nil), z.Records["host-192-168-1-0.example.com."]...)
	z.RUnlock()

	if len(aRecords) != 0 {
		t.Fatalf("A records = %+v, want no A record for a skipped entry", aRecords)
	}
}

// Preview must agree with apply: a skip entry must not be counted in willAddA.
func TestHandleBulkPTR_PreviewSkipEntryNotCountedInWillAddA(t *testing.T) {
	s, user := newServerWithReverseZone(t)
	if err := s.zoneManager.AddRecord("1.168.192.in-addr.arpa.", zone.Record{
		Name:  "0",
		Type:  "PTR",
		Class: "IN",
		TTL:   3600,
		RData: "host-192-168-1-0.example.com.",
	}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	body := `{"cidr":"192.168.1.0/31","pattern":"host-[A]-[B]-[C]-[D].example.com.","addA":true,"preview":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp ReverseDNSPreviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	// .0 has an existing PTR (skip, no A promised); .1 is a fresh add (PTR + A).
	if resp.WillSkip != 1 || resp.WillAdd != 1 || resp.WillAddA != 1 {
		t.Fatalf("preview counts: willSkip=%d willAdd=%d willAddA=%d, want 1/1/1", resp.WillSkip, resp.WillAdd, resp.WillAddA)
	}
}

func TestHandleBulkPTR_MissingFields(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"192.168.1.0/24"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleBulkPTR_InvalidCIDR(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"not-a-cidr","pattern":"host-[A]-[B]-[C]-[D].example.com."}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleBulkPTR_CIDRTooLarge(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"192.168.0.0/8","pattern":"host-[A]-[B]-[C]-[D].example.com."}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleBulkPTR_PatternMissingPlaceholders(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"192.168.1.0/30","pattern":"host.example.com."}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleBulkPTR_ZoneNotFound(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"192.168.1.0/30","pattern":"host-[A]-[B]-[C]-[D].example.com."}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/nonexistent.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "nonexistent.in-addr.arpa.")

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandleBulkPTR_InvalidJSON(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte("{bad json")))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleBulkPTR_CDIRZoneMismatch(t *testing.T) {
	// Zone is 1.168.192.in-addr.arpa but CIDR is 10.0.0.0/24 — wrong zone
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"10.0.0.0/24","pattern":"host-[A]-[B]-[C]-[D].example.com."}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for CIDR outside reverse zone, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// handlePtr6Lookup
// ---------------------------------------------------------------------------

func newServerWithIPv6ReverseZone(t *testing.T) (*Server, *auth.User) {
	t.Helper()
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.zoneManager = zone.NewManager()

	soa := &zone.SOARecord{
		TTL:     3600,
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}
	nsRecords := []zone.NSRecord{
		{TTL: 3600, NSDName: "ns1.example.com."},
	}
	if err := s.zoneManager.CreateZone("ip6.arpa.", 3600, soa, nsRecords); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}

	user, _ := store.GetUser("admin")
	return s, user
}

func TestHandlePtr6Lookup_MissingIP(t *testing.T) {
	s, user := newServerWithIPv6ReverseZone(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/ip6.arpa./ptr6-lookup", nil)
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handlePtr6Lookup(rec, req, "ip6.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandlePtr6Lookup_InvalidIPv6(t *testing.T) {
	s, user := newServerWithIPv6ReverseZone(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/ip6.arpa./ptr6-lookup?ip=not-an-ip", nil)
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handlePtr6Lookup(rec, req, "ip6.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandlePtr6Lookup_IPv4Rejected(t *testing.T) {
	s, user := newServerWithIPv6ReverseZone(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/ip6.arpa./ptr6-lookup?ip=192.168.1.1", nil)
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handlePtr6Lookup(rec, req, "ip6.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for IPv4, got %d", rec.Code)
	}
}

func TestHandlePtr6Lookup_ZoneNotFound(t *testing.T) {
	s, user := newServerWithIPv6ReverseZone(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/nonexistent./ptr6-lookup?ip=2001:db8::1", nil)
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handlePtr6Lookup(rec, req, "nonexistent.")

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandlePtr6Lookup_NotIPv6Zone(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com./ptr6-lookup?ip=2001:db8::1", nil)
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handlePtr6Lookup(rec, req, "example.com.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-ip6.arpa zone, got %d", rec.Code)
	}
}

func TestHandlePtr6Lookup_Found(t *testing.T) {
	s, user := newServerWithIPv6ReverseZone(t)

	ptrName := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
	if err := s.zoneManager.AddRecord("ip6.arpa.", zone.Record{
		Name:  ptrName + ".",
		TTL:   3600,
		Class: "IN",
		Type:  "PTR",
		RData: "host.example.com.",
	}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/ip6.arpa./ptr6-lookup?ip=2001:db8::1", nil)
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handlePtr6Lookup(rec, req, "ip6.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	if resp["found"] != true {
		t.Errorf("expected found=true, got %v; ptr=%v ptrFQDN=%v", resp["found"], resp["ptr"], resp["ptrFQDN"])
	}
}

func TestHandlePtr6Lookup_NotFound(t *testing.T) {
	s, user := newServerWithIPv6ReverseZone(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/ip6.arpa./ptr6-lookup?ip=2001:db8::1", nil)
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handlePtr6Lookup(rec, req, "ip6.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	if resp["found"] != false {
		t.Errorf("expected found=false, got %v", resp["found"])
	}
}

// ---------------------------------------------------------------------------
// validateUpstreamAddress
// ---------------------------------------------------------------------------

func TestValidateUpstreamAddress_PublicIP(t *testing.T) {
	err := validateUpstreamAddress("8.8.8.8:53")
	if err != nil {
		t.Errorf("public IP should be valid: %v", err)
	}
}

func TestValidateUpstreamAddress_PrivateIP(t *testing.T) {
	err := validateUpstreamAddress("192.168.1.1:53")
	if err == nil {
		t.Error("private IP should be rejected")
	}
}

func TestValidateUpstreamAddress_PrivateIP10(t *testing.T) {
	err := validateUpstreamAddress("10.0.0.1:53")
	if err == nil {
		t.Error("10.x.x.x should be rejected")
	}
}

func TestValidateUpstreamAddress_Loopback(t *testing.T) {
	err := validateUpstreamAddress("127.0.0.1:53")
	if err == nil {
		t.Error("loopback should be rejected")
	}
}

func TestValidateUpstreamAddress_IPWithoutPort(t *testing.T) {
	// No port — SplitHostPort fails, so entire string is treated as host
	err := validateUpstreamAddress("8.8.8.8")
	if err != nil {
		t.Errorf("public IP without port should be valid: %v", err)
	}
}

func TestValidateUpstreamAddress_BracketIPv6(t *testing.T) {
	err := validateUpstreamAddress("[::1]:53")
	if err == nil {
		t.Error("loopback IPv6 should be rejected")
	}
}

func TestValidateUpstreamAddress_PublicIPv6(t *testing.T) {
	err := validateUpstreamAddress("[2001:4860:4860::8888]:53")
	if err != nil {
		t.Errorf("public IPv6 should be valid: %v", err)
	}
}

// ---------------------------------------------------------------------------
// handleReadiness — with upstream
// ---------------------------------------------------------------------------

func TestHandleReadiness_WithUpstreamClient(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	// We can't easily mock upstream.Client, but we can set upstreamLB and
	// upstreamClient to nil and verify the no-upstream path returns 200.
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	srv.handleReadiness(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 without upstream, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// handleSPA
// ---------------------------------------------------------------------------

func TestHandleSPA_Delegates(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	called := false
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := srv.handleSPA(mockHandler)
	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if !called {
		t.Error("SPA handler should delegate to the provided handler")
	}
}

// ---------------------------------------------------------------------------
// handleAddRecord — edge cases
// ---------------------------------------------------------------------------

func TestHandleAddRecord_DefaultTTL(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	// Add record with TTL=0 — should use zone default TTL (3600)
	body := `{"name":"test.example.com.","type":"A","ttl":0,"data":"1.2.3.4"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleAddRecord(rec, req, "example.com.")

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleAddRecord_InvalidJSON(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", bytes.NewReader([]byte("{bad")))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleAddRecord(rec, req, "example.com.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// handleDeleteRecord — edge cases
// ---------------------------------------------------------------------------

func TestHandleDeleteRecord_InvalidJSON(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/example.com./records", bytes.NewReader([]byte("{bad")))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleDeleteRecord(rec, req, "example.com.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleDeleteRecord_NotFound(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	body := `{"name":"nonexistent.example.com.","type":"A"}`
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/example.com./records", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleDeleteRecord(rec, req, "example.com.")

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}
