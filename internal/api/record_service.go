package api

import (
	"github.com/nothingdns/nothingdns/internal/zone"
)

// RecordService is the single source of truth for record-related business
// logic, kept separate from the HTTP handler layer.
type RecordService struct {
	zoneManager *zone.Manager
}

// NewRecordService creates a RecordService backed by the given zone.Manager.
func NewRecordService(zoneManager *zone.Manager) *RecordService {
	return &RecordService{zoneManager: zoneManager}
}

// ListRecords returns records for a zone, optionally filtered by name.
// The response is capped at RecordListMaxResults entries; Total reflects
// the unfiltered count, and Truncated is true when the response was capped.
func (s *RecordService) ListRecords(zoneName, name string) *RecordListResponse {
	resp := &RecordListResponse{Records: []RecordItem{}}
	if s.zoneManager == nil {
		return resp
	}

	records, err := s.zoneManager.GetRecords(zoneName, name)
	if err != nil {
		return resp
	}

	resp.Total = len(records)
	limit := resp.Total
	if limit > RecordListMaxResults {
		limit = RecordListMaxResults
		resp.Truncated = true
	}

	for _, r := range records[:limit] {
		resp.Records = append(resp.Records, RecordItem{
			Name:  r.Name,
			Type:  r.Type,
			TTL:   r.TTL,
			Class: r.Class,
			Data:  r.RData,
		})
	}

	return resp
}
