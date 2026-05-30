package api

import (
	"github.com/nothingdns/nothingdns/internal/blocklist"
)

// BlocklistService provides blocklist operations for both REST and MCP handlers.
// It is the single source of truth for blocklist-related business logic,
// avoiding duplication between the HTTP handler layer and the MCP tool layer.
type BlocklistService struct {
	bl *blocklist.Blocklist
}

// NewBlocklistService creates a BlocklistService backed by the given *blocklist.Blocklist.
// If bl is nil, all methods return zero values / nil errors gracefully.
func NewBlocklistService(bl *blocklist.Blocklist) *BlocklistService {
	return &BlocklistService{bl: bl}
}

// GetStats returns blocklist statistics in a transport-agnostic format.
func (s *BlocklistService) GetStats() *BlocklistResponse {
	if s.bl == nil {
		return &BlocklistResponse{
			Enabled:    false,
			TotalRules: 0,
			FilesCount: 0,
			URLsCount:  0,
		}
	}
	stats := s.bl.Stats()
	return &BlocklistResponse{
		Enabled:    stats.Enabled,
		TotalRules: stats.TotalBlocks,
		FilesCount: stats.Files,
		URLsCount:  stats.URLs,
	}
}

// IsBlocked reports whether a domain is on any blocklist.
func (s *BlocklistService) IsBlocked(domain string) bool {
	if s.bl == nil {
		return false
	}
	return s.bl.IsBlocked(domain)
}

// Toggle atomically flips the global blocklist enabled state.
// Returns the new enabled state.
func (s *BlocklistService) Toggle() bool {
	if s.bl == nil {
		return false
	}
	return s.bl.Toggle()
}

// GetSources returns the list of configured blocklist sources.
func (s *BlocklistService) GetSources() []blocklist.SourceInfo {
	if s.bl == nil {
		return nil
	}
	return s.bl.GetSources()
}

// ToggleSource enables or disables a specific blocklist source by ID.
// Returns the new enabled state.
func (s *BlocklistService) ToggleSource(id string) (bool, error) {
	if s.bl == nil {
		return false, nil
	}
	return s.bl.ToggleSource(id)
}

// RemoveSource removes a blocklist source by file path or URL.
func (s *BlocklistService) RemoveSource(source string) error {
	if s.bl == nil {
		return nil
	}
	return s.bl.RemoveSource(source)
}

// AddFile loads a new blocklist from a file path.
func (s *BlocklistService) AddFile(path string) error {
	if s.bl == nil {
		return nil
	}
	return s.bl.AddFile(path)
}

// AddURL loads a new blocklist from a URL.
func (s *BlocklistService) AddURL(url string) error {
	if s.bl == nil {
		return nil
	}
	return s.bl.AddURL(url)
}

// Available reports whether the underlying blocklist is present.
func (s *BlocklistService) Available() bool {
	return s != nil && s.bl != nil
}

// Blocklist returns the underlying *blocklist.Blocklist. Use with caution.
func (s *BlocklistService) Blocklist() *blocklist.Blocklist {
	return s.bl
}