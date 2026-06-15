package api

import (
	"net/http"
)

func (s *Server) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodGet) {
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	if !s.cacheService.Available() {
		s.writeError(w, http.StatusServiceUnavailable, "Cache not available")
		return
	}

	stats := s.cacheService.GetStats()
	s.writeJSON(w, http.StatusOK, stats)
}

// handleCacheFlush flushes the cache.
func (s *Server) handleCacheFlush(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodPost) {
		return
	}
	if s.requireAdmin(w, r) {
		return
	}

	if !s.cacheService.Available() {
		s.writeError(w, http.StatusServiceUnavailable, "Cache not available")
		return
	}

	if err := s.cacheService.Flush(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Cache flush failed: "+err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: "Cache flushed",
	})
}

// handleConfigReload reloads configuration.
