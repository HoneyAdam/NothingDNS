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
		// Route the internal error through sanitizeError so file paths /
		// panic details never leak to the client (consistent with the rest
		// of the API); fall back to a generic message otherwise.
		s.writeError(w, http.StatusInternalServerError, sanitizeError(err, "Cache flush failed"))
		return
	}
	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: "Cache flushed",
	})
}

// handleConfigReload reloads configuration.
