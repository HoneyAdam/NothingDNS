// Package api provides the REST API server for NothingDNS.
package api

import (
	"encoding/json"
	"encoding/xml"
	"net/http"

	"github.com/nothingdns/nothingdns/internal/util"
)

// MaxBodyBytes is the maximum size for request bodies to prevent OOM attacks.
const MaxBodyBytes = 64 * 1024 // 64KB

// writeJSON writes a JSON response with the given status code.
// It uses a compact encoder and does not log encode failures (caller logs context).
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		util.Warnf("api: failed to encode JSON response: %v", err)
	}
}

// writeErrorJSON writes a JSON error response with the given status and message.
func writeErrorJSON(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, &ErrorResponse{Error: message})
}

// decode reads a JSON request body into dest, respecting MaxBodyBytes.
// Returns false if the body could not be decoded; in that case a 400 error
// has already been written to w. This combines http.MaxBytesReader with
// json.Decoder and eliminates the repeated boilerplate across all handlers.
// Usage in handlers: if !decode(w, r, &req) { return }
func decode(w http.ResponseWriter, r *http.Request, dest any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes)).Decode(dest); err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "Invalid JSON")
		return false
	}
	return true
}

// writeXML writes an XML response (used by SD and ODoH).
func writeXML(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	if err := xml.NewEncoder(w).Encode(v); err != nil {
		util.Warnf("api: failed to encode XML response: %v", err)
	}
}