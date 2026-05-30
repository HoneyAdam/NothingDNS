// Package api provides the REST API server for NothingDNS.
package api

import (
	"encoding/json"
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
