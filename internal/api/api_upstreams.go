package api

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/nothingdns/nothingdns/internal/util"
)

func (s *Server) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.runtimeMu.RLock()
		upstreamLB := s.upstreamLB
		upstreamClient := s.upstreamClient
		s.runtimeMu.RUnlock()

		var upstreams []UpstreamStatus
		if upstreamLB != nil {
			queries, failed, failovers := upstreamLB.Stats()
			upstreams = append(upstreams, UpstreamStatus{
				Address:   "load-balancer",
				Healthy:   upstreamLB.IsHealthy(),
				Queries:   queries,
				Failed:    failed,
				Failovers: failovers,
			})
		}
		if upstreamClient != nil {
			queries, failed, _ := upstreamClient.Stats()
			upstreams = append(upstreams, UpstreamStatus{
				Address: "direct-upstream",
				Healthy: upstreamClient.IsHealthy(),
				Queries: queries,
				Failed:  failed,
			})
		}
		s.writeJSON(w, http.StatusOK, &UpstreamsResponse{Upstreams: upstreams})
	case http.MethodPut:
		// Swapping the upstream lets an operator MITM every recursive query
		// served by this resolver — admin-only (VULN-009).
		if s.requireAdmin(w, r) {
			return
		}
		// Update upstream configuration (add/remove servers)
		var req UpstreamUpdateRequest
		if !s.decode(w, r, &req) {
			return
		}

		switch req.Action {
		case "add":
			if req.Server == "" {
				s.writeError(w, http.StatusBadRequest, "Server address required")
				return
			}
			// Validate upstream server is not a private/internal IP (SSRF protection)
			if err := validateUpstreamAddress(req.Server); err != nil {
				s.writeError(w, http.StatusBadRequest, sanitizeError(err, "Invalid upstream address"))
				return
			}
			s.runtimeMu.RLock()
			upstreamClient := s.upstreamClient
			s.runtimeMu.RUnlock()
			if upstreamClient == nil {
				s.writeError(w, http.StatusServiceUnavailable, "Upstream client not configured")
				return
			}
			if err := upstreamClient.AddServer(req.Server); err != nil {
				s.writeError(w, http.StatusConflict, sanitizeError(err, "Operation failed"))
				return
			}
			s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Server added: " + req.Server})

		case "remove":
			if req.Server == "" {
				s.writeError(w, http.StatusBadRequest, "Server address required")
				return
			}
			s.runtimeMu.RLock()
			upstreamClient := s.upstreamClient
			s.runtimeMu.RUnlock()
			if upstreamClient == nil {
				s.writeError(w, http.StatusServiceUnavailable, "Upstream client not configured")
				return
			}
			if err := upstreamClient.RemoveServer(req.Server); err != nil {
				s.writeError(w, http.StatusNotFound, sanitizeError(err, "Not found"))
				return
			}
			s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Server removed: " + req.Server})

		default:
			s.writeError(w, http.StatusBadRequest, "Invalid action: must be 'add' or 'remove'")
		}
	}
}

// validateUpstreamAddress checks that an upstream server address does not resolve
// to a private/internal IP address, preventing SSRF attacks.
func validateUpstreamAddress(addr string) error {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	// Strip brackets from IPv6 addresses
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	// Check if it's an IP literal
	if ip := net.ParseIP(host); ip != nil {
		if util.IsPrivateIP(ip) {
			return fmt.Errorf("upstream server must not use a private/internal IP address")
		}
		return nil
	}
	// Resolve hostname and check all resulting IPs
	ips, err := net.LookupHost(host)
	if err != nil {
		// Allow unresolvable hostnames — they'll fail at connection time
		return nil
	}
	for _, ipStr := range ips {
		if ip := net.ParseIP(ipStr); ip != nil && util.IsPrivateIP(ip) {
			return fmt.Errorf("upstream server hostname resolves to private/internal IP %s", ipStr)
		}
	}
	return nil
}

// handleACL returns ACL rules or updates them.
