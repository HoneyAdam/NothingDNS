package api

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
)

func TestIsRequestSecure(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		tls            bool
		xfProto        string
		want           bool
	}{
		{
			name:       "plain HTTP, no proxies — insecure",
			remoteAddr: "203.0.113.5:4444",
			want:       false,
		},
		{
			name:       "direct TLS — secure regardless of proxies",
			remoteAddr: "203.0.113.5:4444",
			tls:        true,
			want:       true,
		},
		{
			name:       "no trusted proxies — X-Forwarded-Proto ignored (no spoofing)",
			remoteAddr: "203.0.113.5:4444",
			xfProto:    "https",
			want:       false,
		},
		{
			name:           "untrusted peer — X-Forwarded-Proto ignored",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "203.0.113.5:4444",
			xfProto:        "https",
			want:           false,
		},
		{
			name:           "trusted proxy forwarding https — secure",
			trustedProxies: []string{"127.0.0.1/32"},
			remoteAddr:     "127.0.0.1:5555",
			xfProto:        "https",
			want:           true,
		},
		{
			name:           "trusted proxy forwarding https, mixed case — secure",
			trustedProxies: []string{"127.0.0.1/32"},
			remoteAddr:     "127.0.0.1:5555",
			xfProto:        "HTTPS",
			want:           true,
		},
		{
			name:           "trusted proxy forwarding http — insecure",
			trustedProxies: []string{"127.0.0.1/32"},
			remoteAddr:     "127.0.0.1:5555",
			xfProto:        "http",
			want:           false,
		},
		{
			name:           "trusted proxy, no forwarded proto — insecure",
			trustedProxies: []string{"127.0.0.1/32"},
			remoteAddr:     "127.0.0.1:5555",
			want:           false,
		},
		{
			name:           "trusted proxy chain — leftmost (original client) scheme wins",
			trustedProxies: []string{"127.0.0.1/32"},
			remoteAddr:     "127.0.0.1:5555",
			xfProto:        "https, http",
			want:           true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer(config.HTTPConfig{Enabled: true, TrustedProxies: tc.trustedProxies}, nil, nil, nil, nil, nil, nil)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if tc.xfProto != "" {
				req.Header.Set("X-Forwarded-Proto", tc.xfProto)
			}
			if got := s.isRequestSecure(req); got != tc.want {
				t.Errorf("isRequestSecure() = %v, want %v", got, tc.want)
			}
		})
	}
}
