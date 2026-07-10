package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
)

func TestClientIP_TrustedProxyHandling(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		xff            string
		xRealIP        string
		want           string
	}{
		{
			name:       "no trusted proxies configured — forwarded headers ignored",
			remoteAddr: "127.0.0.1:5555",
			xff:        "9.9.9.9",
			xRealIP:    "8.8.8.8",
			want:       "127.0.0.1",
		},
		{
			name:           "untrusted peer — headers ignored (no spoofing)",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "203.0.113.5:4444", // not in trusted set
			xff:            "1.2.3.4",
			want:           "203.0.113.5",
		},
		{
			name:           "trusted proxy — X-Forwarded-For client used",
			trustedProxies: []string{"127.0.0.1/32"},
			remoteAddr:     "127.0.0.1:5555",
			xff:            "198.51.100.7",
			want:           "198.51.100.7",
		},
		{
			name:           "trusted proxy chain — rightmost untrusted entry used",
			trustedProxies: []string{"127.0.0.1/32", "10.0.0.0/8"},
			remoteAddr:     "127.0.0.1:5555",
			xff:            "198.51.100.7, 10.1.2.3", // 10.x is a trusted hop, skip it
			want:           "198.51.100.7",
		},
		{
			name:           "trusted proxy — falls back to X-Real-IP when no XFF",
			trustedProxies: []string{"127.0.0.1/32"},
			remoteAddr:     "127.0.0.1:5555",
			xRealIP:        "192.0.2.50",
			want:           "192.0.2.50",
		},
		{
			name:           "trusted proxy but no forwarded header — peer used",
			trustedProxies: []string{"127.0.0.1/32"},
			remoteAddr:     "127.0.0.1:5555",
			want:           "127.0.0.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer(config.HTTPConfig{Enabled: true, TrustedProxies: tc.trustedProxies}, nil, nil, nil, nil, nil, nil)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xRealIP != "" {
				req.Header.Set("X-Real-IP", tc.xRealIP)
			}
			if got := s.clientIP(req); got != tc.want {
				t.Errorf("clientIP() = %q, want %q", got, tc.want)
			}
		})
	}
}
