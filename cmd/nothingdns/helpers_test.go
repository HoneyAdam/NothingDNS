package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
)

// TestResolveDashboardBearer_NeverReturnsAuthSecret regresses
// SECURITY-REPORT.md H-1. Before the fix, an empty AuthToken caused
// main() to fall back to AuthSecret as the dashboard bearer, conflating
// the HMAC-SHA512 session-signing key with a routine credential.
// Leaking the dashboard bearer would then also leak the token-forgery
// key. The helper must return AuthToken verbatim — empty when AuthToken
// is empty, never AuthSecret.
func TestResolveDashboardBearer_NeverReturnsAuthSecret(t *testing.T) {
	const secret = "super-secret-hmac-signing-key-must-not-leak"

	cases := []struct {
		name string
		cfg  config.HTTPConfig
		want string
	}{
		{
			name: "empty AuthToken, populated AuthSecret",
			cfg:  config.HTTPConfig{AuthToken: "", AuthSecret: secret},
			want: "",
		},
		{
			name: "empty AuthToken, empty AuthSecret",
			cfg:  config.HTTPConfig{AuthToken: "", AuthSecret: ""},
			want: "",
		},
		{
			name: "populated AuthToken, populated AuthSecret",
			cfg:  config.HTTPConfig{AuthToken: "explicit-bearer", AuthSecret: secret},
			want: "explicit-bearer",
		},
		{
			name: "populated AuthToken, empty AuthSecret",
			cfg:  config.HTTPConfig{AuthToken: "explicit-bearer", AuthSecret: ""},
			want: "explicit-bearer",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveDashboardBearer(tc.cfg)
			if got != tc.want {
				t.Errorf("resolveDashboardBearer = %q, want %q", got, tc.want)
			}
			if tc.cfg.AuthSecret != "" && got == tc.cfg.AuthSecret {
				t.Errorf("resolveDashboardBearer returned AuthSecret — this is the H-1 regression")
			}
		})
	}
}
