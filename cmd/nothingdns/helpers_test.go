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

// TestValidateAuthPersistenceConfig regresses SECURITY-REPORT.md L-4:
// TokenPersistencePath without an explicit AuthSecret must fail at
// startup, not silently boot with an empty token map.
func TestValidateAuthPersistenceConfig(t *testing.T) {
	cases := []struct {
		name      string
		cfg       config.HTTPConfig
		wantError bool
	}{
		{
			name:      "persistence path set, no auth_secret — must fail",
			cfg:       config.HTTPConfig{TokenPersistencePath: "/var/lib/ndns/tokens", AuthSecret: ""},
			wantError: true,
		},
		{
			name:      "persistence path set, auth_secret set — ok",
			cfg:       config.HTTPConfig{TokenPersistencePath: "/var/lib/ndns/tokens", AuthSecret: "stable-secret"},
			wantError: false,
		},
		{
			name:      "no persistence path — ok regardless of auth_secret",
			cfg:       config.HTTPConfig{},
			wantError: false,
		},
		{
			name:      "no persistence path, auth_secret set — ok",
			cfg:       config.HTTPConfig{AuthSecret: "stable-secret"},
			wantError: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAuthPersistenceConfig(tc.cfg)
			if (err != nil) != tc.wantError {
				t.Errorf("got err=%v, wantError=%v", err, tc.wantError)
			}
		})
	}
}
