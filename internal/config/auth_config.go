package config

import (
	"fmt"
)

// CookieConfig holds DNS Cookie (RFC 7873) configuration.
type CookieConfig struct {
	// Enable DNS cookies
	Enabled bool `yaml:"enabled"`

	// Secret rotation interval (duration string, e.g., "1h")
	SecretRotation string `yaml:"secret_rotation"`
}

func unmarshalCookie(node *Node, cfg *CookieConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	if sr := node.GetString("secret_rotation"); sr != "" {
		cfg.SecretRotation = sr
	}

	return nil
}
