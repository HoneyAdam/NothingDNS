package config

import "fmt"

// CacheConfig contains DNS cache settings.
type CacheConfig struct {
	// Enable caching
	Enabled bool `yaml:"enabled"`

	// Maximum number of entries
	Size int `yaml:"size"`

	// Default TTL for positive responses
	DefaultTTL int `yaml:"default_ttl"`

	// Maximum TTL
	MaxTTL int `yaml:"max_ttl"`

	// Minimum TTL
	MinTTL int `yaml:"min_ttl"`

	// Negative cache TTL (for NXDOMAIN, etc.)
	NegativeTTL int `yaml:"negative_ttl"`

	// Prefetch before expiration
	Prefetch bool `yaml:"prefetch"`

	// Prefetch threshold (seconds before expiration)
	PrefetchThreshold int `yaml:"prefetch_threshold"`

	// RFC 8767: Serve stale responses when upstream is unavailable
	ServeStale bool `yaml:"serve_stale"`

	// Stale grace period in seconds (how long past TTL expiry to keep entries)
	StaleGraceSecs int `yaml:"stale_grace_secs"`
}

func unmarshalCache(node *Node, cfg *CacheConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	cfg.Size = getInt(node, "size", cfg.Size)
	cfg.DefaultTTL = getInt(node, "default_ttl", cfg.DefaultTTL)
	cfg.MaxTTL = getInt(node, "max_ttl", cfg.MaxTTL)
	cfg.MinTTL = getInt(node, "min_ttl", cfg.MinTTL)
	cfg.NegativeTTL = getInt(node, "negative_ttl", cfg.NegativeTTL)
	cfg.Prefetch = getBool(node, "prefetch", cfg.Prefetch)
	cfg.PrefetchThreshold = getInt(node, "prefetch_threshold", cfg.PrefetchThreshold)
	cfg.ServeStale = getBool(node, "serve_stale", cfg.ServeStale)
	cfg.StaleGraceSecs = getInt(node, "stale_grace_secs", cfg.StaleGraceSecs)

	return nil
}
