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
	var err error
	if cfg.Size, err = getRequiredInt(node, "size", cfg.Size); err != nil {
		return err
	}
	if cfg.DefaultTTL, err = getRequiredInt(node, "default_ttl", cfg.DefaultTTL); err != nil {
		return err
	}
	if cfg.MaxTTL, err = getRequiredInt(node, "max_ttl", cfg.MaxTTL); err != nil {
		return err
	}
	if cfg.MinTTL, err = getRequiredInt(node, "min_ttl", cfg.MinTTL); err != nil {
		return err
	}
	if cfg.NegativeTTL, err = getRequiredInt(node, "negative_ttl", cfg.NegativeTTL); err != nil {
		return err
	}
	cfg.Prefetch = getBool(node, "prefetch", cfg.Prefetch)
	if cfg.PrefetchThreshold, err = getRequiredInt(node, "prefetch_threshold", cfg.PrefetchThreshold); err != nil {
		return err
	}
	cfg.ServeStale = getBool(node, "serve_stale", cfg.ServeStale)
	if cfg.StaleGraceSecs, err = getRequiredInt(node, "stale_grace_secs", cfg.StaleGraceSecs); err != nil {
		return err
	}

	return nil
}
