package config

// ViewConfig holds configuration for a single split-horizon view.
type ViewConfig struct {
	// Name is a unique identifier for this view.
	Name string `yaml:"name"`

	// MatchClients contains CIDR networks or "any" for a catch-all.
	MatchClients []string `yaml:"match_clients"`

	// ZoneFiles lists zone file paths specific to this view.
	ZoneFiles []string `yaml:"zone_files"`
}
