package config

import (
	"fmt"
)

// ResolutionConfig contains DNS resolution settings.
type ResolutionConfig struct {
	// Enable recursive resolution
	Recursive bool `yaml:"recursive"`

	// AuthoritativeOnly hard-disables every code path that would forward a
	// query off this server (recursive resolver, upstream forwarder, and
	// out-of-zone CNAME chase). Names not covered by a local zone return
	// REFUSED instead of being resolved elsewhere. Set true for any
	// deployment that intends to be a pure authoritative DNS server — this
	// closes the cache-poisoning / query-proxy escape hatch that opens
	// when a malicious or compromised zone contains a CNAME pointing at an
	// attacker-controlled name outside the zone.
	AuthoritativeOnly bool `yaml:"authoritative_only"`

	// Root hints file for recursive resolution
	RootHints string `yaml:"root_hints"`

	// Maximum recursion depth
	MaxDepth int `yaml:"max_depth"`

	// Timeout for queries
	Timeout string `yaml:"timeout"`

	// EDNS0 UDP buffer size
	EDNS0BufferSize int `yaml:"edns0_buffer_size"`

	// QNAME Minimization (RFC 7816) — reduces privacy leakage
	QnameMinimization bool `yaml:"qname_minimization"`

	// DNS 0x20 encoding (Vixie/Dagon) — randomizes query name case for spoofing resistance
	Use0x20 bool `yaml:"use_0x20"`
}

// UpstreamConfig contains upstream DNS server settings.
type UpstreamConfig struct {
	// List of upstream servers
	Servers []string `yaml:"servers"`

	// Strategy for selecting upstream (random, round_robin, fastest)
	Strategy string `yaml:"strategy"`

	// Health check interval
	HealthCheck string `yaml:"health_check"`

	// Failover timeout
	FailoverTimeout string `yaml:"failover_timeout"`

	// Anycast groups for advanced load balancing
	AnycastGroups []AnycastGroupConfig `yaml:"anycast_groups"`

	// Topology configuration for this instance
	Topology TopologyConfig `yaml:"topology"`
}

// AnycastGroupConfig holds configuration for an anycast group.
type AnycastGroupConfig struct {
	// Anycast IP address shared by all backends
	AnycastIP string `yaml:"anycast_ip"`

	// Backend servers in this group
	Backends []AnycastBackendConfig `yaml:"backends"`

	// Health check interval (overrides global setting)
	HealthCheck string `yaml:"health_check"`
}

// AnycastBackendConfig holds configuration for an anycast backend.
type AnycastBackendConfig struct {
	// Physical IP address of the backend
	PhysicalIP string `yaml:"physical_ip"`

	// Port (default: 53)
	Port int `yaml:"port"`

	// Region identifier (e.g., "us-east-1")
	Region string `yaml:"region"`

	// Zone identifier within region (e.g., "a", "b")
	Zone string `yaml:"zone"`

	// Weight for load balancing (0-100, default: 100)
	Weight int `yaml:"weight"`
}

// TopologyConfig holds topology information for routing decisions.
type TopologyConfig struct {
	// Region identifier (e.g., "us-east-1")
	Region string `yaml:"region"`

	// Zone identifier within region (e.g., "a", "b")
	Zone string `yaml:"zone"`

	// Weight for load balancing (0-100)
	Weight int `yaml:"weight"`
}

func unmarshalResolution(node *Node, cfg *ResolutionConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Recursive = getBool(node, "recursive", cfg.Recursive)
	cfg.RootHints = node.GetString("root_hints")
	cfg.MaxDepth = getInt(node, "max_depth", cfg.MaxDepth)
	cfg.Timeout = node.GetString("timeout")
	if cfg.Timeout == "" {
		cfg.Timeout = "5s"
	}
	cfg.EDNS0BufferSize = getInt(node, "edns0_buffer_size", cfg.EDNS0BufferSize)
	cfg.QnameMinimization = node.GetBool("qname_minimization")
	cfg.Use0x20 = getBool(node, "use_0x20", cfg.Use0x20)

	return nil
}

func unmarshalUpstream(node *Node, cfg *UpstreamConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Servers = getStringSlice(node, "servers", cfg.Servers)
	cfg.Strategy = node.GetString("strategy")
	if cfg.Strategy == "" {
		cfg.Strategy = "random"
	}
	cfg.HealthCheck = node.GetString("health_check")
	if cfg.HealthCheck == "" {
		cfg.HealthCheck = "30s"
	}
	cfg.FailoverTimeout = node.GetString("failover_timeout")
	if cfg.FailoverTimeout == "" {
		cfg.FailoverTimeout = "5s"
	}

	// Parse topology configuration
	if topologyNode := node.Get("topology"); topologyNode != nil {
		cfg.Topology.Region = topologyNode.GetString("region")
		cfg.Topology.Zone = topologyNode.GetString("zone")
		cfg.Topology.Weight = getInt(topologyNode, "weight", 100)
	}

	// Parse anycast groups
	if anycastNode := node.Get("anycast_groups"); anycastNode != nil && anycastNode.Type == NodeSequence {
		for _, groupNode := range anycastNode.Children {
			if groupNode.Type == NodeMapping {
				var group AnycastGroupConfig
				group.AnycastIP = groupNode.GetString("anycast_ip")
				group.HealthCheck = groupNode.GetString("health_check")

				// Parse backends
				if backendsNode := groupNode.Get("backends"); backendsNode != nil && backendsNode.Type == NodeSequence {
					for _, backendNode := range backendsNode.Children {
						if backendNode.Type == NodeMapping {
							var backend AnycastBackendConfig
							backend.PhysicalIP = backendNode.GetString("physical_ip")
							backend.Port = getInt(backendNode, "port", 53)
							backend.Region = backendNode.GetString("region")
							backend.Zone = backendNode.GetString("zone")
							backend.Weight = getInt(backendNode, "weight", 100)
							group.Backends = append(group.Backends, backend)
						}
					}
				}

				cfg.AnycastGroups = append(cfg.AnycastGroups, group)
			}
		}
	}

	return nil
}
