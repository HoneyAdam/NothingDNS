package cluster

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// DefaultGossipConfig returns default configuration.
func DefaultGossipConfig() GossipConfig {
	return GossipConfig{
		BindAddr:        "0.0.0.0",
		BindPort:        7946,
		GossipInterval:  200 * time.Millisecond,
		ProbeInterval:   1 * time.Second,
		ProbeTimeout:    500 * time.Millisecond,
		SuspicionMult:   4,
		RetransmitMult:  4,
		GossipNodes:     3,
		IndirectChecks:  3,
		ProtocolVersion: 1, // Gossip protocol version for rolling upgrade compatibility
	}
}

func normalizeGossipConfig(config GossipConfig) GossipConfig {
	defaults := DefaultGossipConfig()
	if config.BindAddr == "" {
		config.BindAddr = defaults.BindAddr
	}
	if config.BindPort <= 0 {
		config.BindPort = defaults.BindPort
	}
	if config.GossipInterval <= 0 {
		config.GossipInterval = defaults.GossipInterval
	}
	if config.ProbeInterval <= 0 {
		config.ProbeInterval = defaults.ProbeInterval
	}
	if config.ProbeTimeout <= 0 {
		config.ProbeTimeout = defaults.ProbeTimeout
	}
	if config.SuspicionMult <= 0 {
		config.SuspicionMult = defaults.SuspicionMult
	}
	if config.RetransmitMult <= 0 {
		config.RetransmitMult = defaults.RetransmitMult
	}
	if config.GossipNodes <= 0 {
		config.GossipNodes = defaults.GossipNodes
	}
	if config.IndirectChecks <= 0 {
		config.IndirectChecks = defaults.IndirectChecks
	}
	if config.ProtocolVersion == 0 {
		config.ProtocolVersion = defaults.ProtocolVersion
	}
	return config
}

// NewGossipProtocol creates a new gossip protocol instance.
// allowInsecure permits unencrypted gossip for test/dev scenarios where
// AllowInsecureCluster is set at the cluster level.
func NewGossipProtocol(config GossipConfig, nodeList *NodeList, allowInsecure bool) (*GossipProtocol, error) {
	config = normalizeGossipConfig(config)
	ctx, cancel := context.WithCancel(context.Background())

	gp := &GossipProtocol{
		config:       config,
		nodeList:     nodeList,
		ctx:          ctx,
		cancel:       cancel,
		nodeMetrics:  make(map[string]ClusterMetricsPayload),
		sequences:    make(map[string]uint64),
		nextSequence: 1, // Start at 1; 0 is the null/unset sentinel
	}

	// VULN-062: Encryption is mandatory unless explicitly allowed for dev/test.
	if len(config.EncryptionKey) > 0 {
		if err := gp.initEncryption(config.EncryptionKey); err != nil {
			cancel()
			return nil, fmt.Errorf("init encryption: %w", err)
		}
	} else if !allowInsecure {
		cancel()
		return nil, fmt.Errorf("gossip encryption_key is required: cluster communication would be in plaintext")
	}

	return gp, nil
}

// SetCallbacks sets the event callbacks.
func (gp *GossipProtocol) SetCallbacks(
	onJoin, onLeave, onUpdate func(*Node),
	onCacheInvalid func([]string),
	onZoneUpdate func(ZoneUpdatePayload),
	onConfigSync func(ConfigSyncPayload),
) {
	gp.callbacksMu.Lock()
	defer gp.callbacksMu.Unlock()
	gp.onNodeJoin = onJoin
	gp.onNodeLeave = onLeave
	gp.onNodeUpdate = onUpdate
	gp.onCacheInvalid = onCacheInvalid
	gp.onZoneUpdate = onZoneUpdate
	gp.onConfigSync = onConfigSync
}

// Start starts the gossip protocol.
func (gp *GossipProtocol) Start() error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", gp.config.BindAddr, gp.config.BindPort))
	if err != nil {
		return fmt.Errorf("resolving address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listening: %w", err)
	}
	gp.conn = conn

	// Start goroutines
	gp.wg.Add(5)
	go gp.receiveLoop()
	go gp.gossipLoop()
	go gp.probeLoop()
	go gp.leaderHeartbeatLoop()
	go gp.leaderFailureDetector()

	// Start leader election if we're the only node (no peers to join)
	if len(gp.nodeList.GetAll()) <= 1 {
		go gp.startElection()
	}

	return nil
}

// Stop stops the gossip protocol.
func (gp *GossipProtocol) Stop() error {
	gp.cancel()

	var closeErr error
	if gp.conn != nil {
		if err := gp.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErr = fmt.Errorf("close gossip UDP socket: %w", err)
		}
	}

	gp.wg.Wait()
	return closeErr
}

func (gp *GossipProtocol) recoverCallback(name string) {
	if recovered := recover(); recovered != nil {
		util.Errorf("gossip: %s callback panic: %v", name, recovered)
	}
}
