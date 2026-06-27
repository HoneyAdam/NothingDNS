// NothingDNS - DNSSEC Manager
// Manages DNSSEC validation and trust anchors

package main

import (
	"fmt"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/util"
)

// DNSSECManager manages DNSSEC validation and trust anchors.
type DNSSECManager struct {
	Validator *dnssec.Validator
	logger    *util.Logger
}

// NewDNSSECManager creates a new DNSSEC manager with the given configuration.
// The resolverAdapter should be the dnssecResolverAdapter from adapters.go.
func NewDNSSECManager(cfg *config.Config, resolverAdapter dnssec.Resolver, logger *util.Logger) (*DNSSECManager, error) {
	if !cfg.DNSSEC.Enabled || resolverAdapter == nil {
		return &DNSSECManager{logger: logger}, nil
	}

	mgr := &DNSSECManager{logger: logger}

	trustAnchors := dnssec.NewTrustAnchorStoreWithBuiltIn()

	// Load custom trust anchors if specified
	if cfg.DNSSEC.TrustAnchor != "" {
		if err := trustAnchors.LoadFromFile(cfg.DNSSEC.TrustAnchor); err != nil {
			return nil, fmt.Errorf("loading DNSSEC trust anchor file %s: %w", cfg.DNSSEC.TrustAnchor, err)
		} else {
			logger.Infof("Loaded trust anchors from %s", cfg.DNSSEC.TrustAnchor)
		}
	}

	mgr.Validator = dnssec.NewValidator(dnssec.ValidatorConfig{
		Enabled:       cfg.DNSSEC.Enabled,
		RequireDNSSEC: cfg.DNSSEC.RequireDNSSEC,
		IgnoreTime:    cfg.DNSSEC.IgnoreTime,
	}, trustAnchors, resolverAdapter)

	logger.Info("DNSSEC validation enabled")

	// Loud warning when ignore_time is on. The YAML field is documented
	// as "for testing" but it's also a security downgrade — bogus
	// expired or future-dated signatures sail through validation. An
	// operator who set it during local debug and forgot would otherwise
	// have no startup signal that production DNSSEC is effectively
	// permissive about replay-style attacks.
	if cfg.DNSSEC.IgnoreTime {
		logger.Warnf("DNSSEC: ignore_time=true — RRSIG inception/expiration checks are DISABLED. " +
			"This is a security downgrade intended for testing only. Unset dnssec.ignore_time in config for production deployments.")
	}

	return mgr, nil
}
