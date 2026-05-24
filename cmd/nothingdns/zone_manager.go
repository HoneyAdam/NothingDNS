// NothingDNS - Zone Manager
// Manages DNS zones, zone files, and DNSSEC signing

package main

import (
	"fmt"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/storage"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ZoneManagerResult holds the results of zone initialization.
type ZoneManagerResult struct {
	Manager       *zone.Manager
	Zones         map[string]*zone.Zone
	ZoneFiles     map[string]string // origin -> file path
	Signers       map[string]*dnssec.Signer
	KVPersistence *zone.KVPersistence
	KVStore       *storage.KVStore
}

// ZoneManager manages DNS zones, zone files, and DNSSEC signing.
type ZoneManager struct {
	result ZoneManagerResult
	logger *util.Logger
}

// NewZoneManager creates a new zone manager with the given configuration.
func NewZoneManager(cfg *config.Config, logger *util.Logger) (*ZoneManager, error) {
	mgr := &ZoneManager{
		result: ZoneManagerResult{
			Zones:     make(map[string]*zone.Zone),
			ZoneFiles: make(map[string]string),
			Signers:   make(map[string]*dnssec.Signer),
		},
		logger: logger,
	}

	zoneManager := zone.NewManager()
	if cfg.ZoneDir != "" {
		zoneManager.SetZoneDir(cfg.ZoneDir)
		logger.Infof("Zone file persistence enabled: %s", cfg.ZoneDir)
	}

	// Enable ZONEMD computation if configured
	if cfg.ZONEMD {
		zoneManager.SetZONEMDEnabled(true)
		logger.Info("ZONEMD zone message digests enabled (RFC 8976)")
	}

	// Load zone files in parallel for faster startup
	type zoneResult struct {
		zone     *zone.Zone
		zoneFile string
		err      error
	}

	zoneChans := make([]chan zoneResult, len(cfg.Zones))
	for i, zoneFile := range cfg.Zones {
		zoneChans[i] = make(chan zoneResult, 1)
		go func(zf string, ch chan zoneResult) {
			z, err := loadZoneFile(zf)
			ch <- zoneResult{z, zf, err}
		}(zoneFile, zoneChans[i])
	}

	for _, ch := range zoneChans {
		result := <-ch
		if result.err != nil {
			logger.Warnf("Failed to load zone file %s: %v", result.zoneFile, result.err)
			continue
		}
		if result.zone != nil {
			mgr.result.Zones[result.zone.Origin] = result.zone
			mgr.result.ZoneFiles[result.zone.Origin] = result.zoneFile
			zoneManager.LoadZone(result.zone, result.zoneFile)
			logger.Infof("Loaded zone %s with %d records", result.zone.Origin, len(result.zone.Records))
		}
	}

	// Initialize zone signers if DNSSEC signing is enabled
	if cfg.DNSSEC.Enabled && cfg.DNSSEC.Signing.Enabled {
		for origin, z := range mgr.result.Zones {
			signer, err := loadZoneSigner(z, cfg.DNSSEC.Signing)
			if err != nil {
				logger.Warnf("Failed to load zone signer for %s: %v", origin, err)
				continue
			}
			if signer != nil {
				mgr.result.Signers[origin] = signer
				logger.Infof("Zone signer loaded for %s (%d keys)", origin, len(signer.GetKeys()))
			}
		}
	}

	mgr.result.Manager = zoneManager

	// Initialize KV store and KVPersistence for persistent zone storage
	kvDataDir := cfg.ZoneDir
	if kvDataDir == "" {
		kvDataDir = "."
	}
	// L-6: pass the optional at-rest AEAD key. config.Validate has
	// already enforced 32-byte hex + key-separation, so a decode
	// failure here is either a bug or a Validate-bypass; either way,
	// L-N11 says fail-fast — silently dropping to plaintext while
	// the operator thinks encryption is on is the worst outcome
	// (matches L-4's fail-fast pattern for token persistence).
	var aeadKey []byte
	if hexKey := cfg.Storage.EncryptionKey; hexKey != "" {
		decoded, decErr := decodeHex32(hexKey)
		if decErr != nil {
			return nil, fmt.Errorf("storage.encryption_key invalid (%v); refusing to start in plaintext mode (L-N11)", decErr)
		}
		aeadKey = decoded
	}
	kvStore, err := storage.OpenKVStoreEncrypted(kvDataDir, nil, aeadKey)
	if err != nil {
		logger.Warnf("Failed to initialize KV store: %v", err)
	} else {
		mgr.result.KVStore = kvStore
		mgr.result.KVPersistence = zone.NewKVPersistence(zoneManager, kvStore)
		mgr.result.KVPersistence.Enable()
		if aeadKey != nil {
			logger.Infof("KV store and KVPersistence initialized at %s (AES-256-GCM at rest)", kvDataDir)
		} else {
			logger.Infof("KV store and KVPersistence initialized at %s", kvDataDir)
		}
	}

	return mgr, nil
}

// Zones returns the loaded zones.
func (m *ZoneManager) Zones() map[string]*zone.Zone {
	return m.result.Zones
}

// ZoneFiles returns the zone file paths.
func (m *ZoneManager) ZoneFiles() map[string]string {
	return m.result.ZoneFiles
}

// Signers returns the DNSSEC signers.
func (m *ZoneManager) Signers() map[string]*dnssec.Signer {
	return m.result.Signers
}

// Manager returns the zone manager.
func (m *ZoneManager) Manager() *zone.Manager {
	return m.result.Manager
}

// KVPersistence returns the KV persistence layer.
func (m *ZoneManager) KVPersistence() *zone.KVPersistence {
	return m.result.KVPersistence
}
