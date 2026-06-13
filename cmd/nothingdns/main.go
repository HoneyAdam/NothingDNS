// NothingDNS - Main server binary
// Zero-dependency DNS server written in pure Go

package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nothingdns/nothingdns/internal/api"
	"github.com/nothingdns/nothingdns/internal/audit"
	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dashboard"
	"github.com/nothingdns/nothingdns/internal/dnscookie"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/dso"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/mdns"
	"github.com/nothingdns/nothingdns/internal/metrics"
	"github.com/nothingdns/nothingdns/internal/odoh"
	"github.com/nothingdns/nothingdns/internal/quic"
	"github.com/nothingdns/nothingdns/internal/resolver"
	"github.com/nothingdns/nothingdns/internal/rpz"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const (
	Name = "NothingDNS"
)

var (
	configPath     = flag.String("config", "/etc/nothingdns/nothingdns.yaml", "Path to configuration file")
	showVersion    = flag.Bool("version", false, "Show version and exit")
	showHelp       = flag.Bool("help", false, "Show help and exit")
	validateConfig = flag.Bool("validate-config", false, "Validate configuration file and exit")
	validateProd   = flag.Bool("validate-production-config", false, "Validate production configuration file and exit")
)

type blocklistReloader interface {
	Reload() error
	Stats() blocklist.Stats
}

type rpzReloader interface {
	Reload() error
	Stats() rpz.Stats
}

func effectiveHTTPConfig(cfg *config.Config) config.HTTPConfig {
	httpCfg := cfg.Server.HTTP
	if httpCfg.ODoHKEM == 0 {
		httpCfg.ODoHKEM = cfg.ODoH.KEM
	}
	if httpCfg.ODoHKDF == 0 {
		httpCfg.ODoHKDF = cfg.ODoH.KDF
	}
	if httpCfg.ODoHAEAD == 0 {
		httpCfg.ODoHAEAD = cfg.ODoH.AEAD
	}
	if httpCfg.ODoHPath == "" {
		httpCfg.ODoHPath = "/odoh"
	}
	if cfg.ODoH.Enabled {
		httpCfg.Enabled = true
		httpCfg.ODoHEnabled = true
		if httpCfg.Bind == "" && cfg.ODoH.Bind != "" {
			httpCfg.Bind = cfg.ODoH.Bind
		}
	}
	return httpCfg
}

func buildODoHConfig(cfg *config.Config, httpCfg config.HTTPConfig) *odoh.ODoHConfig {
	odohCfg := &odoh.ODoHConfig{
		TargetName: httpCfg.Bind,
		ProxyName:  httpCfg.Bind,
		HPKEKEM:    httpCfg.ODoHKEM,
		HPKEKDF:    httpCfg.ODoHKDF,
		HPKEAEAD:   httpCfg.ODoHAEAD,
	}
	if cfg.ODoH.Enabled {
		odohCfg.HPKEKEM = cfg.ODoH.KEM
		odohCfg.HPKEKDF = cfg.ODoH.KDF
		odohCfg.HPKEAEAD = cfg.ODoH.AEAD
		odohCfg.TargetURL = cfg.ODoH.TargetURL
		odohCfg.ProxyURL = cfg.ODoH.ProxyURL
	}
	return odohCfg
}

func reloadConfiguredZoneFiles(handler *integratedHandler, zoneManager *zone.Manager, zoneFiles map[string]string, configuredZoneFiles []string, loadZoneFileFunc func(string) (*zone.Zone, error), logger *util.Logger) (int, error) {
	loaded, err := prepareConfiguredZoneFiles(configuredZoneFiles, loadZoneFileFunc)
	if err != nil {
		return 0, err
	}
	applyConfiguredZoneFiles(handler, zoneManager, zoneFiles, loaded, logger)
	return len(loaded), nil
}

type loadedZoneFile struct {
	zone *zone.Zone
	file string
}

func prepareConfiguredZoneFiles(configuredZoneFiles []string, loadZoneFileFunc func(string) (*zone.Zone, error)) ([]loadedZoneFile, error) {
	loaded := make([]loadedZoneFile, 0, len(configuredZoneFiles))
	for _, zoneFile := range configuredZoneFiles {
		z, err := loadZoneFileFunc(zoneFile)
		if err != nil {
			return nil, fmt.Errorf("loading zone file %s: %w", zoneFile, err)
		}
		loaded = append(loaded, loadedZoneFile{zone: z, file: zoneFile})
	}
	return loaded, nil
}

func applyConfiguredZoneFiles(handler *integratedHandler, zoneManager *zone.Manager, zoneFiles map[string]string, loaded []loadedZoneFile, logger *util.Logger) {
	for _, item := range loaded {
		handler.zonesMu.Lock()
		handler.zones[item.zone.Origin] = item.zone
		handler.zonesMu.Unlock()
		zoneFiles[item.zone.Origin] = item.file
		zoneManager.LoadZone(item.zone, item.file)
		logger.Infof("Reloaded zone %s", item.zone.Origin)
		// Do NOT mirror file-backed zones into the KV store: the zone
		// file is their durable source, and a KV copy would resurrect
		// the zone after the operator removes it from the config.
	}

	handler.RebuildZoneTree()
}

func reloadConfiguredViews(handler *integratedHandler, views []config.ViewConfig, loadZoneFileFunc func(string) (*zone.Zone, error), logger *util.Logger) error {
	plan, count, err := prepareConfiguredViews(handler, views, loadZoneFileFunc)
	if err != nil {
		return err
	}
	applyConfiguredViews(handler, plan, count, logger)
	return nil
}

func prepareConfiguredViews(handler *integratedHandler, views []config.ViewConfig, loadZoneFileFunc func(string) (*zone.Zone, error)) (*viewReloadPlan, int, error) {
	viewConfigs := make([]filter.ViewConfig, len(views))
	for i, v := range views {
		viewConfigs[i] = filter.ViewConfig{
			Name:         v.Name,
			MatchClients: v.MatchClients,
			ZoneFiles:    v.ZoneFiles,
		}
	}
	plan, err := handler.prepareReloadViews(viewConfigs, loadZoneFileFunc)
	if err != nil {
		return nil, len(viewConfigs), fmt.Errorf("reloading configured split-horizon views: %w", err)
	}
	return plan, len(viewConfigs), nil
}

func applyConfiguredViews(handler *integratedHandler, plan *viewReloadPlan, count int, logger *util.Logger) {
	handler.applyReloadViews(plan)
	if count == 0 {
		logger.Info("Cleared split-horizon views")
	} else {
		logger.Infof("Reloaded split-horizon views")
	}
}

type upstreamReloadPlan struct {
	upstreamManager *UpstreamManager
	dnssecManager   *DNSSECManager
}

func prepareUpstreamComponents(cfg *config.Config, logger *util.Logger) (*upstreamReloadPlan, error) {
	nextUpstreamManager, err := NewUpstreamManager(cfg, logger)
	if err != nil {
		return nil, err
	}
	nextDNSSECManager, err := NewDNSSECManager(cfg, nextUpstreamManager.Resolver(), logger)
	if err != nil {
		nextUpstreamManager.Stop()
		return nil, err
	}
	return &upstreamReloadPlan{
		upstreamManager: nextUpstreamManager,
		dnssecManager:   nextDNSSECManager,
	}, nil
}

func applyUpstreamComponents(plan *upstreamReloadPlan, current *UpstreamManager, handler *integratedHandler, apiServer *api.Server) {
	if plan == nil || plan.upstreamManager == nil || plan.dnssecManager == nil {
		return
	}
	if handler != nil {
		handler.runtimeMu.Lock()
		handler.upstream = plan.upstreamManager.Client
		handler.loadBalancer = plan.upstreamManager.LoadBalancer
		handler.validator = plan.dnssecManager.Validator
		handler.runtimeMu.Unlock()
	}
	if apiServer != nil {
		apiServer.
			WithUpstream(plan.upstreamManager.Client, plan.upstreamManager.LoadBalancer).
			WithDNSSEC(plan.dnssecManager.Validator)
	}
	if current != nil && current != plan.upstreamManager {
		current.Stop()
	}
}

func reloadSecurityPolicy(bl blocklistReloader, rpzEngine rpzReloader, logger *util.Logger) error {
	var errs []error
	if bl != nil {
		if err := bl.Reload(); err != nil {
			wrapped := fmt.Errorf("reloading blocklist: %w", err)
			logger.Warnf("Failed to reload blocklist: %v", err)
			errs = append(errs, wrapped)
		} else {
			stats := bl.Stats()
			logger.Infof("Reloaded blocklist with %d entries from %d files", stats.TotalBlocks, stats.Files)
		}
	}
	if rpzEngine != nil {
		if err := rpzEngine.Reload(); err != nil {
			wrapped := fmt.Errorf("reloading RPZ zones: %w", err)
			logger.Warnf("Failed to reload RPZ zones: %v", err)
			errs = append(errs, wrapped)
		} else {
			stats := rpzEngine.Stats()
			logger.Infof("Reloaded RPZ with %d rules from %d files", stats.TotalRules, stats.Files)
		}
	}
	return errors.Join(errs...)
}

func reloadSecurityComponents(cfg *config.Config, current *SecurityManager, handler *integratedHandler, apiServer *api.Server, logger *util.Logger) (*SecurityManager, *SecurityManagerResult, error) {
	next, err := NewSecurityManager(cfg, logger)
	if err != nil {
		return nil, nil, err
	}
	result := next.Result()
	if handler != nil {
		handler.runtimeMu.Lock()
		handler.blocklist = result.Blocklist
		handler.rpzEngine = result.RPZEngine
		handler.geoEngine = result.GeoEngine
		handler.dns64Synth = result.DNS64Synth
		handler.aclChecker = result.ACLChecher
		handler.rateLimiter = result.RateLimiter
		handler.rrl = result.RRL
		handler.runtimeMu.Unlock()
	}
	if apiServer != nil {
		apiServer.
			WithBlocklist(result.Blocklist).
			WithRPZ(result.RPZEngine).
			WithGeoDNS(result.GeoEngine).
			WithACL(result.ACLChecher).
			WithRateLimiter(result.RateLimiter)
	}
	if current != nil {
		current.Stop()
	}
	return next, result, nil
}

func loadReloadConfig(path string) (*config.Config, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("config file %s not accessible: %w", path, err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	if err := validateRuntimeAssets(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func storeReloadConfig(path string, cfgMu *sync.RWMutex, cfgRef **config.Config) (*config.Config, error) {
	newCfg, err := loadReloadConfig(path)
	if err != nil {
		return nil, err
	}
	storeLoadedConfig(newCfg, cfgMu, cfgRef)
	return newCfg, nil
}

func storeLoadedConfig(newCfg *config.Config, cfgMu *sync.RWMutex, cfgRef **config.Config) {
	cfgMu.Lock()
	*cfgRef = newCfg
	cfgMu.Unlock()
}

func commitLoadedConfig(newCfg *config.Config, cfgMu *sync.RWMutex, cfgRef **config.Config, handler *integratedHandler) {
	storeLoadedConfig(newCfg, cfgMu, cfgRef)
	if handler != nil {
		handler.runtimeMu.Lock()
		handler.config = newCfg
		handler.runtimeMu.Unlock()
	}
}

func main() {
	flag.Parse()

	if *validateConfig {
		if err := validateConfigOnly(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Config validation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Config file %s is valid\n", *configPath)
		os.Exit(0)
	}

	if *validateProd {
		if err := validateProductionConfigOnly(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Production config validation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Production config file %s is valid\n", *configPath)
		os.Exit(0)
	}

	if *showHelp {
		printHelp()
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("%s version %s\n", Name, util.Version)
		os.Exit(0)
	}

	// Initialize and start server
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load configuration
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	var cfgMu sync.RWMutex

	// Initialize logger
	level := logLevelFromString(cfg.Logging.Level)
	format := logFormatFromString(cfg.Logging.Format)
	var output *os.File = os.Stdout
	if cfg.Logging.Output == "stderr" {
		output = os.Stderr
	}
	logger := util.NewLogger(level, format, output)
	logger.Infof("Starting %s v%s", Name, util.Version)

	// Initialize cache manager
	cacheManager, err := NewCacheManager(cfg, logger)
	if err != nil {
		return fmt.Errorf("creating cache manager: %w", err)
	}
	dnsCache := cacheManager.Cache

	// Load cache from persistent storage
	cacheManager.LoadCache()
	// Start periodic cache persistence
	cacheManager.StartPersistence(5 * time.Minute)

	// Initialize upstream manager
	upstreamManager, err := NewUpstreamManager(cfg, logger)
	if err != nil {
		return fmt.Errorf("creating upstream manager: %w", err)
	}
	client := upstreamManager.Client
	loadBalancer := upstreamManager.LoadBalancer

	// Initialize zone manager
	zoneManager, err := NewZoneManager(cfg, logger)
	if err != nil {
		return fmt.Errorf("creating zone manager: %w", err)
	}
	zones := zoneManager.Zones()
	zoneFiles := zoneManager.ZoneFiles()
	zoneSigners := zoneManager.Signers()
	zoneManagerInstance := zoneManager.Manager()
	kvPersistence := zoneManager.KVPersistence()

	// Initialize security manager
	securityManager, err := NewSecurityManager(cfg, logger)
	if err != nil {
		return fmt.Errorf("creating security manager: %w", err)
	}
	bl := securityManager.Result().Blocklist
	rpzEngine := securityManager.Result().RPZEngine
	geoEngine := securityManager.Result().GeoEngine
	dns64Synth := securityManager.Result().DNS64Synth
	aclChecker := securityManager.Result().ACLChecher
	rateLimiter := securityManager.Result().RateLimiter

	// Initialize metrics collector
	metricsCollector := metrics.New(metrics.Config{
		Enabled:   cfg.Metrics.Enabled,
		Bind:      cfg.Metrics.Bind,
		Path:      cfg.Metrics.Path,
		AuthToken: cfg.Metrics.AuthToken,
	})
	if err := metricsCollector.Start(); err != nil {
		if cfg.Metrics.Enabled {
			return fmt.Errorf("starting metrics server: %w", err)
		}
		logger.Warnf("Failed to start metrics server: %v", err)
	} else if cfg.Metrics.Enabled {
		logger.Infof("Metrics server listening on %s%s", cfg.Metrics.Bind, cfg.Metrics.Path)
	}

	// Initialize DNSSEC manager
	dnssecManager, err := NewDNSSECManager(cfg, upstreamManager.Resolver(), logger)
	if err != nil {
		return fmt.Errorf("creating DNSSEC manager: %w", err)
	}
	validator := dnssecManager.Validator

	// Stop channel for graceful goroutine shutdown
	stopCh := make(chan struct{})

	// Server root context — cancelled on SIGINT/SIGTERM to tear down
	// in-flight queries before the process exits.
	serverCtx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer() // Safe: deferred before any early return

	// Initialize cluster manager
	clusterManager, err := NewClusterManager(cfg, logger, dnsCache, metricsCollector, zoneManagerInstance)
	if err != nil {
		return fmt.Errorf("creating cluster manager: %w", err)
	}
	clusterMgr := clusterManager.Cluster

	// Initialize mDNS responder
	var mdnsResponder *mdns.Responder
	if cfg.MDNS.Enabled {
		mdnsConfig := mdns.Config{
			Enabled:     cfg.MDNS.Enabled,
			MulticastIP: cfg.MDNS.MulticastIP,
			Port:        cfg.MDNS.Port,
			HostName:    cfg.MDNS.HostName,
			Browser:     cfg.MDNS.Browser,
		}
		mdnsResponder = mdns.NewResponder(mdnsConfig, logger)
		if err := mdnsResponder.Start(); err != nil {
			return fmt.Errorf("starting mDNS responder: %w", err)
		} else {
			logger.Infof("mDNS responder started on %s:%d", mdnsConfig.MulticastIP, mdnsConfig.Port)
		}
	}

	// Initialize DSO manager
	var dsoManager *dso.Manager
	if cfg.DSO.Enabled {
		dsoConfig := dso.Config{
			Enabled:           cfg.DSO.Enabled,
			InactivityTimeout: parseDurationOrDefault(cfg.DSO.SessionTimeout, dso.DefaultInactivityTimeout),
			KeepaliveInterval: parseDurationOrDefault(cfg.DSO.HeartbeatInterval, dso.MinKeepaliveInterval),
			MaxSessions:       cfg.DSO.MaxSessions,
			MaxPayloadSize:    dso.DefaultMaxPayloadSize,
		}
		dsoManager = dso.NewManager(dsoConfig, logger)
		dsoManager.Start()
		logger.Info("DSO (DNS Stateful Operations) manager started")
	}

	// Set up cache invalidation callback for cluster sync
	if cfg.Cluster.Enabled && cfg.Cluster.CacheSync {
		cacheManager.SetInvalidateFunc(func(key string) {
			if err := clusterMgr.InvalidateCache([]string{key}); err != nil {
				logger.Debugf("Failed to broadcast cache invalidation: %v", err)
			}
		})
	}

	// Initialize transfer manager
	transferManager, err := NewTransferManager(cfg, zones, nil, logger)
	if err != nil {
		return fmt.Errorf("creating transfer manager: %w", err)
	}

	// Initialize auth store
	authUsers := make([]auth.User, len(cfg.Server.HTTP.Users))
	for i, u := range cfg.Server.HTTP.Users {
		authUsers[i] = auth.User{
			Username: u.Username,
			Password: u.Password,
			Role:     auth.Role(u.Role),
		}
		// Hash plaintext password and zero it from memory
		if authUsers[i].Password != "" {
			hash, err := auth.HashPasswordWithError(authUsers[i].Password, nil)
			if err != nil {
				return fmt.Errorf("hashing configured password for user %q: %w", authUsers[i].Username, err)
			}
			authUsers[i].Hash = hash
			authUsers[i].Password = strings.Repeat("\x00", len(authUsers[i].Password))
		}
		// Zero plaintext in the raw config struct as well
		cfg.Server.HTTP.Users[i].Password = strings.Repeat("\x00", len(cfg.Server.HTTP.Users[i].Password))
	}
	authStore, err := auth.NewStore(&auth.Config{
		Secret:             cfg.Server.HTTP.AuthSecret,
		Users:              authUsers,
		TokenExpiry:        auth.Duration{Duration: 24 * time.Hour},
		MaxSessionsPerUser: cfg.Server.HTTP.MaxSessionsPerUser, // L-N10
	})
	if err != nil {
		logger.Fatalf("Failed to initialize auth store: %v", err)
	}
	logger.Infof("Auth store initialized with %d users", len(cfg.Server.HTTP.Users))

	// Restore persistent tokens from file if configured. Validation
	// lives in cmd/nothingdns/helpers.validateAuthPersistenceConfig
	// so it's unit-testable (L-4).
	if err := validateAuthPersistenceConfig(cfg.Server.HTTP); err != nil {
		logger.Fatalf("%v", err)
	}
	if cfg.Server.HTTP.TokenPersistencePath != "" {
		authStore.SetTokenFilePath(cfg.Server.HTTP.TokenPersistencePath)
		if err := authStore.LoadTokensSigned(cfg.Server.HTTP.TokenPersistencePath); err != nil {
			logger.Warnf("Failed to load persisted tokens from %s: %v", cfg.Server.HTTP.TokenPersistencePath, err)
		} else {
			logger.Infof("Loaded session tokens from %s", cfg.Server.HTTP.TokenPersistencePath)
		}
	}

	// Warn if using legacy single-token auth without multi-user auth.
	// Since VULN-003 (CVE-2025-pending), the legacy token binds to the
	// role configured by `auth_token_role` (default: viewer). Reflect
	// the actual bound role in the warning so operators don't think
	// the token grants more than it does.
	if cfg.Server.HTTP.AuthToken != "" && len(cfg.Server.HTTP.Users) == 0 {
		boundRole := strings.ToLower(strings.TrimSpace(cfg.Server.HTTP.AuthTokenRole))
		if boundRole == "" {
			boundRole = "viewer"
		}
		if boundRole != "admin" && boundRole != "operator" && boundRole != "viewer" {
			boundRole = "viewer"
		}
		logger.Warnf("AUTH: Using legacy single-token auth (auth_token configured, no users). "+
			"All requests bearing this token are bound to role %q (set via auth_token_role; default \"viewer\"). "+
			"For per-user RBAC, configure multi-user auth via the `users` block.",
			boundRole)
	}

	// Initialize audit logger
	auditLogger, err := audit.NewAuditLogger(cfg.Logging.QueryLog, cfg.Logging.QueryLogFile)
	if err != nil {
		logger.Warnf("Failed to initialize audit logger: %v", err)
	} else if cfg.Logging.QueryLog {
		logger.Info("Query audit logging enabled")
	}

	// Initialize DNS cookie jar (RFC 7873)
	var cookieJar *dnscookie.CookieJar
	if cfg.Cookie.Enabled {
		rotation := parseDurationOrDefault(cfg.Cookie.SecretRotation, 1*time.Hour)
		jar, err := dnscookie.NewCookieJar(rotation)
		if err != nil {
			return fmt.Errorf("failed to initialize DNS cookie jar: %w", err)
		}
		cookieJar = jar
		logger.Infof("DNS cookies enabled (secret rotation: %s)", rotation)
	}

	// Initialize split-horizon views
	var splitHorizon *filter.SplitHorizon
	var viewZones map[string]map[string]*zone.Zone
	if len(cfg.Views) > 0 {
		viewConfigs := make([]filter.ViewConfig, len(cfg.Views))
		for i, v := range cfg.Views {
			viewConfigs[i] = filter.ViewConfig{
				Name:         v.Name,
				MatchClients: v.MatchClients,
				ZoneFiles:    v.ZoneFiles,
			}
		}
		var shErr error
		splitHorizon, shErr = filter.NewSplitHorizon(viewConfigs)
		if shErr != nil {
			return fmt.Errorf("initializing split-horizon: %w", shErr)
		}

		viewZones = make(map[string]map[string]*zone.Zone)
		for _, v := range cfg.Views {
			vzMap := make(map[string]*zone.Zone)
			for _, zf := range v.ZoneFiles {
				vz, vzErr := loadZoneFile(zf)
				if vzErr != nil {
					return fmt.Errorf("loading zone file %q for view %q: %w", zf, v.Name, vzErr)
				}
				vzMap[vz.Origin] = vz
				logger.Infof("Loaded zone %s for view %s", vz.Origin, v.Name)
			}
			viewZones[v.Name] = vzMap
		}
		logger.Infof("Split-horizon enabled with %d views", len(cfg.Views))
	}

	// Initialize IDNA validator if enabled (RFC 5891)
	idnaEnabled := cfg.IDNA.Enabled
	if idnaEnabled {
		logger.Infof("IDNA validation enabled (STD3=%v, Bidi=%v, Joiner=%v)",
			cfg.IDNA.UseSTD3Rules, cfg.IDNA.CheckBidi, cfg.IDNA.CheckJoiner)
	}

	// Create DNS handler (needed for API server DoH support)
	handler := &integratedHandler{
		config:        cfg,
		logger:        logger,
		cache:         dnsCache,
		upstream:      client,
		loadBalancer:  loadBalancer,
		zones:         zones,
		zoneTree:      zone.BuildRadixTree(zones),
		zoneManager:   zoneManagerInstance,
		kvPersistence: kvPersistence,
		blocklist:     bl,
		rpzEngine:     rpzEngine,
		geoEngine:     geoEngine,
		metrics:       metricsCollector,
		validator:     validator,
		zoneSigners:   zoneSigners,
		idnaEnabled:   idnaEnabled,
		cluster:       clusterMgr,
		axfrServer:    transferManager.Result().AXFRServer,
		ixfrServer:    transferManager.Result().IXFRServer,
		notifyHandler: transferManager.Result().NotifyHandler,
		ddnsHandler:   transferManager.Result().DDNSHandler,
		slaveManager:  transferManager.Result().SlaveManager,
		aclChecker:    aclChecker,
		rateLimiter:   rateLimiter,
		rrl:           securityManager.Result().RRL,
		splitHorizon:  splitHorizon,
		viewZones:     viewZones,
		auditLogger:   auditLogger,
		nsecCache:     cache.NewNSECCache(10000),
		dns64Synth:    dns64Synth,
		cookieJar:     cookieJar,
		mdnsResponder: mdnsResponder,
		dsoManager:    dsoManager,
		zoneProvider: NewMultiZoneProvider(
			zones,
			zoneManagerInstance,
			kvPersistence,
			zone.BuildRadixTree(zones),
		),
		serverCtx:    serverCtx,
		cancelServer: cancelServer,
	}

	// Initialize iterative recursive resolver if enabled
	if cfg.Resolution.Recursive {
		resolverTransport := newResolverTransport(client, loadBalancer)
		resolverConfig := resolver.Config{
			MaxDepth:          cfg.Resolution.MaxDepth,
			MaxCNAMEDepth:     16,
			Timeout:           5 * time.Second,
			EDNS0BufSize:      uint16(cfg.Resolution.EDNS0BufferSize),
			QnameMinimization: cfg.Resolution.QnameMinimization,
			Use0x20:           cfg.Resolution.Use0x20,
		}
		if cfg.Resolution.Timeout != "" {
			if d, err := time.ParseDuration(cfg.Resolution.Timeout); err == nil {
				resolverConfig.Timeout = d
			}
		}
		if resolverConfig.EDNS0BufSize == 0 {
			resolverConfig.EDNS0BufSize = 4096
		}
		if resolverConfig.MaxDepth > 30 {
			logger.Warnf("MaxDepth %d exceeds safe limit, clamping to 30", resolverConfig.MaxDepth)
			resolverConfig.MaxDepth = 30
		}
		if cfg.Resolution.RootHints != "" {
			hints, err := loadRootHintsFile(cfg.Resolution.RootHints)
			if err != nil {
				return fmt.Errorf("loading root hints file %s: %w", cfg.Resolution.RootHints, err)
			}
			resolverConfig.Hints = hints
			logger.Infof("Loaded %d custom root hints from %s", len(hints), cfg.Resolution.RootHints)
		}
		handler.resolver = resolver.NewResolver(resolverConfig, &resolverCacheAdapter{cache: dnsCache}, resolverTransport)
		logger.Info("Iterative recursive resolver enabled")
		if resolverConfig.QnameMinimization {
			logger.Info("QNAME minimization enabled (RFC 7816)")
		}
		if resolverConfig.Use0x20 {
			logger.Info("0x20 encoding enabled for spoofing resistance")
		}
	}

	// VULN-041: Warn if recursion is enabled without ACL rules but with explicit allow-unrestricted
	if cfg.Resolution.Recursive && aclChecker == nil && cfg.Server.ACLAllowUnrestrictedRecursion {
		logger.Warnf("SECURITY WARNING: Recursive resolver is enabled with no ACL rules but acl_allow_unrestricted_recursion=true. This configuration makes the server an OPEN RECURSIVE RESOLVER accessible from any IP. Only set acl_allow_unrestricted_recursion=true if you intentionally want to run an open resolver.")
	}

	// Share the zones mutex between handler, AXFR server, and DDNS handler
	// to prevent data races on the shared zones map
	transferManager.SetZonesMu(&handler.zonesMu)

	// Initialize API server
	dashboardServer := dashboard.NewServer()
	dashboardServer.SetAllowedOrigins(cfg.Server.HTTP.AllowedOrigins)
	dashboardServer.SetAuthStore(authStore)
	dashboardServer.SetAuthToken(resolveDashboardBearer(cfg.Server.HTTP))
	dashboardServer.SetZoneManager(zoneManagerInstance)
	// Feed per-query events into the dashboard (Query Log page + live stream).
	handler.dashboardServer = dashboardServer
	httpConfig := effectiveHTTPConfig(cfg)
	var apiServer *api.Server
	apiServer = api.NewServer(httpConfig, zoneManagerInstance, dnsCache, func() error {
		logger.Info("Reloading configuration via API...")
		now := time.Now().UTC().Format(time.RFC3339)
		if auditLogger != nil {
			auditLogger.LogReload(audit.ReloadAuditEntry{
				Timestamp: now,
				Action:    "start",
			})
		}
		reloadCfg, cfgErr := loadReloadConfig(*configPath)
		if cfgErr != nil {
			logger.Warnf("Failed to reload config: %v", cfgErr)
			if auditLogger != nil {
				auditLogger.LogReload(audit.ReloadAuditEntry{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Action:    "complete",
					Error:     cfgErr.Error(),
				})
			}
			return cfgErr
		}
		zonePlan, reloadZonesErr := prepareConfiguredZoneFiles(reloadCfg.Zones, loadZoneFile)
		reloadedZones := len(zonePlan)
		if reloadZonesErr != nil {
			logger.Warnf("Failed to reload configured zone files: %v", reloadZonesErr)
			if auditLogger != nil {
				auditLogger.LogReload(audit.ReloadAuditEntry{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Action:    "complete",
					Zones:     reloadedZones,
					Error:     reloadZonesErr.Error(),
				})
			}
			return reloadZonesErr
		}
		viewPlan, viewCount, reloadViewsErr := prepareConfiguredViews(handler, reloadCfg.Views, loadZoneFile)
		if reloadViewsErr != nil {
			logger.Warnf("Failed to reload split-horizon views: %v", reloadViewsErr)
			if auditLogger != nil {
				auditLogger.LogReload(audit.ReloadAuditEntry{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Action:    "complete",
					Zones:     reloadedZones,
					Error:     reloadViewsErr.Error(),
				})
			}
			return reloadViewsErr
		}
		upstreamPlan, reloadUpstreamErr := prepareUpstreamComponents(reloadCfg, logger)
		if reloadUpstreamErr != nil {
			logger.Warnf("Failed to reload upstream components: %v", reloadUpstreamErr)
			if auditLogger != nil {
				auditLogger.LogReload(audit.ReloadAuditEntry{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Action:    "complete",
					Zones:     reloadedZones,
					Error:     reloadUpstreamErr.Error(),
				})
			}
			return reloadUpstreamErr
		}
		nextSecurityManager, securityResult, reloadSecurityErr := reloadSecurityComponents(reloadCfg, securityManager, handler, apiServer, logger)
		if reloadSecurityErr != nil {
			upstreamPlan.upstreamManager.Stop()
			if auditLogger != nil {
				auditLogger.LogReload(audit.ReloadAuditEntry{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Action:    "complete",
					Zones:     reloadedZones,
					Error:     reloadSecurityErr.Error(),
				})
			}
			return reloadSecurityErr
		}
		securityManager = nextSecurityManager
		bl = securityResult.Blocklist
		rpzEngine = securityResult.RPZEngine
		geoEngine = securityResult.GeoEngine
		dns64Synth = securityResult.DNS64Synth
		aclChecker = securityResult.ACLChecher
		rateLimiter = securityResult.RateLimiter
		applyConfiguredZoneFiles(handler, zoneManagerInstance, zoneFiles, zonePlan, logger)
		applyConfiguredViews(handler, viewPlan, viewCount, logger)
		applyUpstreamComponents(upstreamPlan, upstreamManager, handler, apiServer)
		upstreamManager = upstreamPlan.upstreamManager
		dnssecManager = upstreamPlan.dnssecManager
		client = upstreamManager.Client
		loadBalancer = upstreamManager.LoadBalancer
		validator = dnssecManager.Validator
		commitLoadedConfig(reloadCfg, &cfgMu, &cfg, handler)
		if auditLogger != nil {
			auditLogger.LogReload(audit.ReloadAuditEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Action:    "complete",
				Zones:     reloadedZones,
			})
		}
		return nil
	}, handler, clusterMgr, dashboardServer).
		WithConfigGetter(func() *config.Config {
			cfgMu.RLock()
			c := cfg
			cfgMu.RUnlock()
			return c
		}).
		WithBlocklist(bl).
		WithUpstream(client, loadBalancer).
		WithACL(aclChecker).
		WithAuth(authStore).
		WithDashboard(dashboardServer).
		WithMetrics(metricsCollector).
		WithDNSSEC(validator).
		WithZoneSigners(zoneSigners).
		WithRPZ(rpzEngine).
		WithGeoDNS(geoEngine).
		WithSlaveManager(transferManager.Result().SlaveManager).
		WithRateLimiter(rateLimiter)

	// Initialize ODoH (RFC 9230) if enabled
	if httpConfig.ODoHEnabled {
		odohConfig := buildODoHConfig(cfg, httpConfig)

		if cfg.ODoH.Enabled && cfg.ODoH.TargetURL != "" {
			// Running as ODoH proxy forwarding to external target
			odohConfig.TargetURL = cfg.ODoH.TargetURL
			odohConfig.ProxyURL = cfg.ODoH.ProxyURL
			odohProxy, err := odoh.NewObliviousProxy(odohConfig)
			if err != nil {
				return fmt.Errorf("creating ODoH proxy: %w", err)
			} else {
				logger.Infof("ODoH proxy configured (target: %s)", cfg.ODoH.TargetURL)
				apiServer = apiServer.WithODoH(odohProxy)
			}
		} else {
			// Running as ODoH target resolver with local DNS handler
			odohTarget, err := odoh.NewObliviousTarget(odohConfig, handler)
			if err != nil {
				return fmt.Errorf("creating ODoH target: %w", err)
			} else {
				logger.Infof("ODoH target configured (KEM=%d, KDF=%d, AEAD=%d)",
					odohConfig.HPKEKEM, odohConfig.HPKEKDF, odohConfig.HPKEAEAD)
				apiServer = apiServer.WithODoHTarget(odohTarget)
			}
		}
	}

	if err := apiServer.Start(); err != nil {
		if httpConfig.Enabled {
			return fmt.Errorf("starting API server: %w", err)
		}
		logger.Warnf("Failed to start API server: %v", err)
	} else if httpConfig.Enabled {
		logger.Infof("API server listening on %s", httpConfig.Bind)
		if httpConfig.DoHEnabled {
			logger.Infof("DoH endpoint enabled at %s", httpConfig.DoHPath)
		}
		if httpConfig.ODoHEnabled {
			logger.Infof("ODoH endpoint enabled at %s", httpConfig.ODoHPath)
		}
	}

	// Create and start DNS servers
	// Use configured bind addresses if set, otherwise default to ":PORT"
	defaultAddr := fmt.Sprintf(":%d", cfg.Server.Port)

	udpAddr := defaultAddr
	if len(cfg.Server.UDPBind) > 0 {
		udpAddr = cfg.Server.UDPBind[0]
	} else if len(cfg.Server.Bind) > 0 {
		udpAddr = bindEntryToAddr(cfg.Server.Bind[0], cfg.Server.Port)
	}

	tcpAddr := defaultAddr
	if len(cfg.Server.TCPBind) > 0 {
		tcpAddr = cfg.Server.TCPBind[0]
	} else if len(cfg.Server.Bind) > 0 {
		tcpAddr = bindEntryToAddr(cfg.Server.Bind[0], cfg.Server.Port)
	}

	udpServer := server.NewUDPServerWithWorkers(udpAddr, handler, cfg.Server.UDPWorkers)
	tcpServer := server.NewTCPServerWithWorkers(tcpAddr, handler, cfg.Server.TCPWorkers)

	// Start UDP server
	if err := udpServer.Listen(); err != nil {
		return fmt.Errorf("starting UDP server: %w", err)
	}
	go func() {
		if err := udpServer.Serve(); err != nil {
			logger.Errorf("UDP server error: %v", err)
		}
	}()
	logger.Infof("UDP server listening on %s", udpAddr)

	// Start TCP server
	if err := tcpServer.Listen(); err != nil {
		return fmt.Errorf("starting TCP server: %w", err)
	}
	go func() {
		if err := tcpServer.Serve(); err != nil {
			logger.Errorf("TCP server error: %v", err)
		}
	}()
	logger.Infof("TCP server listening on %s", tcpAddr)

	// Start TLS server if enabled
	var tlsServer *server.TLSServer
	if cfg.Server.TLS.Enabled {
		tlsAddr := cfg.Server.TLS.Bind
		if tlsAddr == "" {
			tlsAddr = fmt.Sprintf(":%d", server.DefaultTLSPort)
		}

		// Load TLS certificate
		cert, err := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("loading TLS certificate: %w", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
			// Dynamic certificate loading — reloads on each handshake
			// Supports Let's Encrypt auto-renewal without restart
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				updatedCert, err := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
				if err != nil {
					return nil, err
				}
				return &updatedCert, nil
			},
		}

		tlsServer = server.NewTLSServer(tlsAddr, handler, tlsConfig)
		if err := tlsServer.Listen(); err != nil {
			return fmt.Errorf("starting TLS server: %w", err)
		}
		go func() {
			if err := tlsServer.Serve(); err != nil {
				logger.Errorf("TLS server error: %v", err)
			}
		}()
		logger.Infof("TLS server listening on %s (DoT)", tlsAddr)
	}

	// Start QUIC server (DNS over QUIC, RFC 9250) if enabled
	var doqServer *quic.DoQServer
	if cfg.Server.QUIC.Enabled {
		doqAddr := cfg.Server.QUIC.Bind
		if doqAddr == "" {
			doqAddr = fmt.Sprintf(":%d", quic.DefaultDoQPort)
		}

		certFile := cfg.Server.QUIC.CertFile
		keyFile := cfg.Server.QUIC.KeyFile
		// Fall back to TLS cert if QUIC-specific cert is not set
		if certFile == "" && cfg.Server.TLS.CertFile != "" {
			certFile = cfg.Server.TLS.CertFile
			keyFile = cfg.Server.TLS.KeyFile
		}

		if certFile == "" || keyFile == "" {
			return fmt.Errorf("QUIC enabled but cert_file/key_file not configured")
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("loading QUIC certificate: %w", err)
		}

		quicTLSConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"doq"},
			MinVersion:   tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
		}

		doqHandler := &doqHandlerAdapter{handler: handler}
		doqServer = quic.NewDoQServer(doqAddr, doqHandler, quicTLSConfig)
		if err := doqServer.Listen(); err != nil {
			return fmt.Errorf("starting DoQ server: %w", err)
		}
		go func() {
			if err := doqServer.Serve(); err != nil {
				logger.Errorf("DoQ server error: %v", err)
			}
		}()
		logger.Infof("DoQ server listening on %s (DNS over QUIC)", doqAddr)
	}

	// Start XoT server (DNS Zone Transfer over TLS, RFC 9103) if enabled
	var xotServer *transfer.XoTServer
	if cfg.Server.XoT.Enabled {
		xotAddr := cfg.Server.XoT.Bind
		if xotAddr == "" {
			xotAddr = fmt.Sprintf(":%d", 853) // XoT default port
		}

		xotConfig := &transfer.XoTConfig{
			CertFile:      cfg.Server.XoT.CertFile,
			KeyFile:       cfg.Server.XoT.KeyFile,
			CAFile:        cfg.Server.XoT.CAFile,
			ListenPort:    853,
			MinTLSVersion: cfg.Server.XoT.MinTLSVersion,
		}

		// Reuse TLS cert if XoT cert not specifically configured
		if xotConfig.CertFile == "" && cfg.Server.TLS.CertFile != "" {
			xotConfig.CertFile = cfg.Server.TLS.CertFile
			xotConfig.KeyFile = cfg.Server.TLS.KeyFile
		}

		if xotConfig.CertFile == "" || xotConfig.KeyFile == "" {
			return fmt.Errorf("XoT enabled but cert_file/key_file not configured")
		}
		xotServer, err = transfer.NewXoTServer(zones, xotConfig, logger)
		if err != nil {
			return fmt.Errorf("creating XoT server: %w", err)
		}
		xotServer.SetJournalStore(transferManager.Result().JournalStore)

		if err := xotServer.Serve(xotAddr); err != nil {
			return fmt.Errorf("starting XoT server: %w", err)
		}

		go xotServer.AcceptLoop()
		logger.Infof("XoT server listening on %s (DNS Zone Transfer over TLS, RFC 9103)", xotServer.Addr())
	}

	// Periodically collect transport stats
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				if metricsCollector != nil {
					us := udpServer.Stats()
					ts := tcpServer.Stats()
					metricsCollector.SetTransportStats(
						us.PacketsReceived, us.PacketsSent, us.Errors,
						ts.ConnectionsAccepted, ts.ConnectionsClosed, ts.MessagesReceived, ts.Errors,
					)
				}
			}
		}
	}()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Capture proper goroutine baseline after all servers are running
	apiServer.SetGoroutineBaseline()

	logger.Info("Server started successfully")

	// Write PID file if configured
	if cfg.Server.PIDFile != "" {
		pidStr := fmt.Sprintf("%d\n", os.Getpid())
		if err := os.WriteFile(cfg.Server.PIDFile, []byte(pidStr), 0644); err != nil {
			logger.Warnf("Failed to write PID file %s: %v", cfg.Server.PIDFile, err)
		} else {
			logger.Infof("Wrote PID to %s", cfg.Server.PIDFile)
		}
	}

	// Send systemd notify if configured
	if cfg.Server.SystemdNotify != "" {
		if err := sdNotifySend(cfg.Server.SystemdNotify); err != nil {
			logger.Warnf("Failed to send systemd notify: %v", err)
		} else {
			logger.Infof("Sent systemd READY=1 to %s", cfg.Server.SystemdNotify)
		}
	}

	// Wait for signals
	for {
		sig := <-sigChan
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			logger.Info("Shutting down gracefully...")

			// Signal goroutines to stop
			close(stopCh)

			shutdownTimeout := parseDurationOrDefault(cfg.ShutdownTimeout, 30*time.Second)
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer shutdownCancel()

			done := make(chan struct{})
			go func() {
				defer close(done)

				// Stop servers
				cancelServer() // Cancel in-flight queries before stopping transports
				if err := udpServer.Stop(); err != nil {
					logger.Warnf("Failed to stop UDP server cleanly: %v", err)
				}
				if err := tcpServer.Stop(); err != nil {
					logger.Warnf("Failed to stop TCP server cleanly: %v", err)
				}
				if tlsServer != nil {
					if err := tlsServer.Stop(); err != nil {
						logger.Warnf("Failed to stop TLS server cleanly: %v", err)
					}
				}
				if doqServer != nil {
					if err := doqServer.Stop(); err != nil {
						logger.Warnf("Failed to stop DoQ server cleanly: %v", err)
					}
				}
				if xotServer != nil {
					if err := xotServer.Close(); err != nil {
						logger.Warnf("Failed to close XoT server cleanly: %v", err)
					}
				}

				// Close upstream client and load balancer
				upstreamManager.Stop()

				// Stop metrics server
				if metricsCollector != nil {
					if err := metricsCollector.Stop(); err != nil {
						logger.Warnf("Failed to stop metrics collector cleanly: %v", err)
					}
				}

				// Stop API server
				if apiServer != nil {
					if err := apiServer.Stop(); err != nil {
						logger.Warnf("Failed to stop API server cleanly: %v", err)
					}
				}

				// Stop cluster manager
				clusterManager.Stop()

				// Stop transfer manager (slave manager, notify handler, DDNS handler)
				transferManager.Stop()

				// Stop mDNS responder
				if mdnsResponder != nil {
					mdnsResponder.Stop()
				}

				// Stop DSO manager
				if dsoManager != nil {
					dsoManager.Stop()
				}

				// Stop security manager (rate limiter)
				securityManager.Stop()

				// Persist session tokens to file if configured
				if cfg.Server.HTTP.TokenPersistencePath != "" {
					if err := authStore.SaveTokensSigned(cfg.Server.HTTP.TokenPersistencePath); err != nil {
						logger.Warnf("Failed to persist tokens to %s: %v", cfg.Server.HTTP.TokenPersistencePath, err)
					}
				}

				// Stop cache manager (memory monitor)
				cacheManager.Stop()

				// Close audit logger
				if auditLogger != nil {
					auditLogger.Close()
				}
			}()

			select {
			case <-done:
				logger.Info("Server shutdown complete")
			case <-shutdownCtx.Done():
				logger.Warnf("Server shutdown timed out after 30s")
			}

			// Clean up PID file
			if cfg.Server.PIDFile != "" {
				if err := os.Remove(cfg.Server.PIDFile); err != nil && !os.IsNotExist(err) {
					logger.Warnf("Failed to remove PID file %s: %v", cfg.Server.PIDFile, err)
				}
			}

			return nil

		case syscall.SIGHUP:
			logger.Info("Received SIGHUP, reloading configuration...")
			now := time.Now().UTC().Format(time.RFC3339)
			if auditLogger != nil {
				auditLogger.LogReload(audit.ReloadAuditEntry{
					Timestamp: now,
					Action:    "start",
				})
			}
			// Reload the config file to pick up changes
			reloadCfg, cfgErr := loadReloadConfig(*configPath)
			if cfgErr != nil {
				logger.Warnf("Failed to reload config: %v", cfgErr)
			}
			// Reload zone files
			if cfgErr != nil {
				cfgMu.RLock()
				reloadCfg = cfg // keep current config on error
				cfgMu.RUnlock()
			}
			zonePlan, reloadZonesErr := prepareConfiguredZoneFiles(reloadCfg.Zones, loadZoneFile)
			reloadedZones := len(zonePlan)
			if reloadZonesErr != nil {
				logger.Warnf("Failed to reload configured zone files: %v", reloadZonesErr)
			}
			viewPlan, viewCount, reloadViewsErr := prepareConfiguredViews(handler, reloadCfg.Views, loadZoneFile)
			if reloadViewsErr != nil {
				logger.Warnf("Failed to reload split-horizon views: %v", reloadViewsErr)
			}
			var upstreamPlan *upstreamReloadPlan
			var reloadUpstreamErr error
			if reloadZonesErr == nil && reloadViewsErr == nil {
				upstreamPlan, reloadUpstreamErr = prepareUpstreamComponents(reloadCfg, logger)
			}
			if reloadUpstreamErr != nil {
				logger.Warnf("Failed to reload upstream components: %v", reloadUpstreamErr)
			}
			var reloadSecurityErr error
			if reloadZonesErr == nil && reloadViewsErr == nil && reloadUpstreamErr == nil {
				var nextSecurityManager *SecurityManager
				var securityResult *SecurityManagerResult
				nextSecurityManager, securityResult, reloadSecurityErr = reloadSecurityComponents(reloadCfg, securityManager, handler, apiServer, logger)
				if reloadSecurityErr == nil {
					securityManager = nextSecurityManager
					bl = securityResult.Blocklist
					rpzEngine = securityResult.RPZEngine
					geoEngine = securityResult.GeoEngine
					dns64Synth = securityResult.DNS64Synth
					aclChecker = securityResult.ACLChecher
					rateLimiter = securityResult.RateLimiter
					applyConfiguredZoneFiles(handler, zoneManagerInstance, zoneFiles, zonePlan, logger)
					applyConfiguredViews(handler, viewPlan, viewCount, logger)
					applyUpstreamComponents(upstreamPlan, upstreamManager, handler, apiServer)
					upstreamManager = upstreamPlan.upstreamManager
					dnssecManager = upstreamPlan.dnssecManager
					client = upstreamManager.Client
					loadBalancer = upstreamManager.LoadBalancer
					validator = dnssecManager.Validator
				}
			}
			if reloadSecurityErr != nil {
				if upstreamPlan != nil && upstreamPlan.upstreamManager != nil {
					upstreamPlan.upstreamManager.Stop()
				}
				logger.Warnf("Failed to reload security components: %v", reloadSecurityErr)
			}
			if cfgErr == nil && reloadZonesErr == nil && reloadSecurityErr == nil && reloadViewsErr == nil && reloadUpstreamErr == nil {
				commitLoadedConfig(reloadCfg, &cfgMu, &cfg, handler)
			}
			if auditLogger != nil {
				errStr := ""
				if cfgErr != nil {
					errStr = cfgErr.Error()
				} else if reloadZonesErr != nil {
					errStr = reloadZonesErr.Error()
				} else if reloadViewsErr != nil {
					errStr = reloadViewsErr.Error()
				} else if reloadUpstreamErr != nil {
					errStr = reloadUpstreamErr.Error()
				} else if reloadSecurityErr != nil {
					errStr = reloadSecurityErr.Error()
				}
				auditLogger.LogReload(audit.ReloadAuditEntry{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Action:    "complete",
					Zones:     reloadedZones,
					Error:     errStr,
				})
			}
		}
	}
}

// loadConfig loads and validates the configuration file.
func loadConfig(path string) (*config.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// If file doesn't exist, use defaults
		if os.IsNotExist(err) {
			cfg := config.DefaultConfig()
			return cfg, nil
		}
		return nil, err
	}

	cfg, err := config.UnmarshalYAML(string(data))
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Validate configuration
	if errs := cfg.Validate(); len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "Config validation error: %s\n", e)
		}
		return nil, fmt.Errorf("configuration validation failed: %d error(s)", len(errs))
	}

	return cfg, nil
}

// loadZoneFile loads a single zone file.
func loadZoneFile(path string) (*zone.Zone, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	z, err := zone.ParseFile(path, f)
	if err != nil {
		return nil, err
	}

	if err := z.Validate(); err != nil {
		return nil, fmt.Errorf("zone validation: %w", err)
	}

	return z, nil
}

// loadZoneSigner creates a DNSSEC signer for a zone from config.
func loadZoneSigner(z *zone.Zone, signingCfg config.SigningConfig) (*dnssec.Signer, error) {
	if !signingCfg.Enabled {
		return nil, nil
	}

	signerCfg := dnssec.DefaultSignerConfig()

	if signingCfg.SignatureValidity != "" {
		if d, err := time.ParseDuration(signingCfg.SignatureValidity); err == nil {
			signerCfg.SignatureValidity = d
		}
	}

	if signingCfg.NSEC3 != nil {
		signerCfg.NSEC3Enabled = true
		signerCfg.NSEC3Iterations = signingCfg.NSEC3.Iterations
		if signingCfg.NSEC3.Salt != "" {
			salt, err := hex.DecodeString(signingCfg.NSEC3.Salt)
			if err != nil {
				return nil, fmt.Errorf("parsing NSEC3 salt: %w", err)
			}
			signerCfg.NSEC3Salt = salt
		}
	}

	signer := dnssec.NewSigner(z.Origin, signerCfg)

	// Generate key pairs from config
	for _, keyConfig := range signingCfg.Keys {
		if keyConfig.PrivateKey == "" {
			continue
		}

		isKSK := keyConfig.Type == "ksk"
		_, err := signer.GenerateKeyPair(keyConfig.Algorithm, isKSK)
		if err != nil {
			return nil, fmt.Errorf("generating key pair: %w", err)
		}
	}

	return signer, nil
}

// validateConfigOnly loads and validates a configuration file without starting the server.
//
// Unlike loadConfig (which falls back to defaults when the path doesn't
// exist — handy at server start, but wrong here), this explicitly
// requires the file to be present. Otherwise `nothingdns -config
// /typo'd/path -validate-config` used to print "is valid" — the
// operator would think their config worked when the file isn't even
// being read.
func validateConfigOnly(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("config file %s not accessible: %w", path, err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if errs := cfg.Validate(); len(errs) > 0 {
		return fmt.Errorf("config validation failed: %s", strings.Join(errs, "; "))
	}
	if err := validateRuntimeAssets(cfg); err != nil {
		return err
	}
	return nil
}

func validateProductionConfigOnly(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("config file %s not accessible: %w", path, err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if errs := cfg.ValidateProduction(); len(errs) > 0 {
		return fmt.Errorf("production config validation failed: %s", strings.Join(errs, "; "))
	}
	if err := validateRuntimeAssets(cfg); err != nil {
		return err
	}
	return nil
}

func validateRuntimeAssets(cfg *config.Config) error {
	zoneFiles, err := discoverStartupZoneFiles(cfg)
	if err != nil {
		return err
	}
	loadedZones := make([]*zone.Zone, 0, len(zoneFiles))
	for _, zoneFile := range zoneFiles {
		z, err := loadZoneFile(zoneFile)
		if err != nil {
			return fmt.Errorf("validating zone file %s: %w", zoneFile, err)
		}
		loadedZones = append(loadedZones, z)
	}
	if cfg.DNSSEC.Enabled && cfg.DNSSEC.Signing.Enabled {
		for _, z := range loadedZones {
			if _, err := loadZoneSigner(z, cfg.DNSSEC.Signing); err != nil {
				return fmt.Errorf("validating DNSSEC signer for %s: %w", z.Origin, err)
			}
		}
	}
	for _, view := range cfg.Views {
		for _, zoneFile := range view.ZoneFiles {
			if _, err := loadZoneFile(zoneFile); err != nil {
				return fmt.Errorf("validating zone file %s for view %s: %w", zoneFile, view.Name, err)
			}
		}
	}
	if cfg.Resolution.Recursive && cfg.Resolution.RootHints != "" {
		if _, err := loadRootHintsFile(cfg.Resolution.RootHints); err != nil {
			return fmt.Errorf("validating root hints file %s: %w", cfg.Resolution.RootHints, err)
		}
	}
	return nil
}

// bindEntryToAddr turns a `server.bind` list entry into a listener
// address. The historical implementation always called
// net.JoinHostPort(entry, port), which silently wrapped an entry
// that already carried a port (e.g. ":15353" or "127.0.0.1:5353")
// into nonsense like "[:15353]:53" — UDP/TCP startup then failed
// with "lookup :15353" because the result was treated as an IPv6
// host. We now accept both forms: if the entry already parses as
// host:port we use it as-is; otherwise we treat it as a bare host
// and join it with the configured port. IPv6 literals must already
// be bracket-wrapped per RFC 3986 to disambiguate from host:port.
func bindEntryToAddr(entry string, port int) string {
	if _, _, err := net.SplitHostPort(entry); err == nil {
		return entry
	}
	// Strip outer brackets if a user supplied "[::1]" — JoinHostPort
	// would re-bracket and produce "[[::1]]:port".
	if len(entry) >= 2 && entry[0] == '[' && entry[len(entry)-1] == ']' {
		entry = entry[1 : len(entry)-1]
	}
	return net.JoinHostPort(entry, fmt.Sprintf("%d", port))
}

// sdNotifySend sends a READY notification to systemd via the unix
// datagram socket named in NOTIFY_SOCKET (or the explicit `socket`
// arg, which takes precedence).
func sdNotifySend(socket string) error {
	// Try NOTIFY_SOCKET environment variable first, then explicit path
	notifySocket := socket
	if notifySocket == "" {
		notifySocket = os.Getenv("NOTIFY_SOCKET")
	}
	if notifySocket == "" {
		return fmt.Errorf("no systemd notify socket configured")
	}

	conn, err := net.Dial("unixgram", notifySocket)
	if err != nil {
		return fmt.Errorf("dialing systemd socket: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("READY=1\n"))
	if err != nil {
		return fmt.Errorf("writing to systemd socket: %w", err)
	}
	return nil
}

func printHelp() {
	fmt.Printf(`%s - Zero-dependency DNS server

Usage: %s [options]

Options:
  -config string
        Path to configuration file (default "/etc/nothingdns/nothingdns.yaml")
  -validate-config
        Validate configuration file and exit
  -validate-production-config
        Validate production configuration file and exit
  -version
        Show version and exit
  -help
        Show this help message and exit

Examples:
  # Start with default configuration
  %s

  # Start with custom configuration
  %s -config /path/to/config.yaml

  # Validate configuration
  %s -config /path/to/config.yaml -validate-config

  # Validate production configuration
  %s -config /path/to/config.yaml -validate-production-config

  # Show version
  %s -version

For more information, visit: https://github.com/nothingdns/nothingdns
`, Name, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}
