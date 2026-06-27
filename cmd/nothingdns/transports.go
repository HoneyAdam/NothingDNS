// NothingDNS — DNS transport server lifecycle.
//
// Extracts the transport-start and transport-shutdown sequences out of
// run() so the main function reads as three clear phases: init managers,
// start transports, handle signals.

package main

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/quic"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// servers holds all DNS transport server instances.
type servers struct {
	udp *server.UDPServer
	tcp *server.TCPServer
	tls *server.TLSServer
	doq *quic.DoQServer
	xot *transfer.XoTServer
}

// startServers creates and starts the UDP, TCP, TLS (DoT), DoQ, and XoT
// transport servers based on the config. Returns the created servers or
// the partially-started set on error (so callers can shut them down).
func startServers(cfg *config.Config, handler *integratedHandler, transferMgr *TransferManager, logger *util.Logger) (*servers, error) {
	s := &servers{}

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

	// UDP
	s.udp = server.NewUDPServerWithWorkers(udpAddr, handler, cfg.Server.UDPWorkers)
	if err := s.udp.Listen(); err != nil {
		return s, fmt.Errorf("starting UDP server: %w", err)
	}
	go func() {
		if err := s.udp.Serve(); err != nil {
			logger.Errorf("UDP server error: %v", err)
		}
	}()
	logger.Infof("UDP server listening on %s", udpAddr)

	// TCP
	s.tcp = server.NewTCPServerWithWorkers(tcpAddr, handler, cfg.Server.TCPWorkers)
	if err := s.tcp.Listen(); err != nil {
		return s, fmt.Errorf("starting TCP server: %w", err)
	}
	go func() {
		if err := s.tcp.Serve(); err != nil {
			logger.Errorf("TCP server error: %v", err)
		}
	}()
	logger.Infof("TCP server listening on %s", tcpAddr)

	// TLS (DoT)
	if cfg.Server.TLS.Enabled {
		if err := s.startTLS(cfg, handler, logger); err != nil {
			return s, err
		}
	}

	// DoQ (RFC 9250)
	if cfg.Server.QUIC.Enabled {
		if err := s.startDoQ(cfg, handler, logger); err != nil {
			return s, err
		}
	}

	// XoT (RFC 9103)
	if cfg.Server.XoT.Enabled {
		if err := s.startXoT(cfg, handler.zones, transferMgr, logger); err != nil {
			return s, err
		}
	}

	return s, nil
}

// startTLS starts the DNS-over-TLS server.
func (s *servers) startTLS(cfg *config.Config, handler *integratedHandler, logger *util.Logger) error {
	tlsAddr := cfg.Server.TLS.Bind
	if tlsAddr == "" {
		tlsAddr = fmt.Sprintf(":%d", server.DefaultTLSPort)
	}

	tlsConfig, err := buildTLSConfig(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
	if err != nil {
		return fmt.Errorf("loading TLS certificate: %w", err)
	}

	s.tls = server.NewTLSServer(tlsAddr, handler, tlsConfig)
	if err := s.tls.Listen(); err != nil {
		return fmt.Errorf("starting TLS server: %w", err)
	}
	go func() {
		if err := s.tls.Serve(); err != nil {
			logger.Errorf("TLS server error: %v", err)
		}
	}()
	logger.Infof("TLS server listening on %s (DoT)", tlsAddr)
	return nil
}

// startDoQ starts the DNS-over-QUIC server (RFC 9250).
func (s *servers) startDoQ(cfg *config.Config, handler *integratedHandler, logger *util.Logger) error {
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
	s.doq = quic.NewDoQServer(doqAddr, doqHandler, quicTLSConfig)
	if err := s.doq.Listen(); err != nil {
		return fmt.Errorf("starting DoQ server: %w", err)
	}
	go func() {
		if err := s.doq.Serve(); err != nil {
			logger.Errorf("DoQ server error: %v", err)
		}
	}()
	logger.Infof("DoQ server listening on %s (DNS over QUIC)", doqAddr)
	return nil
}

// startXoT starts the DNS Zone Transfer over TLS server (RFC 9103).
func (s *servers) startXoT(cfg *config.Config, zones map[string]*zone.Zone, transferMgr *TransferManager, logger *util.Logger) error {
	xotAddr := cfg.Server.XoT.Bind
	if xotAddr == "" {
		xotAddr = fmt.Sprintf(":%d", 853)
	}

	xotConfig := &transfer.XoTConfig{
		CertFile:        cfg.Server.XoT.CertFile,
		KeyFile:         cfg.Server.XoT.KeyFile,
		CAFile:          cfg.Server.XoT.CAFile,
		ListenPort:      853,
		MinTLSVersion:   cfg.Server.XoT.MinTLSVersion,
		AllowedNetworks: cfg.Server.XoT.AllowedNetworks,
	}

	// Reuse TLS cert if XoT cert not specifically configured
	if xotConfig.CertFile == "" && cfg.Server.TLS.CertFile != "" {
		xotConfig.CertFile = cfg.Server.TLS.CertFile
		xotConfig.KeyFile = cfg.Server.TLS.KeyFile
	}
	if xotConfig.CertFile == "" || xotConfig.KeyFile == "" {
		return fmt.Errorf("XoT enabled but cert_file/key_file not configured")
	}

	var err error
	s.xot, err = transfer.NewXoTServer(zones, xotConfig, logger)
	if err != nil {
		return fmt.Errorf("creating XoT server: %w", err)
	}
	s.xot.SetJournalStore(transferMgr.Result().JournalStore)

	if err := s.xot.Serve(xotAddr); err != nil {
		return fmt.Errorf("starting XoT server: %w", err)
	}
	go s.xot.AcceptLoop()
	logger.Infof("XoT server listening on %s (DNS Zone Transfer over TLS, RFC 9103)", s.xot.Addr())
	return nil
}

// stopAll shuts down all transport servers. Each is stopped independently;
// failures are logged but do not prevent the remaining servers from
// shutting down.
func (s *servers) stopAll(logger *util.Logger) {
	if s.udp != nil {
		if err := s.udp.Stop(); err != nil {
			logger.Warnf("Failed to stop UDP server cleanly: %v", err)
		}
	}
	if s.tcp != nil {
		if err := s.tcp.Stop(); err != nil {
			logger.Warnf("Failed to stop TCP server cleanly: %v", err)
		}
	}
	if s.tls != nil {
		if err := s.tls.Stop(); err != nil {
			logger.Warnf("Failed to stop TLS server cleanly: %v", err)
		}
	}
	if s.doq != nil {
		if err := s.doq.Stop(); err != nil {
			logger.Warnf("Failed to stop DoQ server cleanly: %v", err)
		}
	}
	if s.xot != nil {
		if err := s.xot.Close(); err != nil {
			logger.Warnf("Failed to close XoT server cleanly: %v", err)
		}
	}
}

// buildTLSConfig creates a tls.Config for DoT with dynamic certificate
// reloading (supports Let's Encrypt auto-renewal without restart).
func buildTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		// Dynamic certificate loading — reloads on each handshake.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			updatedCert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, err
			}
			return &updatedCert, nil
		},
	}, nil
}

// startStatsCollector launches a background goroutine that periodically
// reads transport stats and reports them to the metrics collector.
// Stops when stopCh is closed.
func startStatsCollector(srvs *servers, metricsCollector metricsTransport, stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				if metricsCollector != nil && srvs.udp != nil && srvs.tcp != nil {
					us := srvs.udp.Stats()
					ts := srvs.tcp.Stats()
					metricsCollector.SetTransportStats(
						us.PacketsReceived, us.PacketsSent, us.Errors,
						ts.ConnectionsAccepted, ts.ConnectionsClosed, ts.MessagesReceived, ts.Errors,
					)
				}
			}
		}
	}()
}

// metricsTransport is the narrow interface for the stats collector.
type metricsTransport interface {
	SetTransportStats(
		udpRx, udpTx, udpErrors uint64,
		tcpConnAccepted, tcpConnClosed, tcpMsgRx, tcpErrors uint64,
	)
}
