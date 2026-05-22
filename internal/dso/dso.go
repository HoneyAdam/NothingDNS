// Package dso implements DNS Stateful Operations (DSO) per RFC 8490.
// DSO enables long-lived TCP connections with session management,
// keepalive, and redirect functionality.
package dso

import (
	cryptorand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

// DSO Header constants per RFC 8490
const (
	// Message type flags
	DSOTypeRequest  = 0x0000
	DSOTypeResponse = 0x8000

	// TLV types per RFC 8490 Section 4
	DSOTLVPadding        = 0x00 // Padding TLV
	DSOTLVKeepalive      = 0x01 // Keepalive TLV
	DSOTLVRetryDelay     = 0x02 // Retry Delay TLV
	DSOTLVSessionID      = 0x03 // Session ID TLV
	DSOTLVEncryption     = 0x04 // Encryption Negotiation TLV
	DSOTLVMaximumPayload = 0x05 // Maximum Payload Size TLV

	// RFC 8490 Section 4.1.1: Default inactivity timeout is 15 seconds
	DefaultInactivityTimeout = 15 * time.Second

	// RFC 8490 Section 4.1.1: Keepalive interval minimum is 1 second
	MinKeepaliveInterval = 1 * time.Second

	// Default maximum payload size
	DefaultMaxPayloadSize = 65535
)

// DSORCode represents DSO-specific response codes per RFC 8490.
type DSORCode uint16

const (
	// DSO success
	DSOCodeNoError DSORCode = 0

	// DSO-specific errors (RFC 8490 Section 5)
	DSOCodeInvalidDSO     DSORCode = 1 // Malformed DSO message
	DSOCodeUnsolicited    DSORCode = 2 // Unsolicited response
	DSOCodeRetry          DSORCode = 3 // Retry with delay
	DSOCodeEncryptionReq  DSORCode = 4 // Encryption required
	DSOCodeEncryptionNot  DSORCode = 5 // Encryption not available
	DSOCodeSessionExpired DSORCode = 6 // Session expired
	DSOCodeSessionClosed  DSORCode = 7 // Session closed
)

// Session represents a DSO session.
type Session struct {
	ID            uint64
	Conn          net.Conn
	RemoteAddr    net.Addr
	CreatedAt     time.Time
	LastActivity  time.Time
	KeepaliveTime time.Duration
	MaxPayload    uint16

	// Session state
	mu                sync.RWMutex
	closed            bool
	keepalivesEnabled bool

	// Channels for coordination
	stopCh chan struct{}
	doneCh chan struct{}
}

// IsExpired returns true if the session has exceeded its inactivity timeout.
func (s *Session) IsExpired(timeout time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.LastActivity) > timeout
}

// Close closes the session.
func (s *Session) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()

	close(s.stopCh)
	if s.Conn != nil {
		s.Conn.Close()
	}
	close(s.doneCh)
}

// UpdateActivity updates the last activity timestamp.
func (s *Session) UpdateActivity() {
	s.mu.Lock()
	s.LastActivity = time.Now()
	s.mu.Unlock()
}

// IsClosed returns true if the session is closed.
func (s *Session) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// TLV represents a DSO Type-Length-Value structure.
type TLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

// Size returns the total size of the TLV in bytes.
func (t *TLV) Size() int {
	return 4 + len(t.Value) // Type(2) + Length(2) + Value
}

// Pack serializes the TLV to wire format.
func (t *TLV) Pack(buf []byte, offset int) (int, error) {
	if offset+t.Size() > len(buf) {
		return 0, fmt.Errorf("buffer too small for TLV")
	}

	binary.BigEndian.PutUint16(buf[offset:], t.Type)
	binary.BigEndian.PutUint16(buf[offset+2:], uint16(len(t.Value)))
	copy(buf[offset+4:], t.Value)

	return t.Size(), nil
}

// UnpackTLV deserializes a TLV from wire format.
func UnpackTLV(buf []byte, offset int) (*TLV, int, error) {
	if offset+4 > len(buf) {
		return nil, 0, fmt.Errorf("buffer too small for TLV header")
	}

	tlv := &TLV{
		Type:   binary.BigEndian.Uint16(buf[offset:]),
		Length: binary.BigEndian.Uint16(buf[offset+2:]),
	}

	if offset+4+int(tlv.Length) > len(buf) {
		return nil, 0, fmt.Errorf("buffer too small for TLV value")
	}

	tlv.Value = make([]byte, tlv.Length)
	copy(tlv.Value, buf[offset+4:offset+4+int(tlv.Length)])

	return tlv, 4 + int(tlv.Length), nil
}

// NewKeepaliveTLV creates a Keepalive TLV with primary and secondary timeouts.
func NewKeepaliveTLV(primaryTimeout, secondaryTimeout time.Duration) *TLV {
	// RFC 8490 Section 4.1: Keepalive TLV format
	// Timeout values are in units of 100 milliseconds
	primary := uint32(primaryTimeout.Milliseconds() / 100)
	secondary := uint32(secondaryTimeout.Milliseconds() / 100)

	value := make([]byte, 8)
	binary.BigEndian.PutUint32(value[0:], primary)
	binary.BigEndian.PutUint32(value[4:], secondary)

	return &TLV{
		Type:  DSOTLVKeepalive,
		Value: value,
	}
}

// ParseKeepaliveTLV extracts timeout values from a Keepalive TLV.
func ParseKeepaliveTLV(tlv *TLV) (primary, secondary time.Duration, err error) {
	if tlv.Type != DSOTLVKeepalive {
		return 0, 0, fmt.Errorf("not a keepalive TLV")
	}
	if len(tlv.Value) != 8 {
		return 0, 0, fmt.Errorf("invalid keepalive TLV length: %d", len(tlv.Value))
	}

	primaryUnits := binary.BigEndian.Uint32(tlv.Value[0:])
	secondaryUnits := binary.BigEndian.Uint32(tlv.Value[4:])

	// Convert from 100ms units to Duration
	primary = time.Duration(primaryUnits) * 100 * time.Millisecond
	secondary = time.Duration(secondaryUnits) * 100 * time.Millisecond

	return primary, secondary, nil
}

// NewSessionIDTLV creates a Session ID TLV.
func NewSessionIDTLV(sessionID uint64) *TLV {
	value := make([]byte, 8)
	binary.BigEndian.PutUint64(value, sessionID)

	return &TLV{
		Type:  DSOTLVSessionID,
		Value: value,
	}
}

// ParseSessionIDTLV extracts the session ID from a Session ID TLV.
func ParseSessionIDTLV(tlv *TLV) (uint64, error) {
	if tlv.Type != DSOTLVSessionID {
		return 0, fmt.Errorf("not a session ID TLV")
	}
	if len(tlv.Value) != 8 {
		return 0, fmt.Errorf("invalid session ID TLV length: %d", len(tlv.Value))
	}

	return binary.BigEndian.Uint64(tlv.Value), nil
}

// NewRetryDelayTLV creates a Retry Delay TLV.
func NewRetryDelayTLV(delay time.Duration) *TLV {
	// Delay in units of 100 milliseconds
	units := uint32(delay.Milliseconds() / 100)

	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, units)

	return &TLV{
		Type:  DSOTLVRetryDelay,
		Value: value,
	}
}

// NewMaximumPayloadTLV creates a Maximum Payload Size TLV.
func NewMaximumPayloadTLV(maxPayload uint16) *TLV {
	value := make([]byte, 2)
	binary.BigEndian.PutUint16(value, maxPayload)

	return &TLV{
		Type:  DSOTLVMaximumPayload,
		Value: value,
	}
}

// NewPaddingTLV creates a Padding TLV with specified length.
func NewPaddingTLV(length uint16) *TLV {
	return &TLV{
		Type:  DSOTLVPadding,
		Value: make([]byte, length),
	}
}

// Manager manages DSO sessions.
type Manager struct {
	sessions   map[uint64]*Session
	sessionsMu sync.RWMutex

	// Configuration
	inactivityTimeout time.Duration
	maxSessions       int
	allowPlainTCP     bool
	maxPayloadSize    uint16

	// Session ID generator (crypto/rand-backed; counter is a fallback only)
	nextSessionID uint64
	sessionIDMu   sync.Mutex

	// startOnce guards Start() from racy double-fires
	startOnce sync.Once

	// Logger
	logger *util.Logger

	// Control
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// Config holds DSO manager configuration.
type Config struct {
	Enabled           bool
	InactivityTimeout time.Duration
	MaxSessions       int
	MaxPayloadSize    uint16

	// AllowPlainTCP relaxes the RFC 8490 §5.1 requirement that DSO sessions
	// run only over TLS / DoT / DoQ. Default false (TLS required). Only enable
	// for unit tests or trusted-network deployments where the underlying
	// transport is independently secured (e.g. WireGuard tunnels).
	AllowPlainTCP bool
}

// DefaultConfig returns default DSO configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:           false,
		InactivityTimeout: DefaultInactivityTimeout,
		MaxSessions:       1000,
		MaxPayloadSize:    DefaultMaxPayloadSize,
	}
}

// NewManager creates a new DSO session manager.
func NewManager(config Config, logger *util.Logger) *Manager {
	if config.InactivityTimeout == 0 {
		config.InactivityTimeout = DefaultInactivityTimeout
	}
	if config.MaxPayloadSize == 0 {
		config.MaxPayloadSize = DefaultMaxPayloadSize
	}
	if config.MaxSessions == 0 {
		config.MaxSessions = 1000
	}

	return &Manager{
		sessions:          make(map[uint64]*Session),
		inactivityTimeout: config.InactivityTimeout,
		maxSessions:       config.MaxSessions,
		maxPayloadSize:    config.MaxPayloadSize,
		allowPlainTCP:     config.AllowPlainTCP,
		logger:            logger,
		stopCh:            make(chan struct{}),
	}
}

// Start starts the DSO manager's background tasks. Idempotent: subsequent
// calls are no-ops thanks to the startOnce gate (TryLock-based deduplication
// was racy because two callers could each observe a free lock in different
// microseconds and both fire cleanupLoop).
func (m *Manager) Start() {
	m.startOnce.Do(func() {
		m.wg.Add(1)
		go m.cleanupLoop()
		if m.logger != nil {
			m.logger.Info("DSO manager started")
		}
	})
}

// Stop stops the DSO manager.
func (m *Manager) Stop() {
	close(m.stopCh)

	// Close all sessions
	m.sessionsMu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.sessions = make(map[uint64]*Session)
	m.sessionsMu.Unlock()

	for _, s := range sessions {
		s.Close()
	}

	m.wg.Wait()

	if m.logger != nil {
		m.logger.Info("DSO manager stopped")
	}
}

// CreateSession creates a new DSO session.
//
// RFC 8490 §5.1 mandates that DSO operate ONLY over an encrypted transport
// (DoT / DoH / DoQ). We enforce that here by requiring conn to be a
// *tls.Conn unless the operator has explicitly opted in to plain TCP via
// Config.AllowPlainTCP (intended for tests / trusted internal networks).
func (m *Manager) CreateSession(conn net.Conn) (*Session, error) {
	if !m.allowPlainTCP {
		if _, ok := conn.(*tls.Conn); !ok {
			return nil, fmt.Errorf("dso: RFC 8490 §5.1 requires TLS; refusing plain TCP connection from %s", conn.RemoteAddr())
		}
	}

	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	if len(m.sessions) >= m.maxSessions {
		return nil, fmt.Errorf("maximum sessions reached: %d", m.maxSessions)
	}

	id := m.generateSessionID()
	now := time.Now()

	session := &Session{
		ID:            id,
		Conn:          conn,
		RemoteAddr:    conn.RemoteAddr(),
		CreatedAt:     now,
		LastActivity:  now,
		KeepaliveTime: m.inactivityTimeout / 3,
		MaxPayload:    m.maxPayloadSize,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}

	m.sessions[id] = session

	if m.logger != nil {
		m.logger.Infof("DSO session %d created from %s", id, conn.RemoteAddr())
	}

	return session, nil
}

// GetSession retrieves a session by ID.
func (m *Manager) GetSession(id uint64) *Session {
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()
	return m.sessions[id]
}

// RemoveSession removes a session.
func (m *Manager) RemoveSession(id uint64) {
	m.sessionsMu.Lock()
	session, ok := m.sessions[id]
	delete(m.sessions, id)
	m.sessionsMu.Unlock()

	if ok {
		session.Close()
		if m.logger != nil {
			m.logger.Infof("DSO session %d removed", id)
		}
	}
}

// SessionCount returns the number of active sessions.
func (m *Manager) SessionCount() int {
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()
	return len(m.sessions)
}

// generateSessionID returns a fresh, unpredictable 64-bit session ID.
//
// RFC 8490 §6.6.1.2 requires session identifiers to be unpredictable so an
// off-path attacker cannot guess and hijack an active session. The previous
// implementation just incremented a uint64 counter — that gave attackers the
// next session's ID with zero work. We now draw from crypto/rand and fall
// back to the counter only if the system entropy source is unavailable,
// matching the defensive pattern used by the resolver's transaction-ID
// generator.
func (m *Manager) generateSessionID() uint64 {
	var b [8]byte
	if _, err := cryptorand.Read(b[:]); err == nil {
		id := binary.BigEndian.Uint64(b[:])
		// Reserve ID 0 as "unassigned" sentinel; redraw rather than return it.
		if id != 0 {
			return id
		}
	}
	// crypto/rand failure: fall back to the monotonic counter so we still
	// produce a unique (but predictable) ID. The keeper at least logs.
	m.sessionIDMu.Lock()
	defer m.sessionIDMu.Unlock()
	m.nextSessionID++
	if m.logger != nil {
		m.logger.Warnf("crypto/rand unavailable; falling back to sequential session ID %d", m.nextSessionID)
	}
	return m.nextSessionID
}

// cleanupLoop periodically removes expired sessions.
func (m *Manager) cleanupLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.cleanupExpiredSessions()
		}
	}
}

// cleanupExpiredSessions removes expired sessions.
func (m *Manager) cleanupExpiredSessions() {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	now := time.Now()
	for id, session := range m.sessions {
		if now.Sub(session.LastActivity) > m.inactivityTimeout {
			session.Close()
			delete(m.sessions, id)
			if m.logger != nil {
				m.logger.Infof("DSO session %d expired and removed", id)
			}
		}
	}
}

// HandleDSORequest handles a DSO request message.
func (m *Manager) HandleDSORequest(session *Session, msg *protocol.Message) (*protocol.Message, error) {
	// Update activity
	session.UpdateActivity()

	// Parse TLVs from additional section
	tlvBuf, err := m.extractTLVs(msg)
	if err != nil {
		return nil, fmt.Errorf("extracting TLVs: %w", err)
	}

	// Process TLVs
	var responseTLVs []*TLV
	for len(tlvBuf) > 0 {
		tlv, consumed, err := UnpackTLV(tlvBuf, 0)
		if err != nil {
			return nil, fmt.Errorf("unpacking TLV: %w", err)
		}

		switch tlv.Type {
		case DSOTLVKeepalive:
			// Process keepalive request and respond
			primary, secondary, err := ParseKeepaliveTLV(tlv)
			if err != nil {
				return nil, err
			}
			session.KeepaliveTime = primary
			session.keepalivesEnabled = true
			responseTLVs = append(responseTLVs, NewKeepaliveTLV(primary, secondary))

		case DSOTLVMaximumPayload:
			// Acknowledge max payload
			if len(tlv.Value) >= 2 {
				maxPayload := binary.BigEndian.Uint16(tlv.Value)
				if maxPayload > 0 && maxPayload < session.MaxPayload {
					session.MaxPayload = maxPayload
				}
				responseTLVs = append(responseTLVs, NewMaximumPayloadTLV(session.MaxPayload))
			}

		case DSOTLVPadding:
			// Ignore padding in requests

		case DSOTLVRetryDelay:
			// Not valid in requests
			return nil, fmt.Errorf("retry delay TLV not allowed in requests")

		default:
			// Unknown TLV - send DSO code 1 (Invalid DSO)
			return nil, fmt.Errorf("unknown TLV type: %d", tlv.Type)
		}

		tlvBuf = tlvBuf[consumed:]
	}

	// Build response
	response := m.buildDSOResponse(msg, responseTLVs)
	return response, nil
}

// extractTLVs extracts the TLV data carried by a DSO message.
//
// F127: DSO wire format (RFC 8490 §5.2) does not place TLVs in OPT records
// in the Additional section. A DSO message uses OPCODE 6, an empty
// Question/Answer/Authority/Additional set, and an unframed TLV stream
// directly in the message body. NothingDNS still routes incoming queries
// through the standard DNS message parser, which discards anything that
// isn't a recognised section — so by the time HandleDSORequest sees the
// *protocol.Message there is no body buffer to read TLVs from.
//
// Implementing real DSO parsing requires plumbing the raw wire bytes
// through ServeDNS as well as a proper DSO-mode message decoder. Until
// that lands, this function fails loud so HandleDSORequest cannot pretend
// to have processed an empty TLV list and silently no-op every request.
func (m *Manager) extractTLVs(msg *protocol.Message) ([]byte, error) {
	_ = msg
	return nil, fmt.Errorf("dso: TLV extraction not implemented (RFC 8490 §5.2 requires raw-body parsing path; tracked as F127)")
}

// buildDSOResponse builds a DSO response message.
func (m *Manager) buildDSOResponse(request *protocol.Message, tlvs []*TLV) *protocol.Message {
	// Clone the request header
	response := &protocol.Message{
		Header: request.Header,
	}

	// Set response flag (QR = true for response)
	response.Header.Flags.QR = true

	// DSO responses use RCODE=0 (NOERROR) with response TLVs in additional section
	response.Header.ARCount = uint16(len(tlvs))

	return response
}

// SendKeepalive would send an unsolicited DSO keepalive on the session.
//
// F129: the previous implementation built a TLV and a message header, then
// silently dropped both — no bytes were actually written to session.Conn.
// Pretending to send a keepalive while doing nothing causes any
// inactivity-timeout countdown the peer is running to expire and tear
// down the session shortly after we claim to keep it alive.
//
// A correct implementation requires the DSO wire-format serialiser
// (paired with the parser tracked as F127). Until that lands, fail loud
// so callers cannot rely on a phantom keepalive.
func (m *Manager) SendKeepalive(session *Session) error {
	if session.IsClosed() {
		return fmt.Errorf("session closed")
	}
	return fmt.Errorf("dso: SendKeepalive not implemented (no DSO wire-format serialiser yet; tracked as F129)")
}

// IsDSOMessage checks if a message is a DSO message.
func IsDSOMessage(msg *protocol.Message) bool {
	// DSO messages have OPCODE 6
	return msg.Header.Flags.Opcode == 6
}

// CreateDSOMessage creates a new DSO message with given TLVs.
func CreateDSOMessage(tlvs []*TLV) (*protocol.Message, error) {
	msg := &protocol.Message{
		Header: protocol.Header{
			ID: 0, // DSO uses ID=0
			Flags: protocol.Flags{
				QR:     false, // Query
				Opcode: 6,     // DSO
			},
			QDCount: 0,
			ANCount: 0,
			NSCount: 0,
			ARCount: uint16(len(tlvs)),
		},
	}

	return msg, nil
}

// Handler is an interface for handling DSO messages.
type Handler interface {
	HandleDSO(session *Session, msg *protocol.Message) (*protocol.Message, error)
}
