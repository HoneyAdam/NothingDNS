package raft

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// ClusterIntegration integrates Raft consensus into the cluster.
type ClusterIntegration struct {
	node         *Node
	stateMachine *ZoneStateMachine
	transport    *TCPTransport
	rpcServer    *RPCServer
	wal          *WAL
	snapshotter  *Snapshotter
	logger       *util.Logger // structured logger; no raw log.Printf

	// Configuration
	config Config
	nodeID NodeID
	peers  []NodeID

	// Leadership tracking
	mu          sync.RWMutex
	isLeader    bool
	currentTerm Term

	// Applied index tracking
	appliedIndex    Index
	lastAppliedTerm Term

	// applyHook, when set, is invoked with each committed ZoneCommand so the
	// real zone store can be updated. Guarded by mu.
	applyHook func(ZoneCommand)

	stopCh   chan struct{}
	stopOnce sync.Once // guards Stop() against second-call panic
	wg       sync.WaitGroup
}

// NewClusterIntegration creates a new Raft cluster integration.
// encryptionKey is a hex-encoded 32-byte AES-256 key used for the
// network/transport AEAD. If empty, transport AEAD is disabled
// (dev-only; production must supply a key).
//
// snapshotEncryptionKey, when set, is an independent hex-encoded
// 32-byte AES-256 key used for on-disk snapshot encryption (L-6).
// Empty leaves snapshots in plaintext (existing behaviour).
func NewClusterIntegration(nodeID NodeID, peers []NodeID, addr string, dataDir string, encryptionKey, snapshotEncryptionKey string, logger *util.Logger) (*ClusterIntegration, error) {
	config := DefaultConfig()
	config.NodeID = nodeID

	// Derive AEAD from the cluster encryption key (same scheme as gossip).
	var aead cipher.AEAD
	if encryptionKey != "" {
		key, err := hex.DecodeString(encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("invalid encryption key hex: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("encryption key must be 32 bytes (%d provided)", len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("aes cipher: %w", err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("gcm: %w", err)
		}
		// Warn if running without transport-level encryption.
		// Note: the gossip protocol uses AES-256-GCM with per-sender sequence tracking.
	}

	// Create transport with AEAD encryption (nil AEAD = plaintext for dev).
	transport := NewTCPTransport(nil, aead)

	// Set peer addresses (simplified — would be looked up from config).
	for _, peerID := range peers {
		transport.SetPeerAddr(peerID, string(peerID)) // Placeholder.
	}

	// Create Raft node.
	node := NewNode(config, peers, transport)

	// ONE shared state machine. The node uses it for snapshot install
	// (Restore), and the apply loop below uses the same instance to apply
	// committed entries and to serve reads. The previous code created two
	// independent ZoneStateMachines — snapshot restores landed in the
	// node's copy while every read went to ci's copy, so a follower that
	// installed a snapshot served permanently stale zone data.
	stateMachine := NewZoneStateMachine()
	node.SetStateMachine(stateMachine)

	// Create RPC server with AEAD encryption.
	rpcServer, err := NewRPCServer(addr, node, nil, aead)
	if err != nil {
		return nil, fmt.Errorf("rpc server: %w", err)
	}

	// Create WAL.
	wal, err := NewWAL(dataDir + "/raft-wal")
	if err != nil {
		return nil, fmt.Errorf("wal: %w", err)
	}

	// Load WAL entries into node, then install the WAL as the node's durable
	// log persister so future appends/truncations are written through.
	if entries, err := wal.ReadAll(); err == nil && len(entries) > 0 {
		// Replay entries into node's log.
		node.log = append(node.log, entries...)
	}
	node.SetLogPersister(wal)

	// Create snapshotter — L-6: encrypted at rest if a snapshot key
	// is provided. The hex decode mirrors the transport-AEAD path
	// above; config.Validate already enforces 32-byte hex + key
	// separation from EncryptionKey.
	var snapAeadKey []byte
	if snapshotEncryptionKey != "" {
		key, err := hex.DecodeString(snapshotEncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("invalid snapshot encryption key hex: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("snapshot encryption key must be 32 bytes (%d provided)", len(key))
		}
		snapAeadKey = key
	}
	snapshotter, err := NewSnapshotterEncrypted(dataDir+"/snapshots", snapAeadKey)
	if err != nil {
		return nil, fmt.Errorf("snapshotter: %w", err)
	}

	ci := &ClusterIntegration{
		node:         node,
		stateMachine: stateMachine, // SAME instance the node restores into
		transport:    transport,
		rpcServer:    rpcServer,
		wal:          wal,
		snapshotter:  snapshotter,
		logger:       logger,
		config:       config,
		nodeID:       nodeID,
		peers:        peers,
		stopCh:       make(chan struct{}),
	}

	return ci, nil
}

// Start starts the Raft integration.
func (ci *ClusterIntegration) Start() error {
	// Start RPC server
	ci.rpcServer.Start()

	// Wire up RPC handlers to use transport
	// In real implementation, node would use ci.transport for outbound RPC

	// Start Raft node
	ci.node.Start()

	// Start commit applier
	ci.wg.Add(1)
	go ci.applyLoop()

	// Start leadership tracker
	ci.wg.Add(1)
	go ci.leadershipLoop()

	return nil
}

// Stop stops the Raft integration. Idempotent — subsequent calls
// return nil without re-closing ci.stopCh (which would panic) or
// re-stopping the child components.
func (ci *ClusterIntegration) Stop() error {
	closed := false
	ci.stopOnce.Do(func() {
		close(ci.stopCh)
		closed = true
	})
	if !closed {
		return nil
	}
	ci.node.Stop()
	ci.rpcServer.Stop()
	ci.wal.Close()
	ci.wg.Wait()
	return nil
}

// applyLoop applies committed entries to the state machine.
func (ci *ClusterIntegration) applyLoop() {
	defer ci.wg.Done()

	for {
		select {
		case <-ci.stopCh:
			return
		case <-ci.node.CommitCh():
			// Collect the newly-committed entries under the node lock, then
			// apply them OUTSIDE it. stateMachine.Apply fires the zone-apply
			// hook (which writes through to the real zone store and may do
			// disk I/O); holding the Raft node lock across that would stall
			// heartbeats and replication. appliedIndex is advanced only AFTER
			// each entry's apply completes, so a caller waiting on
			// appliedIndex >= idx is guaranteed the store mutation is done.
			ci.node.mu.Lock()
			commitIdx := ci.node.commitIndex
			start := ci.appliedIndex + 1
			lastSnap := ci.node.lastSnapshot
			var pending []entry
			for i := start; i <= commitIdx; i++ {
				if i <= lastSnap {
					continue
				}
				pos := int(i - lastSnap - 1)
				if pos >= 0 && pos < len(ci.node.log) {
					pending = append(pending, ci.node.log[pos])
				}
			}
			ci.node.mu.Unlock()

			for _, e := range pending {
				if e.Term != 0 {
					if err := ci.stateMachine.Apply(e); err != nil {
						// F050: an apply failure means this node has diverged
						// from the cluster's intended state. Log loudly but
						// still advance appliedIndex — re-applying the same
						// failed entry would just busy-loop. Treat as Sev-1.
						ci.logger.Errorf("raft: stateMachine.Apply failed for index=%d term=%d: %v", e.Index, e.Term, err)
					}
					ci.runApplyHook(e)
				}
				ci.node.mu.Lock()
				ci.appliedIndex = e.Index
				ci.lastAppliedTerm = e.Term
				ci.node.mu.Unlock()
			}
		}
	}
}

// runApplyHook decodes a committed normal entry's ZoneCommand and forwards
// it to the registered apply hook (if any). Runs outside the Raft node lock.
func (ci *ClusterIntegration) runApplyHook(e entry) {
	if e.Type != EntryNormal || len(e.Command) == 0 {
		return
	}
	ci.mu.RLock()
	hook := ci.applyHook
	ci.mu.RUnlock()
	if hook == nil {
		return
	}
	var cmd ZoneCommand
	if err := json.Unmarshal(e.Command, &cmd); err != nil {
		ci.logger.Errorf("raft: apply-hook decode failed for index=%d: %v", e.Index, err)
		return
	}
	hook(cmd)
}

// leadershipLoop tracks leadership changes.
func (ci *ClusterIntegration) leadershipLoop() {
	defer ci.wg.Done()

	for {
		select {
		case <-ci.stopCh:
			return
		case state := <-ci.node.LeadershipCh():
			ci.mu.Lock()
			ci.isLeader = (state.State == StateLeader)
			ci.currentTerm = state.Term
			ci.mu.Unlock()
		}
	}
}

// IsLeader returns true if this node is the current leader.
func (ci *ClusterIntegration) IsLeader() bool {
	ci.mu.RLock()
	defer ci.mu.RUnlock()
	return ci.isLeader
}

// ProposeZoneChange proposes a zone change for consensus.
func (ci *ClusterIntegration) ProposeZoneChange(cmd ZoneCommand) error {
	data, err := json.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	if err := ci.node.Propose(data, EntryNormal); err != nil {
		return fmt.Errorf("propose: %w", err)
	}

	return nil
}

// ProposeZoneChangeWait replicates cmd through Raft and blocks until it has
// been applied locally (so the zone store reflects it) or the timeout
// elapses. Must be called on the leader — otherwise the underlying propose
// returns a "not leader" error.
func (ci *ClusterIntegration) ProposeZoneChangeWait(cmd ZoneCommand, timeout time.Duration) error {
	data, err := json.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	idx, err := ci.node.ProposeEntry(data, EntryNormal)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		if ci.AppliedIndex() >= idx {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("raft: zone change at index %d not applied within %s", idx, timeout)
		}
		select {
		case <-ci.stopCh:
			return fmt.Errorf("raft: shutting down before zone change applied")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// AppliedIndex returns the highest log index applied to the state machine.
func (ci *ClusterIntegration) AppliedIndex() Index {
	ci.node.mu.Lock()
	defer ci.node.mu.Unlock()
	return ci.appliedIndex
}

// SetApplyHook installs fn, called with each committed ZoneCommand as it is
// applied on this node (leader and followers alike), so the real DNS zone
// store stays in sync. Fires for every command type, independent of how the
// in-memory ledger models it.
func (ci *ClusterIntegration) SetApplyHook(fn func(ZoneCommand)) {
	ci.mu.Lock()
	ci.applyHook = fn
	ci.mu.Unlock()
}

// GetLeaderID returns the current leader's node ID. If this node is the
// leader, returns its own ID; otherwise returns the leader ID learned
// via AppendEntries, or "" if no leader has been observed yet.
func (ci *ClusterIntegration) GetLeaderID() NodeID {
	ci.mu.RLock()
	isLdr := ci.isLeader
	ci.mu.RUnlock()

	if isLdr {
		return ci.nodeID
	}
	return ci.node.LeaderID()
}

// ErrNotLeader is returned by AddNode/RemoveNode when this node is not
// the Raft leader. Callers can read LeaderID to redirect the request
// to the right node. LeaderID is "" if no leader has been observed yet
// (the cluster may be in an election).
type ErrNotLeader struct {
	LeaderID NodeID
}

func (e *ErrNotLeader) Error() string {
	if e.LeaderID == "" {
		return "raft: not the leader; leader unknown (cluster may be in election)"
	}
	return fmt.Sprintf("raft: not the leader; retry against %s", e.LeaderID)
}

// AddNode proposes adding a new node to the Raft cluster using joint
// consensus. Returns *ErrNotLeader (with the known leader ID, when
// available) if this node is not the leader.
func (ci *ClusterIntegration) AddNode(nodeID NodeID, addr string) error {
	if !ci.IsLeader() {
		return &ErrNotLeader{LeaderID: ci.node.LeaderID()}
	}

	return ci.node.AddPeer(nodeID, addr)
}

// RemoveNode proposes removing a node from the Raft cluster. Returns
// *ErrNotLeader when called on a follower.
func (ci *ClusterIntegration) RemoveNode(nodeID NodeID) error {
	if !ci.IsLeader() {
		return &ErrNotLeader{LeaderID: ci.node.LeaderID()}
	}

	ci.node.mu.Lock()
	defer ci.node.mu.Unlock()

	if ci.node.pendingConfChange != nil {
		return fmt.Errorf("cluster is already processing a configuration change")
	}

	// Create the joint config entry
	oldPeers := make(map[NodeID]*Peer)
	for pid, p := range ci.node.peers {
		if pid != nodeID {
			oldPeers[pid] = p
		}
	}
	if _, ok := oldPeers[nodeID]; !ok {
		return fmt.Errorf("node %s is not in the cluster", nodeID)
	}

	newPeers := make(map[NodeID]*Peer)
	for pid, p := range ci.node.peers {
		if pid != nodeID {
			newPeers[pid] = p
		}
	}

	jointConfig := NewJointConfig(ci.node.peers, newPeers)
	jcBytes, err := encodeJointConfig(jointConfig)
	if err != nil {
		return fmt.Errorf("encode joint config: %w", err)
	}

	// Append joint config entry
	entry := entry{
		Index:   Index(len(ci.node.log)) + 1,
		Term:    ci.node.currentTerm,
		Command: jcBytes,
		Type:    EntryRemoveNode,
	}
	ci.node.log = append(ci.node.log, entry)

	// Store joint config reference
	ci.node.jointConfig = jointConfig
	ci.node.jointConfigIdx = entry.Index
	ci.node.pendingConfChange = &JointConfigProposal{
		Type:   EntryRemoveNode,
		PeerID: nodeID,
	}

	return nil
}

// Stats returns cluster statistics.
//
// ci.appliedIndex is written by applyLoop under ci.node.mu.Lock();
// reading it outside that lock was a data race against the
// concurrent commit applier. While uint64 stores are atomic at the
// hardware level on every platform we target, the Go memory model
// still requires synchronization for cross-goroutine visibility,
// and the race detector flagged this site. Snapshot appliedIndex
// inside the same ci.node.mu critical section that captures
// state and commitIndex — those three values are then a coherent
// view of the same instant.
func (ci *ClusterIntegration) Stats() ClusterStats {
	ci.mu.RLock()
	isLeader := ci.isLeader
	term := ci.currentTerm
	ci.mu.RUnlock()

	ci.node.mu.Lock()
	state := ci.node.state
	commitIdx := ci.node.commitIndex
	applied := ci.appliedIndex
	ci.node.mu.Unlock()

	return ClusterStats{
		NodeID:       ci.nodeID,
		State:        state.String(),
		Term:         int64(term),
		CommitIndex:  int64(commitIdx),
		AppliedIndex: int64(applied),
		IsLeader:     isLeader,
	}
}

// ClusterStats contains cluster statistics.
type ClusterStats struct {
	NodeID       NodeID
	State        string
	Term         int64
	CommitIndex  int64
	AppliedIndex int64
	IsLeader     bool
}

// ProposeAddRecord proposes adding a record to a zone.
func (ci *ClusterIntegration) ProposeAddRecord(zone, name string, rrtype uint16, ttl uint32, rdata string) error {
	cmd := ZoneCommand{
		Type:   "add_record",
		Zone:   zone,
		Name:   name,
		RRType: rrtype,
		TTL:    ttl,
		RData:  []string{rdata},
	}
	return ci.ProposeZoneChange(cmd)
}

// ProposeDeleteRecord proposes deleting a record from a zone.
func (ci *ClusterIntegration) ProposeDeleteRecord(zone, name string, rrtype uint16) error {
	cmd := ZoneCommand{
		Type:   "del_record",
		Zone:   zone,
		Name:   name,
		RRType: rrtype,
	}
	return ci.ProposeZoneChange(cmd)
}

// GetZoneData returns zone data from the state machine.
func (ci *ClusterIntegration) GetZoneData(zone string) []RecordEntry {
	return ci.stateMachine.GetRecords(zone)
}
