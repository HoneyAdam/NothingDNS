package raft

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// raftRPCTimeout bounds each outgoing RPC. Without a timeout a transport
// call that hangs (peer down, network partition) ties up a goroutine
// indefinitely. A 5 s timeout is long enough for a live peer but clears
// a blocked goroutine quickly when a node is unreachable.
const raftRPCTimeout = 5 * time.Second

// State represents the Raft node state.
type State int

const (
	StateFollower State = iota
	StateCandidate
	StateLeader
)

func (s State) String() string {
	switch s {
	case StateFollower:
		return "Follower"
	case StateCandidate:
		return "Candidate"
	case StateLeader:
		return "Leader"
	default:
		return "Unknown"
	}
}

// NodeID is a unique node identifier.
type NodeID string

// Term is the Raft term number.
type Term uint64

// Index is the log index.
type Index uint64

// Config configures the Raft node.
type Config struct {
	NodeID            NodeID
	HeartbeatInterval time.Duration // Interval between heartbeats
	ElectionTimeout   time.Duration // Election timeout (should be >> heartbeat)
	MaxLogEntries     int           // Max entries per AppendEntries call
	SnapshotInterval  time.Duration // How often to snapshot

	// DataDir is the directory where Raft persists HardState (currentTerm
	// and votedFor) per RFC §5.1. Leaving this empty disables persistence —
	// which is unsafe for production: a restart loses all votes and the
	// node may vote twice in the same term, violating election safety.
	// Tests may use a temp dir; production deployments must set this
	// alongside the WAL directory.
	DataDir string
}

// DefaultConfig returns a default Raft configuration.
func DefaultConfig() Config {
	return Config{
		HeartbeatInterval: 150 * time.Millisecond,
		ElectionTimeout:   1000 * time.Millisecond,
		MaxLogEntries:     128,
		SnapshotInterval:  30 * time.Second,
	}
}

// entry is a single log entry.
type entry struct {
	Index      Index
	Term       Term
	Command    []byte // Application-specific command data
	Type       EntryType
	Commitment uint64 // Used for commit acknowledgment
}

// JointConfig represents a joint consensus configuration per RFC 7003.
// It contains both the old and new configurations during transitions.
type JointConfig struct {
	OldPeers map[NodeID]*Peer // Previous configuration
	NewPeers map[NodeID]*Peer // New configuration
}

// NewJointConfig creates a new joint config from old and new peer sets.
func NewJointConfig(oldPeers, newPeers map[NodeID]*Peer) *JointConfig {
	return &JointConfig{
		OldPeers: oldPeers,
		NewPeers: newPeers,
	}
}

// QuorumForConfig returns the quorum size for a given configuration.
func (jc *JointConfig) QuorumForConfig(peerSet map[NodeID]*Peer) int {
	return len(peerSet)/2 + 1
}

// HasQuorumOldAndNew checks if we have quorum in both old and new configurations.
// Per RFC 7003, for joint consensus, we need quorum from BOTH configurations.
func (jc *JointConfig) HasQuorumOldAndNew(matchIndex map[NodeID]Index, commitIdx Index) bool {
	// Count replicas in old config
	oldReplicas := 0
	for id := range jc.OldPeers {
		if matchIndex[id] >= commitIdx {
			oldReplicas++
		}
	}
	oldQuorum := jc.QuorumForConfig(jc.OldPeers)
	if oldReplicas < oldQuorum {
		return false
	}

	// Count replicas in new config
	newReplicas := 0
	for id := range jc.NewPeers {
		if matchIndex[id] >= commitIdx {
			newReplicas++
		}
	}
	newQuorum := jc.QuorumForConfig(jc.NewPeers)
	return newReplicas >= newQuorum
}

// IsInJoint returns true if we're currently in joint consensus.
func (n *Node) IsInJoint() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.jointConfig != nil
}

// JointConfigProposal describes a pending configuration change.
type JointConfigProposal struct {
	Type     EntryType // EntryAddNode or EntryRemoveNode
	PeerID   NodeID
	PeerAddr string
	Proposed time.Time // When this was proposed
}

// logPersister durably records Raft log mutations. Implemented by *WAL.
// All methods are called with the Node lock held, so implementations must
// not call back into the Node.
type logPersister interface {
	// Write appends a single log entry.
	Write(e entry) error
	// TruncateAfter discards entries with Index > keepThrough.
	TruncateAfter(keepThrough Index) error
	// Sync flushes buffered writes to stable storage.
	Sync() error
}

// StateMachine is the interface for the state machine that applies snapshots.
// Implemented by ZoneStateMachine.
type StateMachine interface {
	// Apply applies a Raft log entry to the state machine.
	Apply(entry) error
	// Snapshot returns a serialized snapshot of the current state.
	Snapshot() ([]byte, error)
	// Restore restores state from a serialized snapshot.
	Restore([]byte) error
}

// EntryType distinguishes different entry types.
type EntryType uint8

const (
	EntryNormal        EntryType = iota // Regular application command
	EntryNoOp                           // No-op entry for commit acknowledgment
	EntryAddNode                        // Add node to cluster (joint consensus phase 1)
	EntryRemoveNode                     // Remove node from cluster (joint consensus phase 1)
	EntryJointComplete                  // Joint consensus complete, using new config
)

// Node is a single Raft node.
type Node struct {
	config    Config
	transport Transport // Network transport for RPC

	// Persistent state (must survive crashes)
	mu          sync.Mutex
	currentTerm Term
	votedFor    NodeID
	log         []entry

	// Volatile state
	state            State
	commitIndex      Index
	lastApplied      Index
	lastSnapshot     Index // Highest index included in snapshot
	lastSnapshotTerm Term  // Term of the entry at lastSnapshot

	// leaderID is the most-recently-seen leader. Followers learn this
	// from AppendEntries (req.LeaderID). Candidates clear it on start
	// of an election; leaders set it to themselves on becomeLeader.
	// Used so cluster-membership clients calling Add/Remove on a
	// non-leader can be redirected to the right node.
	leaderID NodeID

	// Leader-specific volatile state
	nextIndex  map[NodeID]Index // For each peer, the next log index to send
	matchIndex map[NodeID]Index // For each peer, the highest replicated index

	// Membership
	peers map[NodeID]*Peer

	// Joint consensus state (RFC 7003)
	jointConfig       *JointConfig         // Current joint configuration (nil = using simple config)
	jointConfigIdx    Index                // Index of joint config entry in log
	pendingConfChange *JointConfigProposal // Pending configuration change proposal

	// State machine for applying snapshots (optional, set by ClusterIntegration)
	// When set, snapshot install will restore state from snapshot data
	stateMachine StateMachine

	// persister durably records log mutations (optional). When set, log
	// entries are written and fsynced before a Propose returns or a follower
	// acknowledges an AppendEntries, so committed entries survive a crash.
	persister logPersister

	// Channels
	voteCh       chan VoteRequest    // Incoming vote requests from RPC
	appendCh     chan AppendRequest  // Incoming append requests from RPC
	voteRespCh   chan VoteResponse   // Outgoing vote responses
	appendRespCh chan AppendResponse // Outgoing append responses
	commitCh     chan Commit
	applyCh      chan Apply
	snapshotCh   chan SnapshotRequest
	leadershipCh chan LeadershipState

	// electionResetCh carries "legitimate leader contact" events from the
	// RPC handlers (valid AppendEntries received, or a vote granted) to the
	// run loop. A follower resets its election timer on this; a candidate
	// steps down. Without it the run-loop timer fires on a fixed schedule
	// regardless of heartbeats, so every follower repeatedly times out and
	// challenges a healthy leader — the cluster livelocks and never settles.
	electionResetCh chan struct{}

	// Control
	stopCh   chan struct{}
	stopOnce sync.Once // guards Stop() against second-call panic
	wg       sync.WaitGroup

	// RNG for election timeout randomization
	rng *LockedRand
}

// Peer represents a Raft cluster peer.
type Peer struct {
	ID   NodeID
	Addr string // Network address for RPC
}

// VoteRequest is the RequestVote RPC arguments.
type VoteRequest struct {
	Term         Term
	CandidateID  NodeID
	LastLogIndex Index
	LastLogTerm  Term
}

// VoteResponse is the RequestVote RPC response.
type VoteResponse struct {
	Term        Term
	VoteGranted bool
	From        NodeID
}

// AppendRequest is the AppendEntries RPC arguments.
type AppendRequest struct {
	Term         Term
	LeaderID     NodeID
	PrevLogIndex Index
	PrevLogTerm  Term
	Entries      []entry
	LeaderCommit Index
}

// AppendResponse is the AppendEntries RPC response.
type AppendResponse struct {
	Term    Term
	Success bool
	From    NodeID
	// Optimization: hint for faster log reconciliation
	MatchIndex Index
	// For leader to track commitment
	Commitment uint64
}

// SnapshotRequest requests a snapshot install from the leader.
type SnapshotRequest struct {
	Term     Term
	LeaderID NodeID
	// Snapshot data
	Data []byte
	// Last included index/term in snapshot
	LastIndex Index
	LastTerm  Term
}

// Commit represents a committed entry ready to be applied.
type Commit struct {
	Entries []entry
}

// Apply represents an entry to be applied to the state machine.
type Apply struct {
	Entry entry
}

// LeadershipState indicates leadership changes.
type LeadershipState struct {
	State State
	Term  Term
}

// NewNode creates a new Raft node.
func NewNode(config Config, peers []NodeID, transport Transport) *Node {
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 150 * time.Millisecond
	}
	if config.ElectionTimeout == 0 {
		config.ElectionTimeout = 1000 * time.Millisecond
	}
	if config.MaxLogEntries == 0 {
		config.MaxLogEntries = 128
	}

	n := &Node{
		config:          config,
		transport:       transport,
		state:           StateFollower,
		currentTerm:     0,
		votedFor:        "",
		log:             make([]entry, 0),
		nextIndex:       make(map[NodeID]Index),
		matchIndex:      make(map[NodeID]Index),
		peers:           make(map[NodeID]*Peer),
		voteCh:          make(chan VoteRequest, 10),
		appendCh:        make(chan AppendRequest, 10),
		voteRespCh:      make(chan VoteResponse, 10),
		appendRespCh:    make(chan AppendResponse, 10),
		commitCh:        make(chan Commit, 10),
		applyCh:         make(chan Apply, 256),
		snapshotCh:      make(chan SnapshotRequest, 10),
		leadershipCh:    make(chan LeadershipState, 10),
		electionResetCh: make(chan struct{}, 1),
		stopCh:          make(chan struct{}),
		rng:             NewLockedRand(),
	}

	// Restore persistent HardState from disk so currentTerm and votedFor
	// survive a restart. Without this the node can grant the same term's
	// vote twice and violate election safety on the very first RPC after
	// reboot. If DataDir is empty (e.g. unit tests, in-memory clusters)
	// persistence is silently skipped — production callers must set it.
	if config.DataDir != "" {
		if hs, err := loadHardState(config.DataDir); err == nil {
			n.currentTerm = hs.CurrentTerm
			n.votedFor = hs.VotedFor
		}
	}

	// Initialize peer tracking
	for _, id := range peers {
		n.peers[id] = &Peer{ID: id}
		n.nextIndex[id] = 0
		n.matchIndex[id] = 0
	}

	return n
}

// setVotedForLocked records a vote for v and persists it before any
// response that depends on it can be sent. MUST be called with n.mu held.
func (n *Node) setVotedForLocked(v NodeID) {
	if v == n.votedFor {
		return
	}
	n.votedFor = v
	n.persistHardStateLocked()
}

// advanceTermLocked advances currentTerm to t, resets votedFor (Raft §5.1
// "first vote of a new term is fresh"), transitions to follower state, and
// persists the change to disk before returning. MUST be called with n.mu
// held. No-op when t is not greater than n.currentTerm.
func (n *Node) advanceTermLocked(t Term) {
	if t <= n.currentTerm {
		return
	}
	n.currentTerm = t
	n.state = StateFollower
	n.votedFor = ""
	n.persistHardStateLocked()
}

// persistHardStateLocked writes the current (currentTerm, votedFor) tuple
// to disk via the atomic+fsync helper. MUST be called with n.mu held so
// the values read are consistent with what's being persisted. Returns no
// error: persistence is best-effort here — a failure indicates a
// catastrophic environment problem (disk full, ENOMEM in fsync) that the
// surrounding RPC handler cannot meaningfully recover from. The error is
// surfaced via panic only if DataDir was explicitly configured but the
// write failed, so silent silent-data-loss never happens.
func (n *Node) persistHardStateLocked() {
	if n.config.DataDir == "" {
		return
	}
	hs := HardState{
		CurrentTerm: n.currentTerm,
		VotedFor:    n.votedFor,
	}
	if err := saveHardState(n.config.DataDir, hs); err != nil {
		// Surface the failure rather than silently continuing — a node
		// that thinks it persisted state but didn't is exactly the
		// election-safety violation we're trying to prevent.
		panic(fmt.Sprintf("raft: persisting HardState failed: %v (term=%d votedFor=%q)", err, hs.CurrentTerm, hs.VotedFor))
	}
}

// Start starts the Raft node's main loop.
func (n *Node) Start() {
	n.wg.Add(1)
	go n.run()
}

// Stop stops the Raft node. Idempotent — a second call is a no-op
// instead of the close-of-closed-channel panic the bare close would
// produce.
func (n *Node) Stop() {
	closed := false
	n.stopOnce.Do(func() {
		close(n.stopCh)
		closed = true
	})
	if !closed {
		return
	}
	n.wg.Wait()
}

// run is the main event loop.
func (n *Node) run() {
	defer n.wg.Done()

	electionTimer := n.newElectionTimer()
	defer electionTimer.Stop()

	for {
		// Exit promptly on Stop(): the inner state functions return when
		// stopCh closes, but without this guard run() would busy-loop
		// re-entering them forever and wg.Done (deferred above) would never
		// fire, hanging Stop().
		select {
		case <-n.stopCh:
			return
		default:
		}

		n.mu.Lock()
		state := n.state
		n.mu.Unlock()

		switch state {
		case StateFollower:
			n.runFollower(electionTimer)
		case StateCandidate:
			n.runCandidate()
		case StateLeader:
			n.runLeader()
		}
	}
}

// drainTimer empties a timer's channel after Stop so a stale fire can't be
// observed by the next Reset cycle.
func drainTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

// runFollower runs the follower state. The election timer is restarted on
// entry and every time the RPC layer reports legitimate leader contact, so
// a follower only becomes a candidate after a genuine silence.
func (n *Node) runFollower(electionTimer *time.Timer) {
	drainTimer(electionTimer)
	electionTimer.Reset(n.randomElectionTimeout())

	for {
		select {
		case <-n.stopCh:
			return
		case <-n.electionResetCh:
			// Heard from the leader (or granted a vote): restart the clock.
			drainTimer(electionTimer)
			electionTimer.Reset(n.randomElectionTimeout())
		case <-electionTimer.C:
			// Election timeout — become candidate. advanceTermLocked must
			// run FIRST: it bumps the term, clears votedFor AND forces state
			// back to Follower, so setting StateCandidate afterwards is what
			// actually leaves us a candidate. The reverse order (the original
			// bug) had advanceTermLocked silently stamp us back to Follower,
			// so the node only ever incremented its term and never campaigned.
			n.mu.Lock()
			n.advanceTermLocked(n.currentTerm + 1)
			n.state = StateCandidate
			n.mu.Unlock()
			return
		case req := <-n.voteCh:
			n.handleVoteRequest(req)
		case req := <-n.appendCh:
			n.handleAppendRequest(req)
		case req := <-n.snapshotCh:
			n.handleSnapshotRequest(req)
		}
	}
}

// runCandidate runs the candidate state.
func (n *Node) runCandidate() {
	// Vote for self (Raft §5.2). Persist before sending vote requests so a
	// restart can't lead us to vote again for someone else in the same term.
	n.mu.Lock()
	n.setVotedForLocked(n.config.NodeID)
	term := n.currentTerm
	lastLogIndex, lastLogTerm := n.lastLogInfo()
	n.mu.Unlock()

	// Request votes from all peers
	n.broadcastVoteRequest(term, lastLogIndex, lastLogTerm)

	// Collect votes
	voteCount := 1 // Vote for self
	quorum := n.quorumSize()

	// A self-vote may already be a majority (single-node cluster). Without
	// this early check the node would wait forever for vote responses that
	// no peer will ever send.
	if voteCount >= quorum {
		n.becomeLeader(term)
		return
	}

	electionTimer := n.newElectionTimer()

	for {
		select {
		case <-n.stopCh:
			return
		case <-electionTimer.C:
			// Election timeout — restart election. advanceTermLocked first
			// (it resets state to Follower); then mark candidate. See the
			// matching note in runFollower.
			n.mu.Lock()
			n.advanceTermLocked(n.currentTerm + 1)
			n.state = StateCandidate
			n.mu.Unlock()
			return
		case <-n.electionResetCh:
			// An RPC handler accepted another leader (or we granted a vote
			// and stepped down to follower). Abandon this candidacy and let
			// run() re-dispatch on the updated state.
			n.mu.Lock()
			stillCandidate := n.state == StateCandidate
			n.mu.Unlock()
			if !stillCandidate {
				return
			}
		case resp := <-n.voteRespCh:
			if resp.Term > term {
				// Discovered higher term — become follower
				n.becomeFollower(resp.Term)
				return
			}
			if resp.VoteGranted {
				voteCount++
				if voteCount >= quorum {
					// Won election — become leader
					n.becomeLeader(term)
					return
				}
			}
		case req := <-n.appendCh:
			n.handleAppendRequest(req)
		case req := <-n.snapshotCh:
			n.handleSnapshotRequest(req)
		}
	}
}

// runLeader runs the leader state.
func (n *Node) runLeader() {
	n.mu.Lock()
	term := n.currentTerm
	n.mu.Unlock()

	// Broadcast initial heartbeats
	n.broadcastHeartbeat(term)

	heartbeatTicker := time.NewTicker(n.config.HeartbeatInterval)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-n.stopCh:
			return
		case <-heartbeatTicker.C:
			n.mu.Lock()
			if n.state != StateLeader {
				n.mu.Unlock()
				return
			}
			currentTerm := n.currentTerm
			n.mu.Unlock()
			n.broadcastHeartbeat(currentTerm)
		case resp := <-n.appendRespCh:
			n.handleAppendResponse(resp)
		case req := <-n.snapshotCh:
			n.handleSnapshotRequest(req)
		}
	}
}

// handleVoteRequest handles a vote request.
func (n *Node) handleVoteRequest(req VoteRequest) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Reply false if term < currentTerm
	if req.Term < n.currentTerm {
		n.voteRespCh <- VoteResponse{
			Term:        n.currentTerm,
			VoteGranted: false,
			From:        n.config.NodeID,
		}
		return
	}

	// Raft §5.1: if RPC carries a higher term we MUST update our own
	// currentTerm, drop to follower, and reset votedFor BEFORE deciding
	// whether to grant this vote. The previous code skipped this step
	// and proceeded to the votedFor check below with the *old* term's
	// vote intact — so a node that had voted for itself in term N
	// would reject every candidate's request in term N+1 even though
	// no one in term N+1 had been voted for yet. The cluster could get
	// stuck unable to elect a leader (livelock) because every node
	// holds a stale per-term vote from an earlier term.
	//
	// Note: advanceTermLocked also persists the new (currentTerm,
	// votedFor="") tuple via fsync before we proceed, satisfying the
	// election-safety durability requirement.
	if req.Term > n.currentTerm {
		n.advanceTermLocked(req.Term)
	}

	// If votedFor is null or candidateId, and candidate's log is at least as
	// up-to-date as receiver's log, grant vote
	if (n.votedFor == "" || n.votedFor == req.CandidateID) && n.isLogUpToDate(req.LastLogIndex, req.LastLogTerm) {
		n.setVotedForLocked(req.CandidateID)
		// Granting a vote counts as leader contact: don't immediately start
		// our own campaign against the candidate we just endorsed.
		n.signalElectionReset()
		n.voteRespCh <- VoteResponse{
			Term:        n.currentTerm,
			VoteGranted: true,
			From:        n.config.NodeID,
		}
	} else {
		n.voteRespCh <- VoteResponse{
			Term:        n.currentTerm,
			VoteGranted: false,
			From:        n.config.NodeID,
		}
	}
}

// handleAppendRequest handles an AppendEntries request arriving on the
// in-process channel path and pushes the response to appendRespCh.
func (n *Node) handleAppendRequest(req AppendRequest) {
	n.mu.Lock()
	resp := n.appendEntriesLocked(req)
	n.mu.Unlock()
	n.appendRespCh <- resp
}

// appendEntriesLocked is the single, snapshot-aware implementation of the
// AppendEntries receiver rules (Raft §5.3). Both the channel-based and the
// exported RPC handler delegate here so the two can never drift apart.
// MUST be called with n.mu held.
//
// On success it sets resp.MatchIndex to the global index of the last entry
// the follower now stores that is consistent with the leader — WITHOUT
// this the leader's matchIndex never advances and nothing ever commits.
// On a consistency-check failure it returns a MatchIndex hint so the
// leader can back nextIndex up quickly instead of decrementing by one.
func (n *Node) appendEntriesLocked(req AppendRequest) AppendResponse {
	resp := AppendResponse{
		Term:    n.currentTerm,
		Success: false,
		From:    n.config.NodeID,
	}

	// Reply false if term < currentTerm (Raft §5.1).
	if req.Term < n.currentTerm {
		return resp
	}

	// A valid AppendEntries means the sender is the leader of a term at
	// least as new as ours: adopt the term, step down to follower, and
	// record the leader for client redirection.
	if req.Term > n.currentTerm {
		n.advanceTermLocked(req.Term)
	}
	n.state = StateFollower
	if req.LeaderID != "" {
		n.leaderID = req.LeaderID
	}
	resp.Term = n.currentTerm

	// Legitimate leader contact for this term: restart the election clock
	// (and, if we were a candidate, step down) so a healthy leader isn't
	// repeatedly challenged.
	n.signalElectionReset()

	// Log-consistency check at PrevLogIndex (Raft §5.3).
	if req.PrevLogIndex > n.lastIndex() {
		// We're missing entries before PrevLogIndex. Hint our last index
		// so the leader resumes from there.
		resp.MatchIndex = n.lastIndex()
		return resp
	}
	if req.PrevLogIndex > n.lastSnapshot {
		if t, ok := n.entryTerm(req.PrevLogIndex); !ok || t != req.PrevLogTerm {
			// Term conflict at PrevLogIndex: drop it and everything after,
			// then ask the leader to retry one entry earlier.
			n.truncateFrom(req.PrevLogIndex)
			n.persistTruncateLocked(req.PrevLogIndex - 1)
			resp.MatchIndex = req.PrevLogIndex - 1
			return resp
		}
	}

	// PrevLog matches. Reconcile the incoming entries with our log,
	// overwriting only on a genuine term conflict so we never discard
	// entries we already agree on (Raft §5.3 final paragraph).
	var toAppend []entry
	truncated := false
	var keepThrough Index
	for j, e := range req.Entries {
		idx := req.PrevLogIndex + 1 + Index(j)
		if idx <= n.lastSnapshot {
			continue // already captured by the snapshot
		}
		if idx <= n.lastIndex() {
			if t, _ := n.entryTerm(idx); t != e.Term {
				n.truncateFrom(idx)
				truncated = true
				keepThrough = idx - 1
				toAppend = req.Entries[j:]
				n.log = append(n.log, toAppend...)
				break
			}
			// identical entry already present — skip
			continue
		}
		// idx is past our log: append this and all remaining entries.
		toAppend = req.Entries[j:]
		n.log = append(n.log, toAppend...)
		break
	}
	// Durably record the reconciliation before acknowledging.
	if truncated {
		n.persistTruncateLocked(keepThrough)
	}
	n.persistEntriesLocked(toAppend)

	// Advance commit index. Cap at the last entry this request let us
	// verify is consistent with the leader (PrevLogIndex + #entries) —
	// never blindly to the leader's commit, which may be ahead of what
	// this follower actually holds.
	lastConsistent := req.PrevLogIndex + Index(len(req.Entries))
	if req.LeaderCommit > n.commitIndex {
		newCommit := min(req.LeaderCommit, lastConsistent)
		if newCommit > n.commitIndex {
			n.commitIndex = newCommit
			n.signalCommit()
		}
	}

	resp.Success = true
	resp.MatchIndex = lastConsistent
	return resp
}

// HandleVoteRequest is the exported RPC handler for vote requests.
func (n *Node) HandleVoteRequest(req VoteRequest) VoteResponse {
	n.mu.Lock()
	defer n.mu.Unlock()

	if req.Term < n.currentTerm {
		return VoteResponse{
			Term:        n.currentTerm,
			VoteGranted: false,
			From:        n.config.NodeID,
		}
	}

	if req.Term > n.currentTerm {
		n.advanceTermLocked(req.Term)
	}

	if (n.votedFor == "" || n.votedFor == req.CandidateID) && n.isLogUpToDate(req.LastLogIndex, req.LastLogTerm) {
		n.setVotedForLocked(req.CandidateID)
		// Granting a vote counts as leader contact: don't immediately start
		// our own campaign against the candidate we just endorsed.
		n.signalElectionReset()
		return VoteResponse{
			Term:        n.currentTerm,
			VoteGranted: true,
			From:        n.config.NodeID,
		}
	}
	return VoteResponse{
		Term:        n.currentTerm,
		VoteGranted: false,
		From:        n.config.NodeID,
	}
}

// HandleAppendRequest is the exported RPC handler for append requests.
// It delegates to the shared receiver implementation so the RPC and
// in-process channel paths apply identical rules.
func (n *Node) HandleAppendRequest(req AppendRequest) AppendResponse {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.appendEntriesLocked(req)
}

// HandleSnapshotRequest is the exported RPC handler for snapshot requests.
// Installs a snapshot from the leader, restoring state machine state.
func (n *Node) HandleSnapshotRequest(req SnapshotRequest) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if req.Term < n.currentTerm {
		return
	}

	if req.Term > n.currentTerm {
		n.advanceTermLocked(req.Term)
	}

	// If we have a state machine and snapshot data, restore it.
	// On Restore failure, we MUST NOT advance the snapshot indices
	// or clear the log: committing to a state we couldn't load means
	// the node now claims `lastApplied=N` while the state machine is
	// still at `M < N`. The follower silently diverges from the rest
	// of the cluster and there is no recovery path — the leader
	// won't re-send a snapshot it already thinks we acknowledged.
	// The right behavior is to refuse the install; the leader's
	// next AppendEntries / snapshot retry will try again.
	if len(req.Data) > 0 && n.stateMachine != nil {
		if err := n.stateMachine.Restore(req.Data); err != nil {
			util.Errorf("failed to restore state machine from snapshot: %v", err)
			return
		}
	}

	// Install snapshot: update indices and clear log. lastSnapshotTerm
	// must move with lastSnapshot so entryTerm(lastSnapshot) keeps
	// answering correctly for the new compaction point.
	n.lastSnapshot = req.LastIndex
	n.lastSnapshotTerm = req.LastTerm
	n.lastApplied = req.LastIndex
	n.commitIndex = req.LastIndex
	n.log = make([]entry, 0) // Discard all log entries before snapshot
}

// handleAppendResponse handles an AppendEntries response from a peer.
func (n *Node) handleAppendResponse(resp AppendResponse) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.state != StateLeader {
		return
	}

	if resp.Term > n.currentTerm {
		// Newer term discovered
		n.advanceTermLocked(resp.Term)
		return
	}

	if resp.Success {
		// Advance match/next for this peer from the follower's hint, then
		// recompute the commit index.
		if resp.MatchIndex > n.matchIndex[resp.From] {
			n.matchIndex[resp.From] = resp.MatchIndex
		}
		n.nextIndex[resp.From] = n.matchIndex[resp.From] + 1
		n.maybeAdvanceCommitIndex()
	} else {
		// Consistency check failed. Back nextIndex up — toward the
		// follower's MatchIndex hint when it's useful, otherwise by one —
		// so the next AppendEntries probes an earlier point in the log.
		hintNext := resp.MatchIndex + 1
		if hintNext >= 1 && hintNext < n.nextIndex[resp.From] {
			n.nextIndex[resp.From] = hintNext
		} else if n.nextIndex[resp.From] > 1 {
			n.nextIndex[resp.From]--
		}
	}
}

// handleSnapshotRequest handles a snapshot install request.
// This is the internal version used for local snapshot installation.
func (n *Node) handleSnapshotRequest(req SnapshotRequest) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if req.Term < n.currentTerm {
		return
	}

	if req.Term > n.currentTerm {
		n.advanceTermLocked(req.Term)
	}

	// If we have a state machine and snapshot data, restore it.
	// On Restore failure, we MUST NOT update the snapshot indices or
	// clear the log: doing so would commit to a state we couldn't
	// actually load, leaving the node permanently divergent from the
	// rest of the cluster. The leader will retry the snapshot install
	// on its next AppendEntries; that's the standard recovery path.
	if len(req.Data) > 0 && n.stateMachine != nil {
		if err := n.stateMachine.Restore(req.Data); err != nil {
			util.Errorf("failed to restore state machine from snapshot: %v", err)
			return
		}
	}

	// Install snapshot: update indices and clear log
	n.lastSnapshot = req.LastIndex
	n.lastApplied = req.LastIndex
	n.commitIndex = req.LastIndex
	n.log = make([]entry, 0)
}

// notifyLeadership publishes a leadership transition. The send is
// non-blocking: leadershipCh is buffered and drained promptly by the
// integration layer, but the run-loop goroutine must never block here —
// a stalled consumer would otherwise freeze elections and replication.
func (n *Node) notifyLeadership(s LeadershipState) {
	select {
	case n.leadershipCh <- s:
	default:
	}
}

// becomeFollower transitions to follower state. Called from the candidate
// loop without n.mu held, so it takes the lock itself — the prior version
// mutated state and called advanceTermLocked (which requires the lock and
// fsyncs HardState) entirely unlocked, a data race against every other
// accessor.
func (n *Node) becomeFollower(term Term) {
	n.mu.Lock()
	// advanceTermLocked is a no-op when term <= currentTerm; ensure we at
	// least transition to follower state in that case (e.g. on a peer
	// step-down where the term doesn't move).
	if term > n.currentTerm {
		n.advanceTermLocked(term)
	} else {
		n.state = StateFollower
	}
	n.mu.Unlock()
	n.notifyLeadership(LeadershipState{State: StateFollower, Term: term})
}

// becomeLeader transitions to leader state. Called from the candidate loop
// without n.mu held. State mutation happens under the lock; Propose is
// called afterwards because it acquires the lock itself.
func (n *Node) becomeLeader(term Term) {
	n.mu.Lock()
	n.state = StateLeader
	n.leaderID = n.config.NodeID
	// Initialize nextIndex and matchIndex for all peers (Raft §5.3:
	// nextIndex = leader's last log index + 1, matchIndex = 0).
	for id := range n.peers {
		n.nextIndex[id] = n.lastIndex() + 1
		n.matchIndex[id] = 0
	}
	n.mu.Unlock()

	n.notifyLeadership(LeadershipState{State: StateLeader, Term: term})

	// Commit a no-op entry to prove liveness. Failure here is logged but
	// does not abort the leader transition — the next AppendEntries cycle
	// will retry. The no-op also defends against the Raft §5.4.2 commit
	// bug (a leader cannot commit entries from a previous term without
	// also committing one of its own).
	if err := n.Propose(nil, EntryNoOp); err != nil {
		_ = err // logged by integration layer
	}
}

// broadcastVoteRequest sends vote requests to all peers.
func (n *Node) broadcastVoteRequest(term Term, lastLogIndex Index, lastLogTerm Term) {
	for id := range n.peers {
		go func(peerID NodeID) {
			defer func() {
				if r := recover(); r != nil {
					util.Errorf("raft: panic in broadcastVoteRequest for peer %s: %v", peerID, r)
				}
			}()
			req := VoteRequest{
				Term:         term,
				CandidateID:  n.config.NodeID,
				LastLogIndex: lastLogIndex,
				LastLogTerm:  lastLogTerm,
			}
			// RPC call — would be injected in real implementation
			n.sendVoteRequest(peerID, req)
		}(id)
	}
}

// broadcastHeartbeat sends AppendEntries to every peer. A "heartbeat" in
// this implementation is just a normal AppendEntries built from the peer's
// nextIndex: if the follower is behind it carries the missing entries, if
// it's caught up it carries none. This is the standard Raft model and is
// what lets the leader's periodic tick double as the catch-up driver.
func (n *Node) broadcastHeartbeat(term Term) {
	for id := range n.peers {
		go func(peerID NodeID) {
			defer func() {
				if r := recover(); r != nil {
					util.Errorf("raft: panic in broadcastHeartbeat for peer %s: %v", peerID, r)
				}
			}()
			n.replicateTo(peerID, term)
		}(id)
	}
}

// buildAppendRequestLocked assembles the AppendEntries to send to peerID
// from its current nextIndex. ok is false only when the entries the peer
// needs have already been compacted into a snapshot (the caller should
// send an InstallSnapshot instead — not yet wired). MUST hold n.mu.
func (n *Node) buildAppendRequestLocked(peerID NodeID, term Term) (AppendRequest, bool) {
	nextIdx := n.nextIndex[peerID]
	if nextIdx < 1 {
		nextIdx = 1
	}
	prevLogIndex := nextIdx - 1
	if prevLogIndex < n.lastSnapshot {
		// The follower is so far behind that PrevLog is inside our
		// snapshot; a plain AppendEntries can't bridge that gap.
		return AppendRequest{}, false
	}
	prevLogTerm, ok := n.entryTerm(prevLogIndex)
	if !ok {
		return AppendRequest{}, false
	}
	return AppendRequest{
		Term:         term,
		LeaderID:     n.config.NodeID,
		PrevLogIndex: prevLogIndex,
		PrevLogTerm:  prevLogTerm,
		Entries:      n.entriesFrom(nextIdx),
		LeaderCommit: n.commitIndex,
	}, true
}

// replicateTo sends one AppendEntries to a single peer based on its
// nextIndex. Used both by the heartbeat tick and immediately after a
// Propose.
func (n *Node) replicateTo(peerID NodeID, term Term) {
	n.mu.Lock()
	if n.state != StateLeader || n.currentTerm != term {
		n.mu.Unlock()
		return
	}
	req, ok := n.buildAppendRequestLocked(peerID, term)
	n.mu.Unlock()
	if !ok {
		return
	}
	n.sendAppendRequest(peerID, req)
}

// sendCommitted sends committed entries to the apply channel.
func (n *Node) sendCommitted() {
	n.mu.Lock()
	defer n.mu.Unlock()

	start := int(n.lastApplied) + 1
	end := int(n.commitIndex) + 1

	if start > end || end > len(n.log)+int(n.lastSnapshot) {
		return
	}

	// Adjust for snapshot offset
	startIdx := start - int(n.lastSnapshot) - 1
	endIdx := end - int(n.lastSnapshot) - 1

	if startIdx < 0 {
		startIdx = 0
	}
	if endIdx > len(n.log) {
		endIdx = len(n.log)
	}

	if startIdx >= endIdx {
		return
	}

	entries := make([]entry, endIdx-startIdx)
	copy(entries, n.log[startIdx:endIdx])

	// Only advance lastApplied AFTER the commit goes through. The
	// previous code bumped lastApplied before the channel send and
	// then fell into a default branch on a full commitCh — so on the
	// next sendCommitted call, the start/end window had already moved
	// past these entries and they were skipped forever. State machine
	// never saw them and the cluster silently lost commits. With this
	// ordering, a dropped send leaves lastApplied where it was; the
	// next maybeAdvanceCommitIndex / commit tick retries the same
	// window.
	select {
	case n.commitCh <- Commit{Entries: entries}:
		n.lastApplied = n.commitIndex
	default:
		// Channel full — will retry on the next commit tick.
	}
}

// quorumSize is the number of nodes (including self) that must agree for a
// decision — a strict majority of the full cluster. peers excludes self, so
// the cluster has len(peers)+1 nodes and the majority is
// ⌊(len(peers)+1)/2⌋ + 1. Correct for both odd and even cluster sizes.
func (n *Node) quorumSize() int {
	return (len(n.peers)+1)/2 + 1
}

// maybeAdvanceCommitIndex advances the commit index to the highest global
// index replicated on a quorum, subject to the Raft §5.4.2 rule that a
// leader may only commit an entry from its OWN term directly (older-term
// entries commit transitively once a current-term entry does). MUST hold
// n.mu.
func (n *Node) maybeAdvanceCommitIndex() {
	if n.state != StateLeader {
		return
	}

	newCommit := n.commitIndex
	for i := n.commitIndex + 1; i <= n.lastIndex(); i++ {
		if i <= n.lastSnapshot {
			continue
		}
		if t, ok := n.entryTerm(i); !ok || t != n.currentTerm {
			continue
		}

		replicas := 1 // the leader itself stores entry i
		for id := range n.peers {
			if n.matchIndex[id] >= i {
				replicas++
			}
		}
		// Commit once a strict majority of the FULL cluster (peers + self)
		// holds the entry. quorumSize() is correct for both odd and even
		// cluster sizes — the old `replicas > len(peers)/2` under-counted
		// for even sizes (e.g. it committed with just the leader in a
		// 2-node cluster, a split-brain hazard).
		if replicas >= n.quorumSize() {
			newCommit = i
		}
	}

	if newCommit > n.commitIndex {
		n.commitIndex = newCommit
		n.signalCommit()
	}
}

// isLogUpToDate checks if the candidate's log is at least as up-to-date as receiver's.
func (n *Node) isLogUpToDate(candidateLastIndex Index, candidateLastTerm Term) bool {
	lastIndex, lastTerm := n.lastLogInfo()

	if lastTerm != candidateLastTerm {
		return candidateLastTerm > lastTerm
	}
	return candidateLastIndex >= lastIndex
}

// --- Snapshot-aware log index helpers ---
//
// The Raft log uses GLOBAL indices: an entry's logical index counts from
// 1 and never resets, even after compaction. n.log only holds the entries
// AFTER the snapshot, so the entry with global index i lives at
// n.log[i-lastSnapshot-1]. Every place that maps between a global index
// and the n.log slice MUST go through these helpers — mixing the two
// conventions (as the pre-fix code did: maybeAdvanceCommitIndex used the
// array offset while sendCommitted applied the snapshot offset) silently
// commits the wrong entries once lastSnapshot > 0. All require n.mu held.

// lastIndex returns the highest global log index the node holds.
func (n *Node) lastIndex() Index {
	return n.lastSnapshot + Index(len(n.log))
}

// entryTerm returns the term of the entry at global index i.
// ok is false when i was compacted away (below the snapshot, term
// unknown) or is beyond the last index.
func (n *Node) entryTerm(i Index) (term Term, ok bool) {
	if i == 0 {
		return 0, true
	}
	if i == n.lastSnapshot {
		return n.lastSnapshotTerm, true
	}
	if i < n.lastSnapshot || i > n.lastIndex() {
		return 0, false
	}
	return n.log[i-n.lastSnapshot-1].Term, true
}

// entriesFrom returns a fresh copy of the log entries at global indices
// [from, lastIndex]. Entries already inside the snapshot are skipped.
func (n *Node) entriesFrom(from Index) []entry {
	if from <= n.lastSnapshot {
		from = n.lastSnapshot + 1
	}
	startArr := int(from - n.lastSnapshot - 1)
	if startArr < 0 || startArr >= len(n.log) {
		return nil
	}
	out := make([]entry, len(n.log)-startArr)
	copy(out, n.log[startArr:])
	return out
}

// truncateFrom drops every log entry with global index >= idx.
func (n *Node) truncateFrom(idx Index) {
	if idx <= n.lastSnapshot+1 {
		n.log = n.log[:0]
		return
	}
	keep := int(idx - n.lastSnapshot - 1)
	if keep < len(n.log) {
		n.log = n.log[:keep]
	}
}

// signalCommit wakes the apply loop after commitIndex advances. The send
// is non-blocking: the applier always re-reads the current commitIndex
// when it wakes, so a dropped signal (buffer full ⇒ applier already
// behind) is harmless — any queued signal makes it apply up to the
// latest commit. Safe to call with n.mu held.
func (n *Node) signalCommit() {
	select {
	case n.commitCh <- Commit{}:
	default:
	}
}

// signalElectionReset notifies the run loop that we've had legitimate
// leader contact (valid AppendEntries) or just granted a vote, so the
// election timer should be restarted (follower) or the candidacy
// abandoned (candidate). Non-blocking: the buffer-of-1 collapses bursts
// and a dropped signal only costs one extra timer cycle. Safe under n.mu.
func (n *Node) signalElectionReset() {
	select {
	case n.electionResetCh <- struct{}{}:
	default:
	}
}

// lastLogInfo returns the last global log index and its term.
func (n *Node) lastLogInfo() (Index, Term) {
	li := n.lastIndex()
	t, _ := n.entryTerm(li)
	return li, t
}

// randomElectionTimeout returns a randomized duration in
// [electionTimeout, 2*electionTimeout). Randomization across nodes is what
// breaks symmetric split votes (Raft §5.2).
func (n *Node) randomElectionTimeout() time.Duration {
	extra := n.rng.Int63n(int64(n.config.ElectionTimeout))
	return time.Duration(extra) + n.config.ElectionTimeout
}

// newElectionTimer creates a timer armed with a randomized election timeout.
func (n *Node) newElectionTimer() *time.Timer {
	return time.NewTimer(n.randomElectionTimeout())
}

// Propose proposes a command for replication. If node is not leader, returns error.
func (n *Node) Propose(command []byte, entryType EntryType) error {
	_, err := n.ProposeEntry(command, entryType)
	return err
}

// ProposeEntry is Propose that also returns the global index assigned to the
// new entry, so callers can wait for it to be applied. Returns an error if
// this node is not the leader.
func (n *Node) ProposeEntry(command []byte, entryType EntryType) (Index, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.state != StateLeader {
		return 0, fmt.Errorf("not leader (state=%s)", n.state)
	}

	e := entry{
		Index: n.lastIndex() + 1,
		Term:  n.currentTerm,
		Type:  entryType,
	}
	if command != nil {
		cmd := make([]byte, len(command))
		copy(cmd, command)
		e.Command = cmd
	}

	n.log = append(n.log, e)
	// Durably record the entry before it can be replicated/committed.
	n.persistEntriesLocked(n.log[len(n.log)-1:])

	// Try to advance commit immediately: when the leader's own copy is
	// already a quorum (single-node cluster), the entry commits here with no
	// peer round-trip. For multi-node clusters this is a no-op until acks
	// arrive (peers' matchIndex is still behind).
	n.maybeAdvanceCommitIndex()

	// Send to followers asynchronously
	go n.replicateToFollowers(e)

	return e.Index, nil
}

// replicateToFollowers pushes newly-appended entries to every follower
// immediately after a Propose, instead of waiting for the next heartbeat
// tick. Each peer is served from its own nextIndex via replicateTo, so a
// lagging follower still receives exactly the entries it's missing.
func (n *Node) replicateToFollowers(_ entry) {
	n.mu.Lock()
	term := n.currentTerm
	isLeader := n.state == StateLeader
	n.mu.Unlock()
	if !isLeader {
		return
	}

	for id := range n.peers {
		go func(peerID NodeID) {
			defer func() {
				if r := recover(); r != nil {
					util.Errorf("raft: panic in replicateToFollowers for peer %s: %v", peerID, r)
				}
			}()
			n.replicateTo(peerID, term)
		}(id)
	}
}

// sendVoteRequest sends a vote request to a peer via the transport.
func (n *Node) sendVoteRequest(peerID NodeID, req VoteRequest) {
	if n.transport == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				util.Errorf("raft: panic in sendVoteRequest: %v", r)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), raftRPCTimeout)
		defer cancel()
		resp, err := n.transport.SendRequestVote(ctx, peerID, req)
		if err != nil || resp == nil {
			// Transport error or a nil response (e.g. peer down): drop it
			// rather than dereference a nil pointer.
			return
		}
		select {
		case n.voteRespCh <- *resp:
		default:
			// voteRespCh is bounded (size 10); if full drop the response
			// rather than block the RPC handler.
		}
	}()
}

// sendAppendRequest sends an AppendEntries request to a peer via the transport.
func (n *Node) sendAppendRequest(peerID NodeID, req AppendRequest) {
	if n.transport == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				util.Errorf("raft: panic in sendAppendRequest: %v", r)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), raftRPCTimeout)
		defer cancel()
		resp, err := n.transport.SendAppendEntries(ctx, peerID, req)
		if err != nil || resp == nil {
			// Transport error or a nil response (e.g. peer down): drop it
			// rather than dereference a nil pointer.
			return
		}
		select {
		case n.appendRespCh <- *resp:
		default:
			// appendRespCh is bounded; if full drop rather than block.
		}
	}()
}

// AddPeer proposes adding a new peer to the cluster using joint consensus (RFC 7003).
// This is a two-phase process: first a joint config is proposed, then the new config.
func (n *Node) AddPeer(id NodeID, addr string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// If already in joint config or pending, reject
	if n.jointConfig != nil || n.pendingConfChange != nil {
		return fmt.Errorf("cluster is already processing a configuration change")
	}

	// If peer already exists, nothing to do
	if _, ok := n.peers[id]; ok {
		return nil
	}

	// Can't add self
	if id == n.config.NodeID {
		return fmt.Errorf("cannot add self")
	}

	// Create the joint config entry directly
	newPeers := make(map[NodeID]*Peer)
	for pid, p := range n.peers {
		newPeers[pid] = p
	}
	newPeers[id] = &Peer{ID: id, Addr: addr}

	jointConfig := NewJointConfig(n.peers, newPeers)
	jcBytes, err := encodeJointConfig(jointConfig)
	if err != nil {
		return fmt.Errorf("encode joint config: %w", err)
	}

	// Append joint config entry
	entry := entry{
		Index:   Index(len(n.log)) + 1,
		Term:    n.currentTerm,
		Command: jcBytes,
		Type:    EntryAddNode,
	}
	n.log = append(n.log, entry)

	// Store joint config reference
	n.jointConfig = jointConfig
	n.jointConfigIdx = entry.Index
	n.pendingConfChange = &JointConfigProposal{
		Type:     EntryAddNode,
		PeerID:   id,
		PeerAddr: addr,
		Proposed: time.Now(),
	}

	// Initialize tracking for the new peer
	n.nextIndex[id] = Index(len(n.log)) + 1
	n.matchIndex[id] = 0

	return nil
}

// ProposeConfChange proposes a configuration change entry.
// For AddNode: proposes joint (C_old, C_old ∪ {new}) then C_new ∪ {new}
// For RemoveNode: proposes joint (C_old, C_old \ {old}) then C_old \ {old}
func (n *Node) ProposeConfChange(proposal *JointConfigProposal) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.state != StateLeader {
		return fmt.Errorf("not leader")
	}

	// Create the joint config entry
	var newPeers map[NodeID]*Peer
	if proposal.Type == EntryAddNode {
		newPeers = make(map[NodeID]*Peer)
		for id, p := range n.peers {
			newPeers[id] = p
		}
		newPeers[proposal.PeerID] = &Peer{ID: proposal.PeerID, Addr: proposal.PeerAddr}
	} else {
		newPeers = make(map[NodeID]*Peer)
		for id, p := range n.peers {
			if id != proposal.PeerID {
				newPeers[id] = p
			}
		}
	}

	jointConfig := NewJointConfig(n.peers, newPeers)
	jcBytes, err := encodeJointConfig(jointConfig)
	if err != nil {
		return fmt.Errorf("encode joint config: %w", err)
	}

	// Append joint config entry
	entry := entry{
		Index:   Index(len(n.log)) + 1,
		Term:    n.currentTerm,
		Command: jcBytes,
		Type:    proposal.Type,
	}
	n.log = append(n.log, entry)

	// Store joint config reference
	n.jointConfig = jointConfig
	n.jointConfigIdx = entry.Index

	// Also initialize tracking for the new peer if adding
	if proposal.Type == EntryAddNode {
		n.nextIndex[proposal.PeerID] = Index(len(n.log)) + 1
		n.matchIndex[proposal.PeerID] = 0
	}

	return nil
}

// advanceJointConfig commits the joint config and transitions to new config.
// Called when the joint config entry has been committed.
func (n *Node) advanceJointConfig() {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.jointConfig == nil {
		return
	}

	// Transition from joint to new config
	n.peers = n.jointConfig.NewPeers

	// Clear joint config state
	n.jointConfig = nil
	n.jointConfigIdx = 0
	n.pendingConfChange = nil
}

// RemovePeer proposes removing a peer from the cluster using joint consensus (RFC 7003).
func (n *Node) RemovePeer(id NodeID) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// If already in joint config or pending, reject
	if n.jointConfig != nil || n.pendingConfChange != nil {
		return fmt.Errorf("cluster is already processing a configuration change")
	}

	// If peer doesn't exist, nothing to do
	if _, ok := n.peers[id]; !ok {
		return nil
	}

	// Can't remove self
	if id == n.config.NodeID {
		return fmt.Errorf("cannot remove self")
	}

	// Create the joint config entry
	newPeers := make(map[NodeID]*Peer)
	for pid, p := range n.peers {
		if pid != id {
			newPeers[pid] = p
		}
	}

	jointConfig := NewJointConfig(n.peers, newPeers)
	jcBytes, err := encodeJointConfig(jointConfig)
	if err != nil {
		return fmt.Errorf("encode joint config: %w", err)
	}

	// Append joint config entry
	entry := entry{
		Index:   Index(len(n.log)) + 1,
		Term:    n.currentTerm,
		Command: jcBytes,
		Type:    EntryRemoveNode,
	}
	n.log = append(n.log, entry)

	// Store joint config reference
	n.jointConfig = jointConfig
	n.jointConfigIdx = entry.Index
	n.pendingConfChange = &JointConfigProposal{
		Type:     EntryRemoveNode,
		PeerID:   id,
		Proposed: time.Now(),
	}

	// Note: we don't remove nextIndex/matchIndex here - they're removed when joint completes

	return nil
}

// encodeJointConfig encodes a joint configuration to bytes.
func encodeJointConfig(jc *JointConfig) ([]byte, error) {
	var buf bytes.Buffer

	// Encode old peers count
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(jc.OldPeers))); err != nil {
		return nil, err
	}
	// Encode old peers
	for id, peer := range jc.OldPeers {
		if err := binary.Write(&buf, binary.BigEndian, uint32(len(id))); err != nil {
			return nil, err
		}
		buf.WriteString(string(id))
		if err := binary.Write(&buf, binary.BigEndian, uint32(len(peer.Addr))); err != nil {
			return nil, err
		}
		buf.WriteString(peer.Addr)
	}

	// Encode new peers count
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(jc.NewPeers))); err != nil {
		return nil, err
	}
	// Encode new peers
	for id, peer := range jc.NewPeers {
		if err := binary.Write(&buf, binary.BigEndian, uint32(len(id))); err != nil {
			return nil, err
		}
		buf.WriteString(string(id))
		if err := binary.Write(&buf, binary.BigEndian, uint32(len(peer.Addr))); err != nil {
			return nil, err
		}
		buf.WriteString(peer.Addr)
	}

	return buf.Bytes(), nil
}

// State returns the current state.
func (n *Node) State() State {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.state
}

// Term returns the current term.
func (n *Node) Term() Term {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.currentTerm
}

// LeaderID returns the most-recently-seen leader node ID, or "" if no
// leader has been observed since startup (e.g. fresh follower waiting
// for the first heartbeat). Followers learn the leader via
// AppendEntries; leaders return their own ID.
func (n *Node) LeaderID() NodeID {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.leaderID
}

// CommitIndex returns the current commit index.
func (n *Node) CommitIndex() Index {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.commitIndex
}

// LeadershipCh returns the leadership change channel.
func (n *Node) LeadershipCh() <-chan LeadershipState {
	return n.leadershipCh
}

// CommitCh returns the commit channel.
func (n *Node) CommitCh() <-chan Commit {
	return n.commitCh
}

// ApplyCh returns the apply channel.
func (n *Node) ApplyCh() <-chan Apply {
	return n.applyCh
}

// SetStateMachine sets the state machine for applying snapshots.
// This should be called before starting the node.
func (n *Node) SetStateMachine(sm StateMachine) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.stateMachine = sm
}

// SetLogPersister installs the durable log store. Call before Start.
func (n *Node) SetLogPersister(p logPersister) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.persister = p
}

// persistEntriesLocked durably appends entries and fsyncs. A failure is
// logged but not fatal: it indicates a catastrophic environment problem
// (disk full) and panicking would take the node down harder than running
// with a stale WAL. Caller holds n.mu.
func (n *Node) persistEntriesLocked(entries []entry) {
	if n.persister == nil || len(entries) == 0 {
		return
	}
	for _, e := range entries {
		if err := n.persister.Write(e); err != nil {
			util.Errorf("raft: WAL write failed (index=%d): %v", e.Index, err)
			return
		}
	}
	if err := n.persister.Sync(); err != nil {
		util.Errorf("raft: WAL sync failed: %v", err)
	}
}

// persistTruncateLocked durably discards WAL entries past keepThrough.
// Caller holds n.mu.
func (n *Node) persistTruncateLocked(keepThrough Index) {
	if n.persister == nil {
		return
	}
	if err := n.persister.TruncateAfter(keepThrough); err != nil {
		util.Errorf("raft: WAL truncate failed (keepThrough=%d): %v", keepThrough, err)
	}
}
