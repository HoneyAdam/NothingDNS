package raft

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

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
