// Package raft implements the Raft consensus algorithm (RFC 7003) for
// NothingDNS cluster coordination. The implementation is split across:
//
//   - types.go       — core types, Node struct, Config, RPC message types
//   - state.go       — lifecycle, state-machine loop (follower/candidate/leader),
//     term/persistence helpers, log index helpers, accessors
//   - handlers.go    — RPC handlers (vote/append/snapshot), transport senders
//   - replication.go — Propose, broadcast, replicate-to-peer, snapshot install
//   - membership.go  — AddPeer/RemovePeer, joint consensus (RFC 7003)
//   - rpc.go         — Transport interface, TCPTransport, RPCServer, InMemoryTransport
//   - snapshot.go    — snapshot creation and management
//   - wal.go         — write-ahead log persistence
//   - hardstate.go   — persistent HardState (currentTerm/votedFor)
//
// This file exists only as the package's central documentation anchor.
// All code has been distributed to the files above for readability.
package raft
