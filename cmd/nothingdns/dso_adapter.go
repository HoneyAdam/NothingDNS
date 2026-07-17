package main

import (
	"net"
	"sync"

	"github.com/nothingdns/nothingdns/internal/dso"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

// dsoConnAdapter bridges the transport servers (TCP/TLS) to the DSO
// manager: it owns the conn→session mapping so each transport connection
// gets exactly one RFC 8490 session, created lazily on the first DSO
// message and torn down when the connection closes.
type dsoConnAdapter struct {
	manager *dso.Manager
	logger  *util.Logger

	mu       sync.Mutex
	sessions map[net.Conn]*dso.Session
}

func newDSOConnAdapter(manager *dso.Manager, logger *util.Logger) *dsoConnAdapter {
	return &dsoConnAdapter{
		manager:  manager,
		logger:   logger,
		sessions: make(map[net.Conn]*dso.Session),
	}
}

// HandleDSO implements server.DSOConnHandler. Session creation happens
// under a.mu so two pipelined DSO messages on the same connection cannot
// race a duplicate session into existence. dso.Manager.CreateSession
// enforces the RFC 8490 §5.1 TLS requirement (plain TCP is refused unless
// the manager was configured with AllowPlainTCP).
func (a *dsoConnAdapter) HandleDSO(conn net.Conn, msg *protocol.Message) (*protocol.Message, error) {
	a.mu.Lock()
	sess, ok := a.sessions[conn]
	if !ok {
		var err error
		sess, err = a.manager.CreateSession(conn)
		if err != nil {
			a.mu.Unlock()
			return nil, err
		}
		a.sessions[conn] = sess
	}
	a.mu.Unlock()

	return a.manager.HandleDSORequest(sess, msg)
}

// ConnClosed implements server.DSOConnHandler.
func (a *dsoConnAdapter) ConnClosed(conn net.Conn) {
	a.mu.Lock()
	sess, ok := a.sessions[conn]
	delete(a.sessions, conn)
	a.mu.Unlock()

	if ok {
		a.manager.RemoveSession(sess.ID)
	}
}
