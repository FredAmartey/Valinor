package proxy

import (
	"context"
	"fmt"
	"sync"
)

// ConnPool maintains open connections to agents, keyed by agent instance ID.
// Connections are created lazily on first Get.
//
// NOTE: The current implementation returns the same AgentConn for all requests
// to a given agent. Frame-ID multiplexing is not yet implemented, so concurrent
// requests to the same agent will interleave on a shared connection. Callers
// must serialize requests per agent or accept that responses may be mis-routed.
// Full frame-ID dispatching is deferred to a future phase.
type ConnPool struct {
	transport Transport
	mu        sync.Mutex
	conns     map[string]*AgentConn
}

// NewConnPool creates a ConnPool using the given transport.
func NewConnPool(transport Transport) *ConnPool {
	return &ConnPool{
		transport: transport,
		conns:     make(map[string]*AgentConn),
	}
}

// Get returns the existing connection for an agent, or dials a new one.
func (p *ConnPool) Get(ctx context.Context, agentID string, cid uint32) (*AgentConn, error) {
	p.mu.Lock()
	if conn, ok := p.conns[agentID]; ok {
		p.mu.Unlock()
		return conn, nil
	}
	p.mu.Unlock()

	// Dial outside lock to avoid blocking other agents
	raw, err := p.transport.Dial(ctx, cid)
	if err != nil {
		return nil, fmt.Errorf("dialing agent %s (CID %d): %w", agentID, cid, err)
	}

	conn := NewAgentConn(raw)

	p.mu.Lock()
	// Check again in case another goroutine dialed concurrently
	if existing, ok := p.conns[agentID]; ok {
		p.mu.Unlock()
		_ = conn.Close() // close the duplicate
		return existing, nil
	}
	p.conns[agentID] = conn
	p.mu.Unlock()

	return conn, nil
}

// Remove closes and removes a connection from the pool.
func (p *ConnPool) Remove(agentID string) {
	p.mu.Lock()
	conn, ok := p.conns[agentID]
	delete(p.conns, agentID)
	p.mu.Unlock()

	if ok {
		_ = conn.Close()
	}
}

// Close closes all connections in the pool.
func (p *ConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for id, conn := range p.conns {
		_ = conn.Close()
		delete(p.conns, id)
	}
}
