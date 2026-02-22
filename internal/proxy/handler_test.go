package proxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/proxy"
)

// mockAgentStore implements the interface proxy.Handler needs to look up agents.
type mockAgentStore struct {
	agents map[string]*orchestrator.AgentInstance
}

func (m *mockAgentStore) GetByID(_ context.Context, id string) (*orchestrator.AgentInstance, error) {
	inst, ok := m.agents[id]
	if !ok {
		return nil, orchestrator.ErrVMNotFound
	}
	return inst, nil
}

func TestHandleMessage_Success(t *testing.T) {
	transport := proxy.NewTCPTransport(9800)
	pool := proxy.NewConnPool(transport)
	defer pool.Close()

	cid := uint32(3)
	agentID := "agent-1"
	tenantID := "tenant-1"

	store := &mockAgentStore{
		agents: map[string]*orchestrator.AgentInstance{
			agentID: {
				ID:       agentID,
				TenantID: &tenantID,
				VsockCID: &cid,
				Status:   orchestrator.StatusRunning,
			},
		},
	}

	handler := proxy.NewHandler(pool, store, proxy.HandlerConfig{
		MessageTimeout: 5 * time.Second,
	})

	// Start mock agent that echoes back as a done chunk
	ctx := context.Background()
	ln, err := transport.Listen(ctx, cid)
	require.NoError(t, err)
	defer ln.Close()

	go mockAgent(t, ln)

	// Send message
	body := `{"role":"user","content":"hello"}`
	req := httptest.NewRequest("POST", "/agents/"+agentID+"/message", bytes.NewBufferString(body))
	req.SetPathValue("id", agentID)
	w := httptest.NewRecorder()

	handler.HandleMessage(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp, "content")
}

func TestHandleMessage_AgentNotFound(t *testing.T) {
	transport := proxy.NewTCPTransport(9810)
	pool := proxy.NewConnPool(transport)
	defer pool.Close()

	store := &mockAgentStore{agents: map[string]*orchestrator.AgentInstance{}}

	handler := proxy.NewHandler(pool, store, proxy.HandlerConfig{
		MessageTimeout: 5 * time.Second,
	})

	body := `{"role":"user","content":"hello"}`
	req := httptest.NewRequest("POST", "/agents/bad-id/message", bytes.NewBufferString(body))
	req.SetPathValue("id", "bad-id")
	w := httptest.NewRecorder()

	handler.HandleMessage(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleMessage_AgentNotRunning(t *testing.T) {
	transport := proxy.NewTCPTransport(9820)
	pool := proxy.NewConnPool(transport)
	defer pool.Close()

	agentID := "agent-1"
	tenantID := "tenant-1"
	cid := uint32(3)

	store := &mockAgentStore{
		agents: map[string]*orchestrator.AgentInstance{
			agentID: {
				ID:       agentID,
				TenantID: &tenantID,
				VsockCID: &cid,
				Status:   orchestrator.StatusProvisioning,
			},
		},
	}

	handler := proxy.NewHandler(pool, store, proxy.HandlerConfig{
		MessageTimeout: 5 * time.Second,
	})

	body := `{"role":"user","content":"hello"}`
	req := httptest.NewRequest("POST", "/agents/"+agentID+"/message", bytes.NewBufferString(body))
	req.SetPathValue("id", agentID)
	w := httptest.NewRecorder()

	handler.HandleMessage(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandleStream_SSE(t *testing.T) {
	transport := proxy.NewTCPTransport(9830)
	pool := proxy.NewConnPool(transport)
	defer pool.Close()

	cid := uint32(3)
	agentID := "agent-1"
	tenantID := "tenant-1"

	store := &mockAgentStore{
		agents: map[string]*orchestrator.AgentInstance{
			agentID: {
				ID:       agentID,
				TenantID: &tenantID,
				VsockCID: &cid,
				Status:   orchestrator.StatusRunning,
			},
		},
	}

	handler := proxy.NewHandler(pool, store, proxy.HandlerConfig{
		MessageTimeout: 5 * time.Second,
	})

	ctx := context.Background()
	ln, err := transport.Listen(ctx, cid)
	require.NoError(t, err)
	defer ln.Close()

	// Mock agent that sends two chunks
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		ac := proxy.NewAgentConn(conn)
		frame, err := ac.Recv(ctx)
		if err != nil {
			return
		}

		chunk1 := proxy.Frame{
			Type:    proxy.TypeChunk,
			ID:      frame.ID,
			Payload: json.RawMessage(`{"content":"Hello ","done":false}`),
		}
		_ = ac.Send(ctx, chunk1)

		chunk2 := proxy.Frame{
			Type:    proxy.TypeChunk,
			ID:      frame.ID,
			Payload: json.RawMessage(`{"content":"World","done":true}`),
		}
		_ = ac.Send(ctx, chunk2)
	}()

	body := `{"role":"user","content":"hello"}`
	req := httptest.NewRequest("GET", "/agents/"+agentID+"/stream?message="+body, nil)
	req.SetPathValue("id", agentID)
	w := httptest.NewRecorder()

	handler.HandleStream(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))

	// Verify SSE format
	respBody := w.Body.String()
	assert.Contains(t, respBody, "event: chunk")
	assert.Contains(t, respBody, "event: done")
	assert.Contains(t, respBody, `"content":"Hello "`)
	assert.Contains(t, respBody, `"content":"World"`)
}

// mockAgent accepts one connection, reads a message frame, and replies with a done chunk.
func mockAgent(t *testing.T, ln net.Listener) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	ac := proxy.NewAgentConn(conn)
	ctx := context.Background()

	frame, err := ac.Recv(ctx)
	if err != nil {
		return
	}

	reply := proxy.Frame{
		Type:    proxy.TypeChunk,
		ID:      frame.ID,
		Payload: json.RawMessage(`{"content":"Echo: hello","done":true}`),
	}
	_ = ac.Send(ctx, reply)
}
