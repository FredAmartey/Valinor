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

func TestEndToEnd_MessageRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	transport := proxy.NewTCPTransport(19900)
	pool := proxy.NewConnPool(transport)
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cid := uint32(5)
	agentID := "e2e-agent"
	tenantID := "e2e-tenant"

	// Start a realistic mock agent
	ln, err := transport.Listen(ctx, cid)
	require.NoError(t, err)
	defer ln.Close()

	go runMockAgent(t, ctx, ln)

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
		MessageTimeout: 10 * time.Second,
	})

	// Test 1: POST /message — full response
	body := `{"role":"user","content":"What is 2+2?"}`
	req := httptest.NewRequest("POST", "/agents/"+agentID+"/message", bytes.NewBufferString(body))
	req.SetPathValue("id", agentID)
	req = withTestAuth(req, tenantID)
	w := httptest.NewRecorder()

	handler.HandleMessage(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["content"], "4")

	// Test 2: GET /stream — SSE
	pool.Remove(agentID) // force new connection for second test
	ln.Close()           // release port before re-listening

	// Start another agent listener for the same CID
	ln2, err := transport.Listen(ctx, cid)
	require.NoError(t, err)
	defer ln2.Close()

	go runStreamingMockAgent(t, ctx, ln2)

	streamBody := `{"role":"user","content":"stream test"}`
	req2 := httptest.NewRequest("POST", "/agents/"+agentID+"/stream", bytes.NewBufferString(streamBody))
	req2.SetPathValue("id", agentID)
	req2 = withTestAuth(req2, tenantID)
	w2 := httptest.NewRecorder()

	handler.HandleStream(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "text/event-stream", w2.Header().Get("Content-Type"))
	assert.Contains(t, w2.Body.String(), "event: chunk")
	assert.Contains(t, w2.Body.String(), "event: done")
}

// runMockAgent simulates a valinor-agent that replies to messages.
func runMockAgent(t *testing.T, ctx context.Context, ln net.Listener) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	ac := proxy.NewAgentConn(conn)

	for {
		frame, err := ac.Recv(ctx)
		if err != nil {
			return
		}

		switch frame.Type {
		case proxy.TypeMessage:
			reply := proxy.Frame{
				Type:    proxy.TypeChunk,
				ID:      frame.ID,
				Payload: json.RawMessage(`{"content":"The answer is 4","done":true}`),
			}
			if err := ac.Send(ctx, reply); err != nil {
				return
			}
		case proxy.TypePing:
			pong := proxy.Frame{
				Type:    proxy.TypePong,
				ID:      frame.ID,
				Payload: json.RawMessage(`{}`),
			}
			_ = ac.Send(ctx, pong)
		}
	}
}

// runStreamingMockAgent sends two chunks for any message.
func runStreamingMockAgent(t *testing.T, ctx context.Context, ln net.Listener) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	ac := proxy.NewAgentConn(conn)

	for {
		frame, err := ac.Recv(ctx)
		if err != nil {
			return
		}

		if frame.Type == proxy.TypeMessage {
			chunk1 := proxy.Frame{
				Type:    proxy.TypeChunk,
				ID:      frame.ID,
				Payload: json.RawMessage(`{"content":"Streaming ","done":false}`),
			}
			_ = ac.Send(ctx, chunk1)

			chunk2 := proxy.Frame{
				Type:    proxy.TypeChunk,
				ID:      frame.ID,
				Payload: json.RawMessage(`{"content":"response","done":true}`),
			}
			_ = ac.Send(ctx, chunk2)
		}
	}
}
