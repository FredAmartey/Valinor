package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/proxy"
)

func TestAgent_PingPong(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	agent := &Agent{
		cfg: AgentConfig{OpenClawURL: "http://localhost:8081"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Run agent loop in background
	go agent.handleConnection(ctx, server)

	// Send ping from control plane side
	cp := proxy.NewAgentConn(client)
	ping := proxy.Frame{
		Type:    proxy.TypePing,
		ID:      "ping-1",
		Payload: json.RawMessage(`{}`),
	}

	// Read initial heartbeat first
	hb, err := cp.Recv(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.TypeHeartbeat, hb.Type)

	err = cp.Send(ctx, ping)
	require.NoError(t, err)

	// Should get pong
	reply, err := cp.Recv(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.TypePong, reply.Type)
	assert.Equal(t, "ping-1", reply.ID)
}

func TestAgent_ConfigUpdate(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	agent := &Agent{
		cfg: AgentConfig{OpenClawURL: "http://localhost:8081"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go agent.handleConnection(ctx, server)

	cp := proxy.NewAgentConn(client)

	// Skip initial heartbeat
	_, err := cp.Recv(ctx)
	require.NoError(t, err)

	// Send config update
	configPayload := json.RawMessage(`{"config":{"model":"gpt-4o"},"tool_allowlist":["search"]}`)
	configFrame := proxy.Frame{
		Type:    proxy.TypeConfigUpdate,
		ID:      "cfg-1",
		Payload: configPayload,
	}
	err = cp.Send(ctx, configFrame)
	require.NoError(t, err)

	// Should get config_ack
	reply, err := cp.Recv(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.TypeConfigAck, reply.Type)
	assert.Equal(t, "cfg-1", reply.ID)

	// Verify allow-list was applied
	assert.Equal(t, []string{"search"}, agent.toolAllowlist)
}

func TestAgent_ConfigUpdate_ToolPoliciesAndCanary(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	agent := &Agent{
		cfg:        AgentConfig{OpenClawURL: "http://localhost:8081"},
		httpClient: &http.Client{Timeout: 2 * time.Second},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go agent.handleConnection(ctx, server)

	cp := proxy.NewAgentConn(client)

	// Skip initial heartbeat
	_, err := cp.Recv(ctx)
	require.NoError(t, err)

	// Send config with tool_policies and canary_tokens
	configPayload := json.RawMessage(`{
		"config":{"model":"gpt-4o"},
		"tool_allowlist":["search_players"],
		"tool_policies":{"search_players":{"allowed_params":["league","position"],"denied_params":["salary"]}},
		"canary_tokens":["CANARY-abc123"]
	}`)
	configFrame := proxy.Frame{
		Type:    proxy.TypeConfigUpdate,
		ID:      "cfg-2",
		Payload: configPayload,
	}
	err = cp.Send(ctx, configFrame)
	require.NoError(t, err)

	reply, err := cp.Recv(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.TypeConfigAck, reply.Type)

	// Verify policies applied
	agent.mu.RLock()
	assert.Equal(t, []string{"search_players"}, agent.toolAllowlist)
	assert.Contains(t, agent.toolPolicies, "search_players")
	assert.Equal(t, []string{"salary"}, agent.toolPolicies["search_players"].DeniedParams)
	assert.Equal(t, []string{"CANARY-abc123"}, agent.canaryTokens)
	agent.mu.RUnlock()
}
