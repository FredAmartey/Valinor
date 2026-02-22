package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/proxy"
)

func TestOpenClawProxy_Message(t *testing.T) {
	// Mock OpenClaw HTTP server
	mockOpenClaw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)

		// Return a simple non-streaming response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": "The answer is 42"}},
			},
		})
	}))
	defer mockOpenClaw.Close()

	agent := &Agent{
		cfg: AgentConfig{OpenClawURL: mockOpenClaw.URL},
	}

	// Use net.Pipe for the vsock side
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Run agent connection handler
	go agent.handleConnection(ctx, server)

	cp := proxy.NewAgentConn(client)

	// Skip initial heartbeat
	_, err := cp.Recv(ctx)
	require.NoError(t, err)

	// Send message
	msg := proxy.Frame{
		Type:    proxy.TypeMessage,
		ID:      "msg-1",
		Payload: json.RawMessage(`{"role":"user","content":"What is the meaning of life?"}`),
	}
	err = cp.Send(ctx, msg)
	require.NoError(t, err)

	// Should receive a done chunk
	reply, err := cp.Recv(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.TypeChunk, reply.Type)

	var chunk struct {
		Content string `json:"content"`
		Done    bool   `json:"done"`
	}
	err = json.Unmarshal(reply.Payload, &chunk)
	require.NoError(t, err)
	assert.Contains(t, chunk.Content, "42")
	assert.True(t, chunk.Done)
}

func TestOpenClawProxy_ToolBlocked(t *testing.T) {
	// Mock OpenClaw that returns a tool call
	mockOpenClaw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{
					"message": map[string]any{
						"tool_calls": []map[string]any{
							{
								"function": map[string]string{
									"name":      "delete_all_data",
									"arguments": "{}",
								},
							},
						},
					},
				},
			},
		})
	}))
	defer mockOpenClaw.Close()

	agent := &Agent{
		cfg:           AgentConfig{OpenClawURL: mockOpenClaw.URL},
		toolAllowlist: []string{"search_players"}, // delete_all_data is NOT allowed
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go agent.handleConnection(ctx, server)

	cp := proxy.NewAgentConn(client)

	// Skip initial heartbeat
	_, err := cp.Recv(ctx)
	require.NoError(t, err)

	msg := proxy.Frame{
		Type:    proxy.TypeMessage,
		ID:      "msg-2",
		Payload: json.RawMessage(`{"role":"user","content":"delete everything"}`),
	}
	err = cp.Send(ctx, msg)
	require.NoError(t, err)

	reply, err := cp.Recv(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.TypeToolBlocked, reply.Type)

	var blocked struct {
		ToolName string `json:"tool_name"`
		Reason   string `json:"reason"`
	}
	err = json.Unmarshal(reply.Payload, &blocked)
	require.NoError(t, err)
	assert.Equal(t, "delete_all_data", blocked.ToolName)
}
