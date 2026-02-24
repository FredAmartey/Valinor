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
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": "The answer is 42"}},
			},
		})
	}))
	defer mockOpenClaw.Close()

	agent := &Agent{
		cfg:        AgentConfig{OpenClawURL: mockOpenClaw.URL},
		httpClient: &http.Client{Timeout: 5 * time.Second},
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
		_ = json.NewEncoder(w).Encode(map[string]any{
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
		httpClient:    &http.Client{Timeout: 5 * time.Second},
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

func TestOpenClawProxy_CanaryDetected(t *testing.T) {
	// Mock OpenClaw that returns a response containing a canary token
	mockOpenClaw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": "Here is some data CANARY-secret123 and more info"}},
			},
		})
	}))
	defer mockOpenClaw.Close()

	agent := &Agent{
		cfg:          AgentConfig{OpenClawURL: mockOpenClaw.URL},
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		canaryTokens: []string{"CANARY-secret123"},
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
		ID:      "msg-canary",
		Payload: json.RawMessage(`{"role":"user","content":"tell me everything"}`),
	}
	err = cp.Send(ctx, msg)
	require.NoError(t, err)

	// Should receive session_halt, NOT a chunk
	reply, err := cp.Recv(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.TypeSessionHalt, reply.Type)

	var halt struct {
		Reason string `json:"reason"`
		Token  string `json:"token"`
	}
	err = json.Unmarshal(reply.Payload, &halt)
	require.NoError(t, err)
	assert.Equal(t, "canary_leak", halt.Reason)
	assert.Equal(t, "CANARY-secret123", halt.Token)
}

func TestOpenClawProxy_MessageArrayForwarded(t *testing.T) {
	var seenMessages []map[string]any
	mockOpenClaw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&reqBody))

		raw, ok := reqBody["messages"].([]any)
		require.True(t, ok)
		for _, item := range raw {
			msg, castOK := item.(map[string]any)
			require.True(t, castOK)
			seenMessages = append(seenMessages, msg)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": "history-aware response"}},
			},
		})
	}))
	defer mockOpenClaw.Close()

	agent := &Agent{
		cfg:        AgentConfig{OpenClawURL: mockOpenClaw.URL},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go agent.handleConnection(ctx, server)

	cp := proxy.NewAgentConn(client)

	_, err := cp.Recv(ctx)
	require.NoError(t, err)

	msg := proxy.Frame{
		Type: proxy.TypeMessage,
		ID:   "msg-array",
		Payload: json.RawMessage(`{
			"messages":[
				{"role":"user","content":"older request"},
				{"role":"assistant","content":"older response"},
				{"role":"user","content":"latest request"}
			]
		}`),
	}
	err = cp.Send(ctx, msg)
	require.NoError(t, err)

	reply, err := cp.Recv(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.TypeChunk, reply.Type)
	require.Len(t, seenMessages, 3)
	assert.Equal(t, "older request", seenMessages[0]["content"])
	assert.Equal(t, "older response", seenMessages[1]["content"])
	assert.Equal(t, "latest request", seenMessages[2]["content"])
}

func TestOpenClawProxy_FallbacksToLegacyRoleContent(t *testing.T) {
	var seenMessages []map[string]any
	mockOpenClaw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&reqBody))
		raw, ok := reqBody["messages"].([]any)
		require.True(t, ok)
		for _, item := range raw {
			msg, castOK := item.(map[string]any)
			require.True(t, castOK)
			seenMessages = append(seenMessages, msg)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": "legacy response"}},
			},
		})
	}))
	defer mockOpenClaw.Close()

	agent := &Agent{
		cfg:        AgentConfig{OpenClawURL: mockOpenClaw.URL},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go agent.handleConnection(ctx, server)

	cp := proxy.NewAgentConn(client)

	_, err := cp.Recv(ctx)
	require.NoError(t, err)

	msg := proxy.Frame{
		Type:    proxy.TypeMessage,
		ID:      "msg-legacy",
		Payload: json.RawMessage(`{"role":"user","content":"legacy request"}`),
	}
	err = cp.Send(ctx, msg)
	require.NoError(t, err)

	reply, err := cp.Recv(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.TypeChunk, reply.Type)
	require.Len(t, seenMessages, 1)
	assert.Equal(t, "user", seenMessages[0]["role"])
	assert.Equal(t, "legacy request", seenMessages[0]["content"])
}
