package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestOpenClawProxy_RejectsRemoteEndpoint(t *testing.T) {
	agent := &Agent{
		cfg:        AgentConfig{OpenClawURL: "http://example.com:8081"},
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
		ID:      "msg-remote-endpoint",
		Payload: json.RawMessage(`{"role":"user","content":"hello"}`),
	}
	err = cp.Send(ctx, msg)
	require.NoError(t, err)

	reply, err := cp.Recv(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.TypeError, reply.Type)

	var payload struct {
		Code string `json:"code"`
	}
	require.NoError(t, json.Unmarshal(reply.Payload, &payload))
	assert.Equal(t, "invalid_config", payload.Code)
}

func TestOpenClawProxy_AllowsRemoteEndpointWithOverride(t *testing.T) {
	agent := &Agent{
		cfg: AgentConfig{
			OpenClawURL:         "http://example.com:8081",
			AllowRemoteOpenClaw: true,
		},
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				assert.Equal(t, "example.com:8081", req.URL.Host)
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body: io.NopCloser(strings.NewReader(
						`{"choices":[{"message":{"content":"override-ok"}}]}`,
					)),
				}, nil
			}),
		},
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
		ID:      "msg-remote-override",
		Payload: json.RawMessage(`{"role":"user","content":"hello"}`),
	}
	err = cp.Send(ctx, msg)
	require.NoError(t, err)

	reply, err := cp.Recv(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.TypeChunk, reply.Type)
}

func TestForwardToOpenClaw_ToolCallLoop(t *testing.T) {
	// Track OpenClaw call count to return tool_calls on first call, text on second
	var openClawCalls int
	mockOpenClaw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		openClawCalls++
		w.Header().Set("Content-Type", "application/json")

		if openClawCalls == 1 {
			// First call: return a tool call
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{
					{
						"message": map[string]any{
							"content": "",
							"tool_calls": []map[string]any{
								{
									"id":   "call-1",
									"type": "function",
									"function": map[string]string{
										"name":      "search_players",
										"arguments": `{"query":"top scorer"}`,
									},
								},
							},
						},
					},
				},
			})
			return
		}

		// Second call: verify tool result was included, return final text
		var reqBody struct {
			Messages []json.RawMessage `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&reqBody)

		// Should have: user msg, assistant msg with tool_calls, tool result
		assert.GreaterOrEqual(t, len(reqBody.Messages), 3,
			"expected at least 3 messages: user + assistant + tool result")

		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": "Found 3 players"}},
			},
		})
	}))
	defer mockOpenClaw.Close()

	// Mock MCP server
	mockMCP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRPCRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		resp := jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: &toolCallResult{
				Content: []contentBlock{{Type: "text", Text: `[{"name":"Haaland","goals":36}]`}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockMCP.Close()

	agent := &Agent{
		cfg:           AgentConfig{OpenClawURL: mockOpenClaw.URL},
		httpClient:    &http.Client{Timeout: 5 * time.Second},
		mcp:           newMCPClient(&http.Client{Timeout: 5 * time.Second}),
		toolAllowlist: []string{"search_players"},
		connectors: []AgentConnector{
			{
				Name:     "football-api",
				Endpoint: mockMCP.URL,
				Auth:     json.RawMessage(`{}`),
				Tools:    []string{"search_players"},
			},
		},
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
		ID:      "msg-tool-loop",
		Payload: json.RawMessage(`{"role":"user","content":"who is the top scorer?"}`),
	}
	err = cp.Send(ctx, msg)
	require.NoError(t, err)

	// Collect frames — expect tool_executed audit frame then done chunk
	var gotToolExecuted bool
	var finalContent string
	for {
		reply, recvErr := cp.Recv(ctx)
		require.NoError(t, recvErr)

		switch reply.Type {
		case proxy.TypeToolExecuted:
			gotToolExecuted = true
			var meta map[string]any
			_ = json.Unmarshal(reply.Payload, &meta)
			assert.Equal(t, "search_players", meta["tool_name"])
			assert.Equal(t, "football-api", meta["connector_name"])
			continue

		case proxy.TypeChunk:
			var chunk struct {
				Content string `json:"content"`
				Done    bool   `json:"done"`
			}
			require.NoError(t, json.Unmarshal(reply.Payload, &chunk))
			if chunk.Done {
				finalContent = chunk.Content
				goto done
			}
			continue

		default:
			t.Fatalf("unexpected frame type: %s (payload: %s)", reply.Type, string(reply.Payload))
		}
	}
done:
	assert.True(t, gotToolExecuted, "expected tool_executed audit frame")
	assert.Equal(t, "Found 3 players", finalContent)
	assert.Equal(t, 2, openClawCalls, "expected exactly 2 OpenClaw calls (tool call + final)")
}

func TestForwardToOpenClaw_ToolCallLoop_ConnectorNotFound(t *testing.T) {
	// OpenClaw returns a tool call for a tool that has no connector
	mockOpenClaw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Always return a tool call — agent should feed error back and get text on next call
		var reqBody struct {
			Messages []json.RawMessage `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&reqBody)

		// If we have tool result messages, return final text
		if len(reqBody.Messages) > 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{
					{"message": map[string]string{"content": "No results available"}},
				},
			})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{
					"message": map[string]any{
						"content": "",
						"tool_calls": []map[string]any{
							{
								"id":   "call-orphan",
								"type": "function",
								"function": map[string]string{
									"name":      "unknown_tool",
									"arguments": `{}`,
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
		mcp:           newMCPClient(&http.Client{Timeout: 5 * time.Second}),
		toolAllowlist: []string{"unknown_tool"},
		connectors:    []AgentConnector{}, // empty — no connector for unknown_tool
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go agent.handleConnection(ctx, server)

	cp := proxy.NewAgentConn(client)
	_, err := cp.Recv(ctx) // skip heartbeat
	require.NoError(t, err)

	msg := proxy.Frame{
		Type:    proxy.TypeMessage,
		ID:      "msg-no-connector",
		Payload: json.RawMessage(`{"role":"user","content":"do something"}`),
	}
	err = cp.Send(ctx, msg)
	require.NoError(t, err)

	// Should get tool_failed then final chunk
	var gotToolFailed bool
	for {
		reply, recvErr := cp.Recv(ctx)
		require.NoError(t, recvErr)

		switch reply.Type {
		case proxy.TypeToolFailed:
			gotToolFailed = true
			continue
		case proxy.TypeChunk:
			var chunk struct {
				Done bool `json:"done"`
			}
			_ = json.Unmarshal(reply.Payload, &chunk)
			if chunk.Done {
				goto done2
			}
			continue
		default:
			t.Fatalf("unexpected frame type: %s", reply.Type)
		}
	}
done2:
	assert.True(t, gotToolFailed, "expected tool_failed audit frame")
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
