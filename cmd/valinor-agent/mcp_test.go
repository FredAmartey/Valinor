package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPClient_CallTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))

		var req jsonRPCRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "2.0", req.JSONRPC)
		assert.Equal(t, "tools/call", req.Method)

		var params toolCallParams
		require.NoError(t, json.Unmarshal(req.Params, &params))
		assert.Equal(t, "search_players", params.Name)

		resp := jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: &toolCallResult{
				Content: []contentBlock{{Type: "text", Text: `{"players":["messi"]}`}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := newMCPClient(&http.Client{})
	connector := AgentConnector{
		Name:     "test-api",
		Endpoint: server.URL,
		Auth:     json.RawMessage(`{"api_key":"test-key"}`),
		Tools:    []string{"search_players"},
	}

	result, err := client.callTool(context.Background(), connector, "search_players", `{"league":"Serie A"}`)
	require.NoError(t, err)
	assert.Contains(t, result, "messi")
}

func TestMCPClient_CallTool_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      "1",
			Error:   &jsonRPCError{Code: -32601, Message: "method not found"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := newMCPClient(&http.Client{})
	connector := AgentConnector{
		Name:     "test-api",
		Endpoint: server.URL,
		Auth:     json.RawMessage(`{}`),
		Tools:    []string{"bad_tool"},
	}

	_, err := client.callTool(context.Background(), connector, "bad_tool", `{}`)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "method not found")
}

func TestResolveConnector(t *testing.T) {
	connectors := []AgentConnector{
		{Name: "api-a", Tools: []string{"tool_1", "tool_2"}},
		{Name: "api-b", Tools: []string{"tool_3"}},
	}

	c, err := resolveConnector(connectors, "tool_3")
	require.NoError(t, err)
	assert.Equal(t, "api-b", c.Name)

	_, err = resolveConnector(connectors, "unknown")
	assert.Error(t, err)
}
