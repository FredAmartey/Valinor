package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

// JSON-RPC 2.0 types for MCP tools/call

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Result  *toolCallResult `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type toolCallResult struct {
	Content []contentBlock `json:"content"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// mcpClient executes MCP tool calls over HTTP JSON-RPC 2.0.
type mcpClient struct {
	httpClient *http.Client
}

func newMCPClient(httpClient *http.Client) *mcpClient {
	return &mcpClient{httpClient: httpClient}
}

// callTool executes a tools/call JSON-RPC request against a connector's endpoint.
func (c *mcpClient) callTool(ctx context.Context, connector AgentConnector, toolName string, arguments string) (string, error) {
	// Validate endpoint URL scheme
	parsed, err := url.Parse(connector.Endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid connector endpoint URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("connector endpoint must use http or https scheme, got %q", parsed.Scheme)
	}

	params, err := json.Marshal(toolCallParams{
		Name:      toolName,
		Arguments: json.RawMessage(arguments),
	})
	if err != nil {
		return "", fmt.Errorf("marshaling tool call params: %w", err)
	}

	rpcReq := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  "tools/call",
		Params:  params,
	}

	body, err := json.Marshal(rpcReq)
	if err != nil {
		return "", fmt.Errorf("marshaling JSON-RPC request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", connector.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Apply auth from connector config
	var authConfig struct {
		APIKey string `json:"api_key"`
	}
	if len(connector.Auth) > 0 && !bytes.Equal(connector.Auth, []byte("{}")) {
		if unmarshalErr := json.Unmarshal(connector.Auth, &authConfig); unmarshalErr != nil {
			slog.Warn("failed to parse connector auth config", "connector", connector.Name, "error", unmarshalErr)
			return "", fmt.Errorf("parsing connector auth config: %w", unmarshalErr)
		}
	}
	if authConfig.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+authConfig.APIKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("MCP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("reading MCP response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("MCP server returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return "", fmt.Errorf("parsing MCP JSON-RPC response: %w", err)
	}

	if rpcResp.Error != nil {
		return "", fmt.Errorf("MCP error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	if rpcResp.Result == nil {
		return "", fmt.Errorf("MCP response has no result")
	}

	// Extract text from content blocks
	var sb strings.Builder
	for _, block := range rpcResp.Result.Content {
		if block.Type == "text" {
			sb.WriteString(block.Text)
		}
	}
	return sb.String(), nil
}

// resolveConnector finds which connector owns a given tool name.
func resolveConnector(connectors []AgentConnector, toolName string) (AgentConnector, error) {
	for _, c := range connectors {
		for _, t := range c.Tools {
			if t == toolName {
				return c, nil
			}
		}
	}
	return AgentConnector{}, fmt.Errorf("no connector registered for tool %q", toolName)
}
