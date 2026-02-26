package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/valinor-ai/valinor/internal/proxy"
)

const maxToolIterations = 10

// openClawResponse models the OpenClaw chat completions response.
type openClawResponse struct {
	Choices []struct {
		Message struct {
			Content   string     `json:"content"`
			ToolCalls []toolCall `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
}

type toolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// callOpenClaw sends a chat completions request to OpenClaw and returns the parsed response.
func (a *Agent) callOpenClaw(ctx context.Context, messages []any) (*openClawResponse, error) {
	reqBody := map[string]any{
		"messages": messages,
	}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/chat/completions", a.cfg.OpenClawURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("OpenClaw request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenClaw returned %d", resp.StatusCode)
	}

	var ocResp openClawResponse
	if err := json.Unmarshal(respBody, &ocResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	if len(ocResp.Choices) == 0 {
		return nil, fmt.Errorf("OpenClaw returned no choices")
	}

	return &ocResp, nil
}

// forwardToOpenClaw sends a message to OpenClaw and loops through tool calls until a final text response.
func (a *Agent) forwardToOpenClaw(ctx context.Context, conn *proxy.AgentConn, frame proxy.Frame) {
	// Total timeout for the entire tool execution loop
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	if err := validateOpenClawURL(a.cfg.OpenClawURL, a.cfg.AllowRemoteOpenClaw); err != nil {
		a.sendError(ctx, conn, frame.ID, "invalid_config", err.Error())
		return
	}

	// Parse initial messages from frame payload
	var msg struct {
		Role     string `json:"role"`
		Content  string `json:"content"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(frame.Payload, &msg); err != nil {
		a.sendError(ctx, conn, frame.ID, "invalid_message", "invalid message payload")
		return
	}

	// messages uses []any because OpenAI chat format requires heterogeneous shapes
	// (user=map[string]string, assistant=map with tool_calls, tool=map with tool_call_id)
	var messages []any
	for _, item := range msg.Messages {
		role := strings.TrimSpace(item.Role)
		content := strings.TrimSpace(item.Content)
		if role == "" || content == "" {
			continue
		}
		messages = append(messages, map[string]string{
			"role":    role,
			"content": content,
		})
	}
	if len(messages) == 0 {
		role := strings.TrimSpace(msg.Role)
		content := strings.TrimSpace(msg.Content)
		if role == "" || content == "" {
			a.sendError(ctx, conn, frame.ID, "invalid_message", "invalid message payload")
			return
		}
		messages = append(messages, map[string]string{
			"role":    role,
			"content": content,
		})
	}

	// Agentic tool execution loop
	for iteration := 0; iteration < maxToolIterations; iteration++ {
		ocResp, err := a.callOpenClaw(ctx, messages)
		if err != nil {
			a.sendError(ctx, conn, frame.ID, "openclaw_error", err.Error())
			return
		}

		choice := ocResp.Choices[0]

		// Check for canary token leak in content
		if found, token := a.checkCanary(choice.Message.Content); found {
			slog.Error("canary token detected in OpenClaw response", "token", token)
			haltPayload, _ := json.Marshal(map[string]string{
				"reason": "canary_leak",
				"token":  token,
			})
			halt := proxy.Frame{
				Type:    proxy.TypeSessionHalt,
				ID:      frame.ID,
				Payload: haltPayload,
			}
			if sendErr := conn.Send(ctx, halt); sendErr != nil {
				slog.Error("session_halt send failed", "error", sendErr)
			}
			return
		}

		// No tool calls → final text response
		if len(choice.Message.ToolCalls) == 0 {
			a.sendDoneChunk(ctx, conn, frame.ID, choice.Message.Content)
			return
		}

		// Validate all tool calls before executing any
		for _, tc := range choice.Message.ToolCalls {
			result := a.validateToolCall(tc.Function.Name, tc.Function.Arguments)
			if !result.Allowed {
				payload, marshalErr := json.Marshal(map[string]string{
					"tool_name": tc.Function.Name,
					"reason":    result.Reason,
				})
				if marshalErr != nil {
					slog.Error("marshal tool_blocked payload failed", "error", marshalErr)
					return
				}
				blocked := proxy.Frame{
					Type:    proxy.TypeToolBlocked,
					ID:      frame.ID,
					Payload: payload,
				}
				if sendErr := conn.Send(ctx, blocked); sendErr != nil {
					slog.Error("tool_blocked send failed", "error", sendErr)
				}
				return
			}
		}

		// Append assistant message (with tool_calls) to conversation
		messages = append(messages, map[string]any{
			"role":       "assistant",
			"content":    choice.Message.Content,
			"tool_calls": choice.Message.ToolCalls,
		})

		// Execute each tool call via MCP
		a.mu.RLock()
		currentConnectors := a.connectors
		a.mu.RUnlock()

		for _, tc := range choice.Message.ToolCalls {
			start := time.Now()

			connector, resolveErr := resolveConnector(currentConnectors, tc.Function.Name)
			if resolveErr != nil {
				errMsg := fmt.Sprintf("error: %v", resolveErr)
				messages = append(messages, map[string]any{
					"role":         "tool",
					"tool_call_id": tc.ID,
					"content":      errMsg,
				})
				a.emitToolAudit(ctx, conn, frame.ID, proxy.TypeToolFailed, tc.Function.Name, "", time.Since(start), resolveErr.Error())
				continue
			}

			toolResult, callErr := a.mcp.callTool(ctx, connector, tc.Function.Name, tc.Function.Arguments)
			elapsed := time.Since(start)

			if callErr != nil {
				errMsg := fmt.Sprintf("error: %v", callErr)
				messages = append(messages, map[string]any{
					"role":         "tool",
					"tool_call_id": tc.ID,
					"content":      errMsg,
				})
				a.emitToolAudit(ctx, conn, frame.ID, proxy.TypeToolFailed, tc.Function.Name, connector.Name, elapsed, callErr.Error())
				continue
			}

			// Check tool result for canary token leak
			if found, token := a.checkCanary(toolResult); found {
				slog.Error("canary token detected in tool result", "tool", tc.Function.Name, "token", token)
				haltPayload, _ := json.Marshal(map[string]string{
					"reason": "canary_leak",
					"token":  token,
					"source": "tool:" + tc.Function.Name,
				})
				halt := proxy.Frame{
					Type:    proxy.TypeSessionHalt,
					ID:      frame.ID,
					Payload: haltPayload,
				}
				if sendErr := conn.Send(ctx, halt); sendErr != nil {
					slog.Error("session_halt send failed", "error", sendErr)
				}
				return
			}

			messages = append(messages, map[string]any{
				"role":         "tool",
				"tool_call_id": tc.ID,
				"content":      toolResult,
			})
			a.emitToolAudit(ctx, conn, frame.ID, proxy.TypeToolExecuted, tc.Function.Name, connector.Name, elapsed, "")
		}
		// Loop continues with updated messages
	}

	a.sendError(ctx, conn, frame.ID, "max_iterations", "tool call loop exceeded maximum iterations")
}

// sendDoneChunk sends a final content chunk to the control plane.
func (a *Agent) sendDoneChunk(ctx context.Context, conn *proxy.AgentConn, reqID, content string) {
	payload, err := json.Marshal(map[string]any{
		"content": content,
		"done":    true,
	})
	if err != nil {
		slog.Error("marshal chunk payload failed", "error", err)
		return
	}
	chunk := proxy.Frame{
		Type:    proxy.TypeChunk,
		ID:      reqID,
		Payload: payload,
	}
	if err := conn.Send(ctx, chunk); err != nil {
		slog.Error("chunk send failed", "error", err)
	}
}

// emitToolAudit sends a fire-and-forget audit frame to the control plane.
func (a *Agent) emitToolAudit(ctx context.Context, conn *proxy.AgentConn, reqID, frameType, toolName, connectorName string, elapsed time.Duration, errMsg string) {
	meta := map[string]any{
		"tool_name":   toolName,
		"duration_ms": elapsed.Milliseconds(),
	}
	if connectorName != "" {
		meta["connector_name"] = connectorName
	}
	if errMsg != "" {
		meta["error"] = errMsg
	}
	payload, err := json.Marshal(meta)
	if err != nil {
		slog.Error("marshal tool audit payload failed", "error", err)
		return
	}
	auditFrame := proxy.Frame{
		Type:    frameType,
		ID:      reqID,
		Payload: payload,
	}
	if err := conn.Send(ctx, auditFrame); err != nil {
		slog.Warn("failed to send tool audit frame", "type", frameType, "tool", toolName, "error", err)
	}
}

func (a *Agent) sendError(ctx context.Context, conn *proxy.AgentConn, reqID, code, message string) {
	slog.Error("agent error", "code", code, "message", message)
	payload, err := json.Marshal(map[string]string{
		"code":    code,
		"message": message,
	})
	if err != nil {
		slog.Error("marshal error payload failed", "error", err)
		return
	}
	errFrame := proxy.Frame{
		Type:    proxy.TypeError,
		ID:      reqID,
		Payload: payload,
	}
	_ = conn.Send(ctx, errFrame)
}
