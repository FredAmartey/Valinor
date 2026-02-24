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

	"github.com/valinor-ai/valinor/internal/proxy"
)

// openClawResponse models the OpenClaw chat completions response.
type openClawResponse struct {
	Choices []struct {
		Message struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
}

// forwardToOpenClaw sends a message to OpenClaw and returns response frames.
func (a *Agent) forwardToOpenClaw(ctx context.Context, conn *proxy.AgentConn, frame proxy.Frame) {
	if err := validateOpenClawURL(a.cfg.OpenClawURL, false); err != nil {
		a.sendError(ctx, conn, frame.ID, "invalid_config", err.Error())
		return
	}

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

	messages := make([]map[string]string, 0, len(msg.Messages)+1)
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

	// Build OpenClaw request
	reqBody := map[string]any{
		"messages": messages,
	}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		a.sendError(ctx, conn, frame.ID, "marshal_error", "failed to marshal request")
		return
	}

	url := fmt.Sprintf("%s/v1/chat/completions", a.cfg.OpenClawURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyJSON))
	if err != nil {
		a.sendError(ctx, conn, frame.ID, "request_error", "failed to create request")
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		a.sendError(ctx, conn, frame.ID, "openclaw_error", fmt.Sprintf("OpenClaw request failed: %v", err))
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		a.sendError(ctx, conn, frame.ID, "read_error", "failed to read OpenClaw response")
		return
	}

	if resp.StatusCode != http.StatusOK {
		a.sendError(ctx, conn, frame.ID, "openclaw_error", fmt.Sprintf("OpenClaw returned %d", resp.StatusCode))
		return
	}

	var ocResp openClawResponse
	err = json.Unmarshal(respBody, &ocResp)
	if err != nil {
		a.sendError(ctx, conn, frame.ID, "parse_error", "failed to parse OpenClaw response")
		return
	}

	if len(ocResp.Choices) == 0 {
		a.sendError(ctx, conn, frame.ID, "empty_response", "OpenClaw returned no choices")
		return
	}

	choice := ocResp.Choices[0]

	// Check for tool calls
	if len(choice.Message.ToolCalls) > 0 {
		for _, tc := range choice.Message.ToolCalls {
			result := a.validateToolCall(tc.Function.Name, tc.Function.Arguments)
			if !result.Allowed {
				var payload []byte
				payload, err = json.Marshal(map[string]string{
					"tool_name": tc.Function.Name,
					"reason":    result.Reason,
				})
				if err != nil {
					slog.Error("marshal tool_blocked payload failed", "error", err)
					return
				}
				blocked := proxy.Frame{
					Type:    proxy.TypeToolBlocked,
					ID:      frame.ID,
					Payload: payload,
				}
				err = conn.Send(ctx, blocked)
				if err != nil {
					slog.Error("tool_blocked send failed", "error", err)
				}
				return
			}
		}
		// All tools allowed — in a full implementation, we'd execute them
		// For MVP, send the content back
	}

	// Check for canary token leak
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

	// Send content as done chunk
	content := choice.Message.Content
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
		ID:      frame.ID,
		Payload: payload,
	}
	if err := conn.Send(ctx, chunk); err != nil {
		slog.Error("chunk send failed", "error", err)
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
