package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

// TokenValidator validates a raw JWT string and returns the identity.
type TokenValidator interface {
	ValidateToken(token string) (*auth.Identity, error)
}

// wsClientMessage is the JSON shape clients send over the WebSocket.
type wsClientMessage struct {
	Type    string `json:"type"`
	Content string `json:"content"`
}

// wsServerMessage is the JSON shape the server sends to clients.
type wsServerMessage struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id,omitempty"`
	Content   string `json:"content,omitempty"`
	Done      bool   `json:"done,omitempty"`
	ToolName  string `json:"tool_name,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Message   string `json:"message,omitempty"`
}

// wsIdleTimeout is the maximum time the server waits for a client message
// before closing an idle connection. Resets on each received message.
const wsIdleTimeout = 10 * time.Minute

// HandleWebSocket upgrades to a WebSocket connection for bidirectional
// agent messaging. Auth is performed via access_token query parameter
// since browsers cannot set headers on WebSocket upgrade.
func (h *Handler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if agentID == "" {
		http.Error(w, `{"error":"missing agent id"}`, http.StatusBadRequest)
		return
	}

	// Auth via query parameter (browsers can't set headers on WS upgrade)
	rawToken := r.URL.Query().Get("access_token")
	if rawToken == "" {
		http.Error(w, `{"error":"missing access_token"}`, http.StatusUnauthorized)
		return
	}

	identity, err := h.tokenValidator.ValidateToken(rawToken)
	if err != nil {
		if errors.Is(err, auth.ErrTokenExpired) {
			http.Error(w, `{"error":"token expired"}`, http.StatusUnauthorized)
		} else {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
		}
		return
	}

	if identity.TokenType != "access" {
		http.Error(w, `{"error":"invalid token type"}`, http.StatusUnauthorized)
		return
	}

	// RBAC — require agents:write (same as HTTP message/stream routes)
	if !identity.IsPlatformAdmin && h.rbacEval != nil {
		decision, rbacErr := h.rbacEval.Authorize(r.Context(), identity, "agents:write", "", "")
		if rbacErr != nil || !decision.Allowed {
			http.Error(w, `{"error":"insufficient permissions"}`, http.StatusForbidden)
			return
		}
	}

	// Look up agent and verify ownership
	inst, err := h.agents.GetByID(r.Context(), agentID)
	if err != nil {
		http.Error(w, `{"error":"agent not found"}`, http.StatusNotFound)
		return
	}

	if !identity.IsPlatformAdmin && inst.TenantID != nil && identity.TenantID != *inst.TenantID {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}

	if inst.Status != orchestrator.StatusRunning {
		http.Error(w, `{"error":"agent is not running"}`, http.StatusServiceUnavailable)
		return
	}

	if inst.VsockCID == nil {
		http.Error(w, `{"error":"agent has no vsock connection"}`, http.StatusServiceUnavailable)
		return
	}

	// Inject identity into context for downstream use
	ctx := auth.WithIdentity(r.Context(), identity)
	ctx = middleware.WithTenantID(ctx, identity.TenantID)

	// Upgrade to WebSocket — restrict origins to configured CORS origins
	acceptOpts := &websocket.AcceptOptions{}
	if len(h.cfg.WSAllowedOrigins) > 0 {
		acceptOpts.OriginPatterns = h.cfg.WSAllowedOrigins
	}
	conn, err := websocket.Accept(w, r, acceptOpts)
	if err != nil {
		slog.Error("websocket upgrade failed", "error", err)
		return
	}
	defer func() { _ = conn.CloseNow() }()

	// Limit inbound message size (matches HTTP handler's 1MB limit)
	conn.SetReadLimit(1 << 20)

	// Disable the server's WriteTimeout for this long-lived connection,
	// same pattern as the SSE handler in HandleStream.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	h.runWebSocketRelay(ctx, conn, inst, identity)
}

// runWebSocketRelay reads client messages one at a time and relays each to the
// agent, forwarding response frames back over the WebSocket. This is a
// synchronous (single-goroutine) design: the client cannot send a new message
// until the current agent response completes. This is simpler than the
// two-goroutine design in the design doc and acceptable for a debug console
// where conversations are sequential.
func (h *Handler) runWebSocketRelay(ctx context.Context, wsConn *websocket.Conn, inst *orchestrator.AgentInstance, identity *auth.Identity) {
	for {
		// Apply idle timeout — close connection if no message within window
		readCtx, readCancel := context.WithTimeout(ctx, wsIdleTimeout)
		var msg wsClientMessage
		err := wsjson.Read(readCtx, wsConn, &msg)
		readCancel()
		if err != nil {
			_ = wsConn.Close(websocket.StatusNormalClosure, "")
			return
		}

		if msg.Type != "message" || msg.Content == "" {
			continue
		}

		// Sentinel scan
		if h.sentinel != nil {
			scanResult, scanErr := h.sentinel.Scan(ctx, SentinelInput{
				TenantID: identity.TenantID,
				UserID:   identity.UserID,
				Content:  msg.Content,
			})
			if scanErr != nil {
				_ = wsjson.Write(ctx, wsConn, wsServerMessage{Type: "error", Message: "sentinel scan failed"})
				continue
			}
			if !scanResult.Allowed {
				_ = wsjson.Write(ctx, wsConn, wsServerMessage{Type: "error", Message: "message blocked: " + scanResult.Reason})
				continue
			}
		}

		// Build frame
		requestID := uuid.New().String()
		agentTenantID := ""
		if inst.TenantID != nil {
			agentTenantID = *inst.TenantID
		}

		// Inject persisted user context
		body, _ := json.Marshal(map[string]any{
			"role":    "user",
			"content": msg.Content,
		})
		body = h.injectPersistedUserContext(ctx, body, agentTenantID, inst.ID)

		frame := Frame{
			Type:    TypeMessage,
			ID:      requestID,
			Payload: body,
		}

		// Send to agent
		agentConn, err := h.pool.Get(ctx, inst.ID, *inst.VsockCID)
		if err != nil {
			_ = wsjson.Write(ctx, wsConn, wsServerMessage{Type: "error", RequestID: requestID, Message: "failed to connect to agent"})
			continue
		}

		stream, err := agentConn.SendRequest(ctx, frame)
		if err != nil {
			_ = wsjson.Write(ctx, wsConn, wsServerMessage{Type: "error", RequestID: requestID, Message: "failed to send message"})
			continue
		}

		// Audit log
		if h.audit != nil {
			evt := AuditEvent{
				Action:       "agent.message.ws",
				ResourceType: "agent",
				Source:       "websocket",
			}
			if tid, parseErr := uuid.Parse(agentTenantID); parseErr == nil {
				evt.TenantID = tid
			}
			if uid, parseErr := uuid.Parse(identity.UserID); parseErr == nil {
				evt.UserID = &uid
			}
			if rid, parseErr := uuid.Parse(inst.ID); parseErr == nil {
				evt.ResourceID = &rid
			}
			h.audit.Log(ctx, evt)
		}

		// Read response frames and forward to WS client
		h.relayAgentFrames(ctx, wsConn, stream, requestID)
	}
}

func (h *Handler) relayAgentFrames(ctx context.Context, wsConn *websocket.Conn, stream *RequestStream, requestID string) {
	defer stream.Close()

	for {
		frame, err := stream.Recv(ctx)
		if err != nil {
			_ = wsjson.Write(ctx, wsConn, wsServerMessage{Type: "error", RequestID: requestID, Message: "agent connection error"})
			return
		}

		switch frame.Type {
		case TypeChunk:
			var chunk struct {
				Content string `json:"content"`
				Done    bool   `json:"done"`
			}
			_ = json.Unmarshal(frame.Payload, &chunk)
			_ = wsjson.Write(ctx, wsConn, wsServerMessage{
				Type:      "chunk",
				RequestID: requestID,
				Content:   chunk.Content,
				Done:      chunk.Done,
			})
			if chunk.Done {
				return
			}

		case TypeError:
			var errPayload struct {
				Message string `json:"message"`
			}
			_ = json.Unmarshal(frame.Payload, &errPayload)
			_ = wsjson.Write(ctx, wsConn, wsServerMessage{
				Type:      "error",
				RequestID: requestID,
				Message:   errPayload.Message,
			})
			return

		case TypeToolExecuted:
			var tool struct {
				ToolName string `json:"tool_name"`
			}
			_ = json.Unmarshal(frame.Payload, &tool)
			_ = wsjson.Write(ctx, wsConn, wsServerMessage{
				Type:      "tool_executed",
				RequestID: requestID,
				ToolName:  tool.ToolName,
			})

		case TypeToolFailed:
			var tool struct {
				ToolName string `json:"tool_name"`
				Reason   string `json:"reason"`
			}
			_ = json.Unmarshal(frame.Payload, &tool)
			_ = wsjson.Write(ctx, wsConn, wsServerMessage{
				Type:      "tool_failed",
				RequestID: requestID,
				ToolName:  tool.ToolName,
				Reason:    tool.Reason,
			})

		case TypeToolBlocked:
			var blocked struct {
				ToolName string `json:"tool_name"`
				Reason   string `json:"reason"`
			}
			_ = json.Unmarshal(frame.Payload, &blocked)
			_ = wsjson.Write(ctx, wsConn, wsServerMessage{
				Type:      "tool_blocked",
				RequestID: requestID,
				ToolName:  blocked.ToolName,
				Reason:    blocked.Reason,
			})

		case TypeSessionHalt:
			var halt struct {
				Reason string `json:"reason"`
			}
			_ = json.Unmarshal(frame.Payload, &halt)
			_ = wsjson.Write(ctx, wsConn, wsServerMessage{
				Type:      "session_halt",
				RequestID: requestID,
				Reason:    halt.Reason,
			})
			_ = wsConn.Close(websocket.StatusPolicyViolation, halt.Reason)
			return
		}
	}
}
