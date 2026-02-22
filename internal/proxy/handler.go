package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

// AgentLookup provides agent instance lookups for the proxy handler.
type AgentLookup interface {
	GetByID(ctx context.Context, id string) (*orchestrator.AgentInstance, error)
}

// Sentinel scans messages for prompt injection before forwarding.
type Sentinel interface {
	Scan(ctx context.Context, input SentinelInput) (SentinelResult, error)
}

// SentinelInput mirrors sentinel.ScanInput to avoid import cycle.
type SentinelInput struct {
	TenantID string
	UserID   string
	Content  string
}

// SentinelResult mirrors sentinel.ScanResult.
type SentinelResult struct {
	Allowed    bool
	Score      float64
	Reason     string
	Quarantine bool
}

// AuditLogger logs audit events without blocking.
type AuditLogger interface {
	Log(ctx context.Context, event AuditEvent)
}

// AuditEvent mirrors audit.Event to avoid import cycle.
type AuditEvent struct {
	TenantID     uuid.UUID
	UserID       *uuid.UUID
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	Metadata     map[string]any
	Source       string
}

// HandlerConfig holds proxy handler configuration.
type HandlerConfig struct {
	MessageTimeout time.Duration
	ConfigTimeout  time.Duration
	PingTimeout    time.Duration
}

// Handler serves proxy HTTP endpoints for agent communication.
type Handler struct {
	pool     *ConnPool
	agents   AgentLookup
	cfg      HandlerConfig
	sentinel Sentinel
	audit    AuditLogger
}

// NewHandler creates a proxy Handler.
func NewHandler(pool *ConnPool, agents AgentLookup, cfg HandlerConfig, sentinel Sentinel, audit AuditLogger) *Handler {
	if cfg.MessageTimeout <= 0 {
		cfg.MessageTimeout = 60 * time.Second
	}
	if cfg.ConfigTimeout <= 0 {
		cfg.ConfigTimeout = 5 * time.Second
	}
	if cfg.PingTimeout <= 0 {
		cfg.PingTimeout = 3 * time.Second
	}
	return &Handler{pool: pool, agents: agents, cfg: cfg, sentinel: sentinel, audit: audit}
}

// HandleMessage sends a user message to an agent and returns the full response.
// POST /agents/:id/message
func (h *Handler) HandleMessage(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if agentID == "" {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}

	inst, err := h.agents.GetByID(r.Context(), agentID)
	if err != nil {
		if errors.Is(err, orchestrator.ErrVMNotFound) {
			writeProxyJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeProxyJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return
	}

	if !verifyTenantOwnership(w, r, inst) {
		return
	}

	if inst.Status != orchestrator.StatusRunning {
		writeProxyJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent not running"})
		return
	}

	if inst.VsockCID == nil {
		writeProxyJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent has no vsock CID"})
		return
	}

	// Read request body
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB max
	var body json.RawMessage
	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Sentinel scan
	if h.sentinel != nil {
		scanInput := SentinelInput{
			TenantID: middleware.GetTenantID(r.Context()),
			Content:  string(body),
		}
		if identity := auth.GetIdentity(r.Context()); identity != nil {
			scanInput.UserID = identity.UserID
		}
		scanResult, scanErr := h.sentinel.Scan(r.Context(), scanInput)
		if scanErr != nil {
			slog.Error("sentinel scan failed", "error", scanErr)
			// fail-open: continue to agent
		} else if !scanResult.Allowed {
			if h.audit != nil {
				evt := auditFromRequest(r, "message.blocked", "agent")
				agentUUID, _ := uuid.Parse(agentID)
				evt.ResourceID = &agentUUID
				evt.Metadata = map[string]any{"reason": scanResult.Reason, "score": scanResult.Score}
				h.audit.Log(r.Context(), evt)
			}
			writeProxyJSON(w, http.StatusForbidden, map[string]string{
				"error":  "message blocked: potential prompt injection",
				"reason": scanResult.Reason,
			})
			return
		}
	}

	// Get or create connection
	conn, err := h.pool.Get(r.Context(), agentID, *inst.VsockCID)
	if err != nil {
		slog.Error("proxy dial failed", "agent", agentID, "cid", *inst.VsockCID, "error", err)
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "agent unreachable"})
		return
	}

	// Send message frame
	reqID := uuid.New().String()
	frame := Frame{
		Type:    TypeMessage,
		ID:      reqID,
		Payload: body,
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.MessageTimeout)
	defer cancel()

	if err := conn.Send(ctx, frame); err != nil {
		h.pool.Remove(agentID)
		slog.Error("proxy send failed", "agent", agentID, "error", err)
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "send failed"})
		return
	}

	// Audit: message sent
	if h.audit != nil {
		evt := auditFromRequest(r, "message.sent", "agent")
		agentUUID, _ := uuid.Parse(agentID)
		evt.ResourceID = &agentUUID
		h.audit.Log(r.Context(), evt)
	}

	// Collect chunks until done
	var contentParts []string
	for {
		reply, err := conn.Recv(ctx)
		if err != nil {
			h.pool.Remove(agentID)
			slog.Error("proxy recv failed", "agent", agentID, "error", err)
			writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "recv failed"})
			return
		}

		switch reply.Type {
		case TypeChunk:
			var chunk struct {
				Content string `json:"content"`
				Done    bool   `json:"done"`
			}
			if err := json.Unmarshal(reply.Payload, &chunk); err != nil {
				writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "invalid chunk"})
				return
			}
			contentParts = append(contentParts, chunk.Content)
			if chunk.Done {
				writeProxyJSON(w, http.StatusOK, map[string]string{
					"content": strings.Join(contentParts, ""),
				})
				return
			}

		case TypeError:
			var agentErr struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(reply.Payload, &agentErr); err != nil {
				writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "agent error"})
				return
			}
			writeProxyJSON(w, http.StatusBadGateway, map[string]string{
				"error": "agent error: " + agentErr.Message,
			})
			return

		case TypeToolBlocked:
			var blocked struct {
				ToolName string `json:"tool_name"`
				Reason   string `json:"reason"`
			}
			_ = json.Unmarshal(reply.Payload, &blocked)
			if h.audit != nil {
				evt := auditFromRequest(r, "tool.blocked", "agent")
				agentUUID, _ := uuid.Parse(agentID)
				evt.ResourceID = &agentUUID
				evt.Metadata = map[string]any{"tool_name": blocked.ToolName, "reason": blocked.Reason}
				h.audit.Log(r.Context(), evt)
			}
			writeProxyJSON(w, http.StatusForbidden, map[string]string{
				"error": "tool blocked: " + blocked.ToolName,
			})
			return

		case TypeSessionHalt:
			slog.Error("session halted by agent", "agent", agentID, "payload", string(reply.Payload))
			h.pool.Remove(agentID)
			if h.audit != nil {
				evt := auditFromRequest(r, "session.halted", "agent")
				agentUUID, _ := uuid.Parse(agentID)
				evt.ResourceID = &agentUUID
				evt.Metadata = map[string]any{"reason": string(reply.Payload)}
				evt.Source = "system"
				h.audit.Log(r.Context(), evt)
			}
			writeProxyJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "session terminated for security reasons",
			})
			return
		}
	}
}

// HandleStream sends a user message and streams response chunks via SSE.
// POST /agents/:id/stream
func (h *Handler) HandleStream(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if agentID == "" {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}

	inst, err := h.agents.GetByID(r.Context(), agentID)
	if err != nil {
		if errors.Is(err, orchestrator.ErrVMNotFound) {
			writeProxyJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeProxyJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return
	}

	if !verifyTenantOwnership(w, r, inst) {
		return
	}

	if inst.Status != orchestrator.StatusRunning {
		writeProxyJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent not running"})
		return
	}

	if inst.VsockCID == nil {
		writeProxyJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent has no vsock CID"})
		return
	}

	// Read message from POST body
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB max
	var messageBody json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&messageBody); err != nil {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Sentinel scan
	if h.sentinel != nil {
		scanInput := SentinelInput{
			TenantID: middleware.GetTenantID(r.Context()),
			Content:  string(messageBody),
		}
		if identity := auth.GetIdentity(r.Context()); identity != nil {
			scanInput.UserID = identity.UserID
		}
		scanResult, scanErr := h.sentinel.Scan(r.Context(), scanInput)
		if scanErr != nil {
			slog.Error("sentinel scan failed", "error", scanErr)
		} else if !scanResult.Allowed {
			if h.audit != nil {
				evt := auditFromRequest(r, "message.blocked", "agent")
				agentUUID, _ := uuid.Parse(agentID)
				evt.ResourceID = &agentUUID
				evt.Metadata = map[string]any{"reason": scanResult.Reason, "score": scanResult.Score}
				h.audit.Log(r.Context(), evt)
			}
			writeProxyJSON(w, http.StatusForbidden, map[string]string{
				"error":  "message blocked: potential prompt injection",
				"reason": scanResult.Reason,
			})
			return
		}
	}

	conn, err := h.pool.Get(r.Context(), agentID, *inst.VsockCID)
	if err != nil {
		slog.Error("proxy dial failed", "agent", agentID, "error", err)
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "agent unreachable"})
		return
	}

	reqID := uuid.New().String()
	frame := Frame{
		Type:    TypeMessage,
		ID:      reqID,
		Payload: messageBody,
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.MessageTimeout)
	defer cancel()

	if err := conn.Send(ctx, frame); err != nil {
		h.pool.Remove(agentID)
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "send failed"})
		return
	}

	// Audit: message sent (stream)
	if h.audit != nil {
		evt := auditFromRequest(r, "message.sent", "agent")
		agentUUID, _ := uuid.Parse(agentID)
		evt.ResourceID = &agentUUID
		h.audit.Log(r.Context(), evt)
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// Disable server write timeout for this SSE stream only
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	flusher, _ := w.(http.Flusher)

	for {
		reply, err := conn.Recv(ctx)
		if err != nil {
			h.pool.Remove(agentID)
			return
		}

		switch reply.Type {
		case TypeChunk:
			var chunk struct {
				Content string `json:"content"`
				Done    bool   `json:"done"`
			}
			if err := json.Unmarshal(reply.Payload, &chunk); err != nil {
				return
			}

			writeSSE(w, "chunk", reply.Payload)
			if flusher != nil {
				flusher.Flush()
			}

			if chunk.Done {
				writeSSE(w, "done", json.RawMessage(`{}`))
				if flusher != nil {
					flusher.Flush()
				}
				return
			}

		case TypeError:
			writeSSE(w, "error", reply.Payload)
			if flusher != nil {
				flusher.Flush()
			}
			return

		case TypeToolBlocked:
			if h.audit != nil {
				var blocked struct {
					ToolName string `json:"tool_name"`
					Reason   string `json:"reason"`
				}
				_ = json.Unmarshal(reply.Payload, &blocked)
				evt := auditFromRequest(r, "tool.blocked", "agent")
				agentUUID, _ := uuid.Parse(agentID)
				evt.ResourceID = &agentUUID
				evt.Metadata = map[string]any{"tool_name": blocked.ToolName, "reason": blocked.Reason}
				h.audit.Log(r.Context(), evt)
			}
			writeSSE(w, "tool_blocked", reply.Payload)
			if flusher != nil {
				flusher.Flush()
			}
			return

		case TypeSessionHalt:
			slog.Error("session halted by agent", "agent", agentID, "payload", string(reply.Payload))
			h.pool.Remove(agentID)
			if h.audit != nil {
				evt := auditFromRequest(r, "session.halted", "agent")
				agentUUID, _ := uuid.Parse(agentID)
				evt.ResourceID = &agentUUID
				evt.Metadata = map[string]any{"reason": string(reply.Payload)}
				evt.Source = "system"
				h.audit.Log(r.Context(), evt)
			}
			writeSSE(w, "error", json.RawMessage(`{"error":"session terminated for security reasons"}`))
			if flusher != nil {
				flusher.Flush()
			}
			return
		}
	}
}

// HandleContext pushes a context update to a running agent.
// POST /agents/:id/context
func (h *Handler) HandleContext(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if agentID == "" {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}

	inst, err := h.agents.GetByID(r.Context(), agentID)
	if err != nil {
		if errors.Is(err, orchestrator.ErrVMNotFound) {
			writeProxyJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeProxyJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return
	}

	if !verifyTenantOwnership(w, r, inst) {
		return
	}

	if inst.Status != orchestrator.StatusRunning {
		writeProxyJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent not running"})
		return
	}

	if inst.VsockCID == nil {
		writeProxyJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent has no vsock CID"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var body json.RawMessage
	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	conn, err := h.pool.Get(r.Context(), agentID, *inst.VsockCID)
	if err != nil {
		slog.Error("proxy dial failed", "agent", agentID, "error", err)
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "agent unreachable"})
		return
	}

	reqID := uuid.New().String()
	frame := Frame{
		Type:    TypeContextUpdate,
		ID:      reqID,
		Payload: body,
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.ConfigTimeout)
	defer cancel()

	err = conn.Send(ctx, frame)
	if err != nil {
		h.pool.Remove(agentID)
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "send failed"})
		return
	}

	// Wait for matching ack — skip unsolicited frames (e.g. heartbeats)
	for {
		reply, recvErr := conn.Recv(ctx)
		if recvErr != nil {
			h.pool.Remove(agentID)
			writeProxyJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "ack timeout"})
			return
		}

		// Skip frames that don't match our request ID (e.g. heartbeats)
		if reply.ID != reqID {
			continue
		}

		if reply.Type == TypeError {
			writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "agent rejected context update"})
			return
		}

		if reply.Type == TypeConfigAck {
			writeProxyJSON(w, http.StatusOK, map[string]string{"status": "applied"})
			return
		}

		// Unexpected frame type with matching ID
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "unexpected response from agent"})
		return
	}
}

// auditFromRequest builds a base AuditEvent from the request context.
func auditFromRequest(r *http.Request, action, resourceType string) AuditEvent {
	evt := AuditEvent{
		Action:       action,
		ResourceType: resourceType,
		Source:       "api",
	}
	if identity := auth.GetIdentity(r.Context()); identity != nil {
		if tid, err := uuid.Parse(identity.TenantID); err == nil {
			evt.TenantID = tid
		}
		if uid, err := uuid.Parse(identity.UserID); err == nil {
			evt.UserID = &uid
		}
	}
	return evt
}

// verifyTenantOwnership checks that the caller owns the agent. Returns true if OK to proceed.
func verifyTenantOwnership(w http.ResponseWriter, r *http.Request, inst *orchestrator.AgentInstance) bool {
	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		writeProxyJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return false
	}
	if !identity.IsPlatformAdmin {
		tenantID := middleware.GetTenantID(r.Context())
		if inst.TenantID == nil || *inst.TenantID != tenantID {
			writeProxyJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return false
		}
	}
	return true
}

// writeSSE writes an SSE event to the response writer without using fmt.Fprintf.
func writeSSE(w io.Writer, event string, data json.RawMessage) {
	_, _ = io.WriteString(w, "event: "+event+"\ndata: "+string(data)+"\n\n")
}

func writeProxyJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
