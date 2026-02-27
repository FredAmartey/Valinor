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
	"github.com/valinor-ai/valinor/internal/rbac"
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
	pool             *ConnPool
	agents           AgentLookup
	cfg              HandlerConfig
	sentinel         Sentinel
	audit            AuditLogger
	userContextStore UserContextStore
	tokenValidator   TokenValidator
	rbacEval         *rbac.Evaluator
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

// WithUserContextStore wires persistent per-user context snapshots into handler flows.
func (h *Handler) WithUserContextStore(store UserContextStore) *Handler {
	if h == nil {
		return nil
	}
	h.userContextStore = store
	return h
}

// WithTokenValidator wires JWT validation for WebSocket auth.
func (h *Handler) WithTokenValidator(tv TokenValidator) *Handler {
	if h == nil {
		return nil
	}
	h.tokenValidator = tv
	return h
}

// WithRBACEvaluator wires RBAC permission checks for WebSocket auth.
func (h *Handler) WithRBACEvaluator(eval *rbac.Evaluator) *Handler {
	if h == nil {
		return nil
	}
	h.rbacEval = eval
	return h
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

	// Use agent's tenant for audit attribution (correct for cross-tenant admin access)
	agentTenant := ""
	if inst.TenantID != nil {
		agentTenant = *inst.TenantID
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

	// Sentinel scan — extract content field for scanning
	if h.sentinel != nil {
		var msg struct {
			Content string `json:"content"`
		}
		scanContent := string(body)
		if json.Unmarshal(body, &msg) == nil && msg.Content != "" {
			scanContent = msg.Content
		}
		scanInput := SentinelInput{
			TenantID: middleware.GetTenantID(r.Context()),
			Content:  scanContent,
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
				evt := auditFromRequest(r, "message.blocked", "agent", agentTenant)
				if agentUUID, parseErr := uuid.Parse(agentID); parseErr == nil {
					evt.ResourceID = &agentUUID
				}
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

	body = h.injectPersistedUserContext(r.Context(), body, agentTenant, agentID)

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

	request, err := conn.SendRequest(ctx, frame)
	if err != nil {
		h.pool.Remove(agentID)
		slog.Error("proxy send failed", "agent", agentID, "error", err)
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "send failed"})
		return
	}
	defer request.Close()

	// Audit: message sent
	if h.audit != nil {
		evt := auditFromRequest(r, "message.sent", "agent", agentTenant)
		if agentUUID, parseErr := uuid.Parse(agentID); parseErr == nil {
			evt.ResourceID = &agentUUID
		}
		h.audit.Log(r.Context(), evt)
	}

	// Collect chunks until done
	var contentParts []string
	for {
		reply, err := request.Recv(ctx)
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
				evt := auditFromRequest(r, "tool.blocked", "agent", agentTenant)
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
				evt := auditFromRequest(r, "session.halted", "agent", agentTenant)
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

		case TypeToolExecuted:
			h.logToolAudit(r, "tool.executed", agentID, agentTenant, reply.Payload)
			continue

		case TypeToolFailed:
			h.logToolAudit(r, "tool.failed", agentID, agentTenant, reply.Payload)
			continue
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

	agentTenant := ""
	if inst.TenantID != nil {
		agentTenant = *inst.TenantID
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
	if decodeErr := json.NewDecoder(r.Body).Decode(&messageBody); decodeErr != nil {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Sentinel scan — extract content field for scanning
	if h.sentinel != nil {
		var msg struct {
			Content string `json:"content"`
		}
		scanContent := string(messageBody)
		if json.Unmarshal(messageBody, &msg) == nil && msg.Content != "" {
			scanContent = msg.Content
		}
		scanInput := SentinelInput{
			TenantID: middleware.GetTenantID(r.Context()),
			Content:  scanContent,
		}
		if identity := auth.GetIdentity(r.Context()); identity != nil {
			scanInput.UserID = identity.UserID
		}
		scanResult, scanErr := h.sentinel.Scan(r.Context(), scanInput)
		if scanErr != nil {
			slog.Error("sentinel scan failed", "error", scanErr)
		} else if !scanResult.Allowed {
			if h.audit != nil {
				evt := auditFromRequest(r, "message.blocked", "agent", agentTenant)
				if agentUUID, parseErr := uuid.Parse(agentID); parseErr == nil {
					evt.ResourceID = &agentUUID
				}
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

	messageBody = h.injectPersistedUserContext(r.Context(), messageBody, agentTenant, agentID)

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

	request, err := conn.SendRequest(ctx, frame)
	if err != nil {
		h.pool.Remove(agentID)
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "send failed"})
		return
	}
	defer request.Close()

	// Audit: message sent (stream)
	if h.audit != nil {
		evt := auditFromRequest(r, "message.sent", "agent", agentTenant)
		if agentUUID, parseErr := uuid.Parse(agentID); parseErr == nil {
			evt.ResourceID = &agentUUID
		}
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
		reply, err := request.Recv(ctx)
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
				evt := auditFromRequest(r, "tool.blocked", "agent", agentTenant)
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
				evt := auditFromRequest(r, "session.halted", "agent", agentTenant)
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

		case TypeToolExecuted:
			h.logToolAudit(r, "tool.executed", agentID, agentTenant, reply.Payload)
			continue

		case TypeToolFailed:
			h.logToolAudit(r, "tool.failed", agentID, agentTenant, reply.Payload)
			continue
		}
	}
}

// HandleContext persists a context snapshot for the caller and agent.
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

	if h.userContextStore == nil {
		writeProxyJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "context store unavailable"})
		return
	}

	identity := auth.GetIdentity(r.Context())
	if identity == nil || strings.TrimSpace(identity.UserID) == "" {
		writeProxyJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	if inst.TenantID != nil && strings.TrimSpace(*inst.TenantID) != "" {
		tenantID = strings.TrimSpace(*inst.TenantID)
	}
	if tenantID == "" {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var body struct {
		Context string `json:"context"`
	}
	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	contextText := strings.TrimSpace(body.Context)
	if contextText == "" {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "context is required"})
		return
	}

	if err := h.userContextStore.UpsertUserContext(r.Context(), tenantID, agentID, identity.UserID, contextText); err != nil {
		slog.Error("persisting user context failed", "agent", agentID, "tenant", tenantID, "user", identity.UserID, "error", err)
		writeProxyJSON(w, http.StatusInternalServerError, map[string]string{"error": "context update failed"})
		return
	}

	writeProxyJSON(w, http.StatusOK, map[string]string{"status": "applied"})
}

// auditFromRequest builds a base AuditEvent from the request context.
// agentTenantID overrides the event's TenantID when non-empty, ensuring
// audit events are attributed to the agent's tenant (not the admin's).
func auditFromRequest(r *http.Request, action, resourceType, agentTenantID string) AuditEvent {
	evt := AuditEvent{
		Action:       action,
		ResourceType: resourceType,
		Source:       "api",
	}
	if agentTenantID != "" {
		if tid, parseErr := uuid.Parse(agentTenantID); parseErr == nil {
			evt.TenantID = tid
		}
	} else if identity := auth.GetIdentity(r.Context()); identity != nil {
		if tid, parseErr := uuid.Parse(identity.TenantID); parseErr == nil {
			evt.TenantID = tid
		}
	}
	if identity := auth.GetIdentity(r.Context()); identity != nil {
		if uid, parseErr := uuid.Parse(identity.UserID); parseErr == nil {
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

func (h *Handler) injectPersistedUserContext(ctx context.Context, body json.RawMessage, tenantID, agentID string) json.RawMessage {
	if h == nil || h.userContextStore == nil {
		return body
	}
	tenantID = strings.TrimSpace(tenantID)
	agentID = strings.TrimSpace(agentID)
	if tenantID == "" || agentID == "" {
		return body
	}
	identity := auth.GetIdentity(ctx)
	if identity == nil || strings.TrimSpace(identity.UserID) == "" {
		return body
	}

	userContext, err := h.userContextStore.GetUserContext(ctx, tenantID, agentID, identity.UserID)
	if err != nil {
		if !errors.Is(err, ErrUserContextNotFound) {
			slog.Warn("loading persisted user context failed", "agent", agentID, "tenant", tenantID, "user", identity.UserID, "error", err)
		}
		return body
	}
	updatedBody, updateErr := prependSystemContext(body, userContext)
	if updateErr != nil {
		slog.Warn("injecting persisted user context failed", "agent", agentID, "error", updateErr)
		return body
	}
	return updatedBody
}

func prependSystemContext(body json.RawMessage, contextText string) (json.RawMessage, error) {
	contextText = strings.TrimSpace(contextText)
	if contextText == "" {
		return body, nil
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	messages := make([]any, 0, 2)
	messages = append(messages, map[string]any{
		"role":    "system",
		"content": "Persisted user context:\n" + contextText,
	})

	if rawMessages, ok := payload["messages"]; ok {
		existing, ok := rawMessages.([]any)
		if !ok {
			return nil, errors.New("messages must be an array")
		}
		messages = append(messages, existing...)
	} else {
		role, _ := payload["role"].(string)
		content, _ := payload["content"].(string)
		role = strings.TrimSpace(role)
		content = strings.TrimSpace(content)
		if role == "" {
			role = "user"
		}
		if content != "" {
			messages = append(messages, map[string]any{
				"role":    role,
				"content": content,
			})
		}
	}

	payload["messages"] = messages
	updated, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func writeProxyJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// logToolAudit emits an audit event for tool execution (success or failure).
func (h *Handler) logToolAudit(r *http.Request, action, agentID, agentTenant string, payload json.RawMessage) {
	if h.audit == nil {
		return
	}
	var meta map[string]any
	_ = json.Unmarshal(payload, &meta)
	evt := auditFromRequest(r, action, "agent", agentTenant)
	agentUUID, _ := uuid.Parse(agentID)
	evt.ResourceID = &agentUUID
	evt.Metadata = meta
	evt.Source = "agent"
	h.audit.Log(r.Context(), evt)
}
