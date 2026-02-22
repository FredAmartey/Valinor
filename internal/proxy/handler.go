package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/orchestrator"
)

// AgentLookup provides agent instance lookups for the proxy handler.
type AgentLookup interface {
	GetByID(ctx context.Context, id string) (*orchestrator.AgentInstance, error)
}

// HandlerConfig holds proxy handler configuration.
type HandlerConfig struct {
	MessageTimeout time.Duration
	ConfigTimeout  time.Duration
	PingTimeout    time.Duration
}

// Handler serves proxy HTTP endpoints for agent communication.
type Handler struct {
	pool   *ConnPool
	agents AgentLookup
	cfg    HandlerConfig
}

// NewHandler creates a proxy Handler.
func NewHandler(pool *ConnPool, agents AgentLookup, cfg HandlerConfig) *Handler {
	if cfg.MessageTimeout <= 0 {
		cfg.MessageTimeout = 60 * time.Second
	}
	if cfg.ConfigTimeout <= 0 {
		cfg.ConfigTimeout = 5 * time.Second
	}
	if cfg.PingTimeout <= 0 {
		cfg.PingTimeout = 3 * time.Second
	}
	return &Handler{pool: pool, agents: agents, cfg: cfg}
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
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
				"error": fmt.Sprintf("agent error: %s", agentErr.Message),
			})
			return

		case TypeToolBlocked:
			var blocked struct {
				ToolName string `json:"tool_name"`
				Reason   string `json:"reason"`
			}
			_ = json.Unmarshal(reply.Payload, &blocked)
			writeProxyJSON(w, http.StatusForbidden, map[string]string{
				"error": fmt.Sprintf("tool blocked: %s", blocked.ToolName),
			})
			return
		}
	}
}

// HandleStream sends a user message and streams response chunks via SSE.
// GET /agents/:id/stream?message={json}
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

	if inst.Status != orchestrator.StatusRunning {
		writeProxyJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent not running"})
		return
	}

	if inst.VsockCID == nil {
		writeProxyJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent has no vsock CID"})
		return
	}

	// Read message from query param
	messageJSON := r.URL.Query().Get("message")
	if messageJSON == "" {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "message query param required"})
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
		Type:    TypeMessage,
		ID:      reqID,
		Payload: json.RawMessage(messageJSON),
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.MessageTimeout)
	defer cancel()

	if err := conn.Send(ctx, frame); err != nil {
		h.pool.Remove(agentID)
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "send failed"})
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

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

			fmt.Fprintf(w, "event: chunk\ndata: %s\n\n", string(reply.Payload))
			if flusher != nil {
				flusher.Flush()
			}

			if chunk.Done {
				fmt.Fprintf(w, "event: done\ndata: {}\n\n")
				if flusher != nil {
					flusher.Flush()
				}
				return
			}

		case TypeError:
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", string(reply.Payload))
			if flusher != nil {
				flusher.Flush()
			}
			return

		case TypeToolBlocked:
			fmt.Fprintf(w, "event: tool_blocked\ndata: %s\n\n", string(reply.Payload))
			if flusher != nil {
				flusher.Flush()
			}
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
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

	if err := conn.Send(ctx, frame); err != nil {
		h.pool.Remove(agentID)
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "send failed"})
		return
	}

	// Wait for ack
	reply, err := conn.Recv(ctx)
	if err != nil {
		h.pool.Remove(agentID)
		writeProxyJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "ack timeout"})
		return
	}

	if reply.Type == TypeError {
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "agent rejected context update"})
		return
	}

	writeProxyJSON(w, http.StatusOK, map[string]string{"status": "applied"})
}

func writeProxyJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
