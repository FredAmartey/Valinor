package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/valinor-ai/valinor/internal/proxy"
)

// AgentConfig holds in-guest agent configuration.
type AgentConfig struct {
	Transport   string
	Port        uint32
	OpenClawURL string
}

// Agent is the in-guest valinor-agent that bridges the control plane to OpenClaw.
type Agent struct {
	cfg           AgentConfig
	httpClient    *http.Client
	toolAllowlist []string
	toolPolicies  map[string]ToolPolicy
	canaryTokens  []string
	mu            sync.RWMutex // protects toolAllowlist, toolPolicies, canaryTokens, config
	config        map[string]any
}

// NewAgent creates a new Agent.
func NewAgent(cfg AgentConfig) *Agent {
	return &Agent{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Run starts the agent: listens for control plane connections.
func (a *Agent) Run(ctx context.Context) error {
	var transport proxy.Transport
	switch a.cfg.Transport {
	case "tcp":
		transport = proxy.NewTCPTransport(0) // port is the full port for TCP agent mode
	default:
		// vsock transport would be used in production (Linux only)
		// For now, default to TCP for development
		transport = proxy.NewTCPTransport(0)
	}

	ln, err := transport.Listen(ctx, a.cfg.Port)
	if err != nil {
		return fmt.Errorf("listening on port %d: %w", a.cfg.Port, err)
	}
	defer ln.Close()

	slog.Info("agent listening", "port", a.cfg.Port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // graceful shutdown
			}
			slog.Error("accept failed", "error", err)
			continue
		}

		go a.handleConnection(ctx, conn)
	}
}

// handleConnection processes frames from a single control plane connection.
func (a *Agent) handleConnection(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	conn := proxy.NewAgentConn(raw)

	// Send initial heartbeat
	hb := proxy.Frame{
		Type:    proxy.TypeHeartbeat,
		ID:      "",
		Payload: json.RawMessage(`{"status":"ready","uptime_secs":0}`),
	}
	if err := conn.Send(ctx, hb); err != nil {
		slog.Error("initial heartbeat failed", "error", err)
		return
	}

	// Start heartbeat goroutine
	heartbeatCtx, heartbeatCancel := context.WithCancel(ctx)
	defer heartbeatCancel()
	go a.heartbeatLoop(heartbeatCtx, conn)

	// Main frame dispatch loop
	for {
		if ctx.Err() != nil {
			return
		}

		frame, err := conn.Recv(ctx)
		if err != nil {
			slog.Info("connection closed", "error", err)
			return
		}

		switch frame.Type {
		case proxy.TypeConfigUpdate:
			a.handleConfigUpdate(ctx, conn, frame)
		case proxy.TypeMessage:
			go a.handleMessage(ctx, conn, frame)
		case proxy.TypeContextUpdate:
			a.handleContextUpdate(ctx, conn, frame)
		case proxy.TypePing:
			pong := proxy.Frame{
				Type:    proxy.TypePong,
				ID:      frame.ID,
				Payload: json.RawMessage(`{}`),
			}
			if err := conn.Send(ctx, pong); err != nil {
				slog.Error("pong send failed", "error", err)
				return
			}
		default:
			slog.Warn("unknown frame type", "type", frame.Type)
		}
	}
}

func (a *Agent) handleConfigUpdate(ctx context.Context, conn *proxy.AgentConn, frame proxy.Frame) {
	var payload struct {
		Config        map[string]any        `json:"config"`
		ToolAllowlist []string              `json:"tool_allowlist"`
		ToolPolicies  map[string]ToolPolicy `json:"tool_policies"`
		CanaryTokens  []string              `json:"canary_tokens"`
	}
	if err := json.Unmarshal(frame.Payload, &payload); err != nil {
		slog.Error("invalid config payload", "error", err)
		errFrame := proxy.Frame{
			Type:    proxy.TypeError,
			ID:      frame.ID,
			Payload: json.RawMessage(`{"code":"invalid_payload","message":"invalid config payload"}`),
		}
		_ = conn.Send(ctx, errFrame)
		return
	}

	a.mu.Lock()
	a.config = payload.Config
	a.toolAllowlist = payload.ToolAllowlist
	a.toolPolicies = payload.ToolPolicies
	a.canaryTokens = payload.CanaryTokens
	a.mu.Unlock()

	slog.Info("config updated", "tools", len(payload.ToolAllowlist))

	ack := proxy.Frame{
		Type:    proxy.TypeConfigAck,
		ID:      frame.ID,
		Payload: json.RawMessage(`{"applied":true}`),
	}
	if err := conn.Send(ctx, ack); err != nil {
		slog.Error("config ack failed", "error", err)
	}
}

func (a *Agent) handleMessage(ctx context.Context, conn *proxy.AgentConn, frame proxy.Frame) {
	a.forwardToOpenClaw(ctx, conn, frame)
}

func (a *Agent) handleContextUpdate(ctx context.Context, conn *proxy.AgentConn, frame proxy.Frame) {
	// TODO: Forward context to OpenClaw memory
	slog.Info("context update received")

	ack := proxy.Frame{
		Type:    proxy.TypeConfigAck,
		ID:      frame.ID,
		Payload: json.RawMessage(`{"applied":true}`),
	}
	if err := conn.Send(ctx, ack); err != nil {
		slog.Error("context ack failed", "error", err)
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context, conn *proxy.AgentConn) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			uptime := int(time.Since(startTime).Seconds())
			payload := fmt.Sprintf(`{"status":"running","uptime_secs":%d}`, uptime)
			hb := proxy.Frame{
				Type:    proxy.TypeHeartbeat,
				ID:      "",
				Payload: json.RawMessage(payload),
			}
			if err := conn.Send(ctx, hb); err != nil {
				slog.Error("heartbeat failed", "error", err)
				return
			}
		}
	}
}

// isToolAllowed checks if a tool is in the allow-list.
func (a *Agent) isToolAllowed(toolName string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.toolAllowlist) == 0 {
		return true // empty list = all allowed
	}
	return slices.Contains(a.toolAllowlist, toolName)
}
