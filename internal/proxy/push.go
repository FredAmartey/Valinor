package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PushConfig sends a config_update frame to a running agent and waits for ack.
func PushConfig(ctx context.Context, pool *ConnPool, agentID string, cid uint32, config map[string]any, toolAllowlist []string, timeout time.Duration) error {
	conn, err := pool.Get(ctx, agentID, cid)
	if err != nil {
		return fmt.Errorf("connecting to agent %s: %w", agentID, err)
	}

	payload := struct {
		Config        map[string]any `json:"config"`
		ToolAllowlist []string       `json:"tool_allowlist"`
	}{
		Config:        config,
		ToolAllowlist: toolAllowlist,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling config payload: %w", err)
	}

	frame := Frame{
		Type:    TypeConfigUpdate,
		ID:      uuid.New().String(),
		Payload: json.RawMessage(payloadJSON),
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := conn.Send(ctx, frame); err != nil {
		pool.Remove(agentID)
		return fmt.Errorf("sending config to agent %s: %w", agentID, err)
	}

	// Wait for ack
	reply, err := conn.Recv(ctx)
	if err != nil {
		pool.Remove(agentID)
		return fmt.Errorf("waiting for config ack from agent %s: %w", agentID, err)
	}

	if reply.Type == TypeError {
		return fmt.Errorf("agent %s rejected config update: %s", agentID, string(reply.Payload))
	}

	return nil
}
