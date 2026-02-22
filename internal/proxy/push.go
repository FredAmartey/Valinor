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

	err = conn.Send(ctx, frame)
	if err != nil {
		pool.Remove(agentID)
		return fmt.Errorf("sending config to agent %s: %w", agentID, err)
	}

	// Wait for matching ack — skip unsolicited frames (e.g. heartbeats)
	for {
		reply, recvErr := conn.Recv(ctx)
		if recvErr != nil {
			pool.Remove(agentID)
			return fmt.Errorf("waiting for config ack from agent %s: %w", agentID, recvErr)
		}

		// Skip frames that don't match our request ID (e.g. heartbeats)
		if reply.ID != frame.ID {
			continue
		}

		if reply.Type == TypeError {
			return fmt.Errorf("agent %s rejected config update: %s", agentID, string(reply.Payload))
		}

		if reply.Type == TypeConfigAck {
			return nil
		}

		return fmt.Errorf("agent %s sent unexpected response type %q", agentID, reply.Type)
	}
}
