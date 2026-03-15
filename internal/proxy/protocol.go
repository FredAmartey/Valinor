package proxy

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// Frame type constants — Control Plane → Agent
const (
	TypeConfigUpdate          = "config_update"
	TypeMessage               = "message"
	TypePing                  = "ping"
	TypeConnectorActionResume = "connector_action_resume"
)

// Frame type constants — Agent → Control Plane
const (
	TypeHeartbeat        = "heartbeat"
	TypeChunk            = "chunk"
	TypeRuntimeEvent     = "runtime_event"
	TypeApprovalRequired = "approval_required"
	TypeConfigAck        = "config_ack"
	TypeToolBlocked      = "tool_blocked"
	TypeSessionHalt      = "session_halt"
	TypePong             = "pong"
	TypeError            = "error"
	TypeToolExecuted     = "tool_executed"
	TypeToolFailed       = "tool_failed"
)

// Frame is the envelope for all vsock wire messages.
type Frame struct {
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	Payload json.RawMessage `json:"payload"`
}

// RuntimeEventPayload carries normalized lifecycle signals from a guest runtime
// back to the control plane without coupling the wire protocol to every
// OpenClaw internal event shape.
type RuntimeEventPayload struct {
	EventType      string         `json:"event_type"`
	Kind           string         `json:"kind,omitempty"`
	Title          string         `json:"title,omitempty"`
	Summary        string         `json:"summary,omitempty"`
	Status         string         `json:"status,omitempty"`
	RiskClass      string         `json:"risk_class,omitempty"`
	Binding        string         `json:"binding,omitempty"`
	DeliveryTarget string         `json:"delivery_target,omitempty"`
	RuntimeSource  string         `json:"runtime_source,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type ApprovalRequiredPayload struct {
	ConnectorID             string `json:"connector_id,omitempty"`
	ConnectorName           string `json:"connector_name,omitempty"`
	ToolName                string `json:"tool_name"`
	Arguments               string `json:"arguments,omitempty"`
	RiskClass               string `json:"risk_class,omitempty"`
	TargetType              string `json:"target_type,omitempty"`
	TargetLabelTemplate     string `json:"target_label_template,omitempty"`
	ApprovalSummaryTemplate string `json:"approval_summary_template,omitempty"`
}

type ConnectorActionResumePayload struct {
	ActionID    string `json:"action_id"`
	ApprovalID  string `json:"approval_id,omitempty"`
	ConnectorID string `json:"connector_id,omitempty"`
	ToolName    string `json:"tool_name"`
	Arguments   string `json:"arguments,omitempty"`
	RiskClass   string `json:"risk_class,omitempty"`
}

// MaxFrameSize limits frame payloads to 4 MB.
const MaxFrameSize = 4 << 20

// EncodeFrame serializes a Frame into length-prefixed wire format:
// [4 bytes: big-endian uint32 payload length] [N bytes: JSON payload]
func EncodeFrame(f Frame) ([]byte, error) {
	payload, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("marshaling frame: %w", err)
	}

	if len(payload) > MaxFrameSize {
		return nil, fmt.Errorf("frame payload %d bytes exceeds max %d", len(payload), MaxFrameSize)
	}

	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(payload))) // #nosec G115 -- bounds checked: len(payload) <= MaxFrameSize (4MB)
	copy(buf[4:], payload)
	return buf, nil
}

// DecodeFrame reads a length-prefixed frame from data.
// Returns the frame, total bytes consumed, and any error.
func DecodeFrame(data []byte) (Frame, int, error) {
	if len(data) < 4 {
		return Frame{}, 0, errors.New("insufficient data for frame header")
	}

	payloadLen := binary.BigEndian.Uint32(data[:4])
	if payloadLen > MaxFrameSize {
		return Frame{}, 0, fmt.Errorf("frame payload %d bytes exceeds max %d", payloadLen, MaxFrameSize)
	}

	total := 4 + int(payloadLen)
	if len(data) < total {
		return Frame{}, 0, errors.New("insufficient data for frame payload")
	}

	var f Frame
	if err := json.Unmarshal(data[4:total], &f); err != nil {
		return Frame{}, 0, fmt.Errorf("unmarshaling frame: %w", err)
	}

	return f, total, nil
}
