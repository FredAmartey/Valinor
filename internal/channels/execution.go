package channels

import "context"

// ExecutionMessage carries the accepted ingress message into execution flow.
type ExecutionMessage struct {
	TenantID          string
	Platform          string
	PlatformUserID    string
	PlatformMessageID string
	CorrelationID     string
	Content           string
	Link              ChannelLink
}

// ExecutionResult captures execution outcome after ingress acceptance.
type ExecutionResult struct {
	Decision IngressDecision
	AgentID  string
}

type executeFunc func(ctx context.Context, msg ExecutionMessage) ExecutionResult

// WithExecutor wires optional post-ingress execution handling.
func (h *Handler) WithExecutor(exec executeFunc) *Handler {
	h.execute = exec
	return h
}
