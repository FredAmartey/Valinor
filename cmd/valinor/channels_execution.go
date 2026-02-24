package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/audit"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/channels"
	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/proxy"
	"github.com/valinor-ai/valinor/internal/rbac"
	"github.com/valinor-ai/valinor/internal/sentinel"
)

type channelIdentityLookupFunc func(ctx context.Context, userID string) (*auth.Identity, error)
type channelAuthorizeFunc func(ctx context.Context, identity *auth.Identity, action string) (*rbac.Decision, error)
type channelListAgentsFunc func(ctx context.Context, tenantID string) ([]orchestrator.AgentInstance, error)
type channelDispatchFunc func(ctx context.Context, agent orchestrator.AgentInstance, content string) (string, error)
type channelSentinelScanFunc func(ctx context.Context, tenantID, userID, content string) (sentinel.ScanResult, error)

func newChannelExecutor(
	lookupIdentity channelIdentityLookupFunc,
	authorize channelAuthorizeFunc,
	listAgents channelListAgentsFunc,
	dispatch channelDispatchFunc,
	scanSentinel channelSentinelScanFunc,
	auditLogger audit.Logger,
) func(context.Context, channels.ExecutionMessage) channels.ExecutionResult {
	if lookupIdentity == nil || authorize == nil || listAgents == nil || dispatch == nil {
		return nil
	}

	return func(ctx context.Context, msg channels.ExecutionMessage) channels.ExecutionResult {
		content := strings.TrimSpace(msg.Content)
		if content == "" {
			return channels.ExecutionResult{Decision: channels.IngressAccepted}
		}
		if msg.Link.UserID == uuid.Nil {
			logChannelExecutionEvent(ctx, auditLogger, audit.ActionChannelActionDispatchFailed, msg, map[string]any{
				"reason": "linked user is missing",
			})
			return channels.ExecutionResult{Decision: channels.IngressDispatchFailed}
		}
		if msg.Link.TenantID != uuid.Nil && msg.TenantID != "" && msg.Link.TenantID.String() != msg.TenantID {
			logChannelExecutionEvent(ctx, auditLogger, audit.ActionChannelActionDispatchFailed, msg, map[string]any{
				"reason": "tenant mismatch between link and ingress path",
			})
			return channels.ExecutionResult{Decision: channels.IngressDispatchFailed}
		}

		identity, err := lookupIdentity(ctx, msg.Link.UserID.String())
		if err != nil || identity == nil {
			logChannelExecutionEvent(ctx, auditLogger, audit.ActionChannelActionDispatchFailed, msg, map[string]any{
				"reason": "identity lookup failed",
				"error":  safeError(err),
			})
			return channels.ExecutionResult{Decision: channels.IngressDispatchFailed}
		}

		decision, err := authorize(ctx, identity, "channels:messages:write")
		if err != nil || decision == nil {
			logChannelExecutionEvent(ctx, auditLogger, audit.ActionChannelActionDispatchFailed, msg, map[string]any{
				"reason": "authorization failed",
				"error":  safeError(err),
			})
			return channels.ExecutionResult{Decision: channels.IngressDispatchFailed}
		}
		if !decision.Allowed {
			logChannelExecutionEvent(ctx, auditLogger, audit.ActionChannelActionDeniedRBAC, msg, map[string]any{
				"reason": decision.Reason,
			})
			return channels.ExecutionResult{Decision: channels.IngressDeniedRBAC}
		}

		if scanSentinel != nil {
			scanResult, scanErr := scanSentinel(ctx, msg.TenantID, identity.UserID, content)
			if scanErr != nil {
				logChannelExecutionEvent(ctx, auditLogger, audit.ActionChannelActionDispatchFailed, msg, map[string]any{
					"reason": "sentinel scan failed",
					"error":  scanErr.Error(),
				})
				return channels.ExecutionResult{Decision: channels.IngressDispatchFailed}
			}
			if !scanResult.Allowed {
				logChannelExecutionEvent(ctx, auditLogger, audit.ActionChannelActionDeniedSentinel, msg, map[string]any{
					"reason": scanResult.Reason,
					"score":  scanResult.Score,
				})
				return channels.ExecutionResult{Decision: channels.IngressDeniedSentinel}
			}
		}

		agents, err := listAgents(ctx, msg.TenantID)
		if err != nil {
			logChannelExecutionEvent(ctx, auditLogger, audit.ActionChannelActionDispatchFailed, msg, map[string]any{
				"reason": "listing tenant agents failed",
				"error":  err.Error(),
			})
			return channels.ExecutionResult{Decision: channels.IngressDispatchFailed}
		}

		target := selectChannelTargetAgent(agents, identity.Departments)
		if target == nil {
			logChannelExecutionEvent(ctx, auditLogger, audit.ActionChannelActionDeniedNoAgent, msg, map[string]any{
				"reason": "no running agent available",
			})
			return channels.ExecutionResult{Decision: channels.IngressDeniedNoAgent}
		}

		response, dispatchErr := dispatch(ctx, *target, content)
		if dispatchErr != nil {
			logChannelExecutionEvent(ctx, auditLogger, audit.ActionChannelActionDispatchFailed, msg, map[string]any{
				"reason":   "dispatch to agent failed",
				"agent_id": target.ID,
				"error":    dispatchErr.Error(),
			})
			return channels.ExecutionResult{
				Decision: channels.IngressDispatchFailed,
				AgentID:  target.ID,
			}
		}

		logChannelExecutionEvent(ctx, auditLogger, audit.ActionChannelActionExecuted, msg, map[string]any{
			"agent_id":            target.ID,
			"response_char_count": len(response),
		})
		return channels.ExecutionResult{
			Decision:        channels.IngressExecuted,
			AgentID:         target.ID,
			ResponseContent: response,
		}
	}
}

func selectChannelTargetAgent(instances []orchestrator.AgentInstance, preferredDepartments []string) *orchestrator.AgentInstance {
	preferred := make(map[string]struct{}, len(preferredDepartments))
	for _, departmentID := range preferredDepartments {
		dept := strings.TrimSpace(departmentID)
		if dept == "" {
			continue
		}
		preferred[dept] = struct{}{}
	}

	if len(preferred) > 0 {
		for i := range instances {
			inst := &instances[i]
			if !isChannelDispatchCandidate(inst) || inst.DepartmentID == nil {
				continue
			}
			if _, ok := preferred[*inst.DepartmentID]; ok {
				return inst
			}
		}
	}

	for i := range instances {
		inst := &instances[i]
		if !isChannelDispatchCandidate(inst) {
			continue
		}
		if inst.DepartmentID == nil {
			return inst
		}
	}

	return nil
}

func isChannelDispatchCandidate(inst *orchestrator.AgentInstance) bool {
	if inst == nil {
		return false
	}
	return inst.Status == orchestrator.StatusRunning && inst.VsockCID != nil
}

func dispatchChannelMessageToAgent(
	ctx context.Context,
	connPool *proxy.ConnPool,
	agent orchestrator.AgentInstance,
	content string,
	timeout time.Duration,
) (string, error) {
	if connPool == nil {
		return "", errors.New("proxy connection pool is not configured")
	}
	if agent.VsockCID == nil {
		return "", errors.New("agent has no vsock CID")
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	conn, err := connPool.Get(ctx, agent.ID, *agent.VsockCID)
	if err != nil {
		return "", fmt.Errorf("dialing agent connection: %w", err)
	}

	reqBody, err := json.Marshal(map[string]string{
		"content": content,
	})
	if err != nil {
		return "", fmt.Errorf("marshaling message payload: %w", err)
	}

	reqID := uuid.New().String()
	frame := proxy.Frame{
		Type:    proxy.TypeMessage,
		ID:      reqID,
		Payload: reqBody,
	}

	sendCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request, err := conn.SendRequest(sendCtx, frame)
	if err != nil {
		connPool.Remove(agent.ID)
		return "", fmt.Errorf("sending agent message: %w", err)
	}
	defer request.Close()

	contentParts := make([]string, 0)
	for {
		reply, err := request.Recv(sendCtx)
		if err != nil {
			connPool.Remove(agent.ID)
			return "", fmt.Errorf("receiving agent response: %w", err)
		}

		switch reply.Type {
		case proxy.TypeChunk:
			var chunk struct {
				Content string `json:"content"`
				Done    bool   `json:"done"`
			}
			if err := json.Unmarshal(reply.Payload, &chunk); err != nil {
				return "", fmt.Errorf("decoding chunk response: %w", err)
			}
			contentParts = append(contentParts, chunk.Content)
			if chunk.Done {
				return strings.Join(contentParts, ""), nil
			}
		case proxy.TypeError:
			var agentErr struct {
				Message string `json:"message"`
			}
			_ = json.Unmarshal(reply.Payload, &agentErr)
			if strings.TrimSpace(agentErr.Message) == "" {
				agentErr.Message = "unknown agent error"
			}
			return "", fmt.Errorf("agent error: %s", strings.TrimSpace(agentErr.Message))
		case proxy.TypeToolBlocked:
			var blocked struct {
				ToolName string `json:"tool_name"`
				Reason   string `json:"reason"`
			}
			_ = json.Unmarshal(reply.Payload, &blocked)
			if strings.TrimSpace(blocked.ToolName) == "" {
				return "", errors.New("tool blocked")
			}
			return "", fmt.Errorf("tool blocked: %s", blocked.ToolName)
		case proxy.TypeSessionHalt:
			connPool.Remove(agent.ID)
			return "", errors.New("session halted by agent")
		default:
			connPool.Remove(agent.ID)
			return "", fmt.Errorf("unexpected frame type from agent: %s", reply.Type)
		}
	}
}

func logChannelExecutionEvent(
	ctx context.Context,
	logger audit.Logger,
	action string,
	msg channels.ExecutionMessage,
	extra map[string]any,
) {
	if logger == nil {
		return
	}

	metadata := map[string]any{
		audit.MetadataCorrelationID:   msg.CorrelationID,
		audit.MetadataPlatformMessage: msg.PlatformMessageID,
		audit.MetadataPlatformUserID:  msg.PlatformUserID,
	}
	for key, value := range extra {
		metadata[key] = value
	}

	event := audit.Event{
		Action:       action,
		ResourceType: "channel_message",
		Metadata:     metadata,
		Source:       msg.Platform,
	}
	if parsedTenantID, err := uuid.Parse(msg.TenantID); err == nil {
		event.TenantID = parsedTenantID
	}
	if msg.Link.UserID != uuid.Nil {
		userID := msg.Link.UserID
		event.UserID = &userID
	}

	logger.Log(ctx, event)
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
