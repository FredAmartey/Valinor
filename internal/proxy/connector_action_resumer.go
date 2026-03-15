package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/approvals"
	auditlog "github.com/valinor-ai/valinor/internal/audit"
	"github.com/valinor-ai/valinor/internal/connectors"
	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

type ConnectorActionResolver struct {
	pool        *database.Pool
	connPool    *ConnPool
	agents      AgentLookup
	actionStore *connectors.GovernedActionStore
	audit       AuditLogger
}

var errConnectorActionResolverUnavailable = errors.New("connector action resolver unavailable")

func NewConnectorActionResolver(pool *database.Pool, connPool *ConnPool, agents AgentLookup, actionStore *connectors.GovernedActionStore) *ConnectorActionResolver {
	return &ConnectorActionResolver{
		pool:        pool,
		connPool:    connPool,
		agents:      agents,
		actionStore: actionStore,
	}
}

func (r *ConnectorActionResolver) WithAuditLogger(logger AuditLogger) *ConnectorActionResolver {
	if r == nil {
		return nil
	}
	r.audit = logger
	return r
}

func (r *ConnectorActionResolver) ResolveConnectorAction(ctx context.Context, tenantID string, request *approvals.Request, approved bool) error {
	if r == nil || r.pool == nil || r.connPool == nil || r.agents == nil || r.actionStore == nil {
		return errConnectorActionResolverUnavailable
	}
	if request == nil {
		return errors.New("approval request required")
	}

	actionID, ok := extractActionID(request.Metadata)
	if !ok {
		return nil
	}

	var action *connectors.GovernedAction
	err := database.WithTenantConnection(ctx, r.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var err error
		action, err = r.actionStore.GetByID(ctx, q, actionID)
		if err != nil {
			return err
		}
		if approved {
			action, err = r.actionStore.MarkApproved(ctx, q, action.ID)
		} else {
			action, err = r.actionStore.MarkDenied(ctx, q, action.ID)
		}
		return err
	})
	if err != nil || !approved {
		if err == nil && action != nil {
			r.logConnectorAudit(ctx, request, action, auditlog.ActionConnectorWriteDenied)
		}
		return err
	}
	r.logConnectorAudit(ctx, request, action, auditlog.ActionConnectorWriteApproved)

	if action == nil || action.AgentID == nil {
		return errors.New("governed action has no agent context")
	}

	inst, err := r.agents.GetByID(ctx, action.AgentID.String())
	if err != nil {
		r.failConnectorAction(ctx, tenantID, request, action.ID, action)
		return fmt.Errorf("loading agent for governed action: %w", err)
	}
	if inst.Status != orchestrator.StatusRunning || inst.VsockCID == nil {
		r.failConnectorAction(ctx, tenantID, request, action.ID, action)
		return errors.New("agent is not running for governed action")
	}

	conn, err := r.connPool.Get(ctx, inst.ID, *inst.VsockCID)
	if err != nil {
		r.failConnectorAction(ctx, tenantID, request, action.ID, action)
		return fmt.Errorf("connecting to agent for governed action: %w", err)
	}

	payload, err := json.Marshal(ConnectorActionResumePayload{
		ActionID:    action.ID.String(),
		ApprovalID:  request.ID.String(),
		ConnectorID: action.ConnectorID.String(),
		ToolName:    action.ToolName,
		Arguments:   string(action.Arguments),
		RiskClass:   action.RiskClass,
	})
	if err != nil {
		r.failConnectorAction(ctx, tenantID, request, action.ID, action)
		return fmt.Errorf("marshaling connector action resume payload: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	stream, err := conn.SendRequest(reqCtx, Frame{
		Type:    TypeConnectorActionResume,
		ID:      uuid.NewString(),
		Payload: payload,
	})
	if err != nil {
		r.failConnectorAction(ctx, tenantID, request, action.ID, action)
		return fmt.Errorf("sending connector action resume request: %w", err)
	}
	defer stream.Close()

	for {
		reply, err := stream.Recv(reqCtx)
		if err != nil {
			r.failConnectorAction(ctx, tenantID, request, action.ID, action)
			return fmt.Errorf("waiting for connector action resume result: %w", err)
		}

		switch reply.Type {
		case TypeRuntimeEvent:
			continue
		case TypeToolExecuted:
			err := database.WithTenantConnection(ctx, r.pool, tenantID, func(ctx context.Context, q database.Querier) error {
				_, err := r.actionStore.MarkExecuted(ctx, q, action.ID)
				return err
			})
			if err == nil {
				r.logConnectorAudit(ctx, request, action, auditlog.ActionConnectorWriteExecuted)
			}
			return err
		case TypeToolFailed, TypeError:
			r.failConnectorAction(ctx, tenantID, request, action.ID, action)
			return errors.New("approved connector action execution failed")
		}
	}
}

func (r *ConnectorActionResolver) markActionFailed(ctx context.Context, tenantID string, actionID uuid.UUID) {
	if r == nil || r.pool == nil || r.actionStore == nil {
		return
	}
	_ = database.WithTenantConnection(ctx, r.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		_, err := r.actionStore.MarkFailed(ctx, q, actionID)
		return err
	})
}

func (r *ConnectorActionResolver) failConnectorAction(ctx context.Context, tenantID string, request *approvals.Request, actionID uuid.UUID, action *connectors.GovernedAction) {
	r.markActionFailed(ctx, tenantID, actionID)
	r.logConnectorAudit(ctx, request, action, auditlog.ActionConnectorWriteFailed)
}

func extractActionID(metadata map[string]any) (uuid.UUID, bool) {
	if metadata == nil {
		return uuid.Nil, false
	}
	value, ok := metadata["governed_action_id"]
	if !ok {
		return uuid.Nil, false
	}
	id, ok := value.(string)
	if !ok {
		return uuid.Nil, false
	}
	parsed, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, false
	}
	return parsed, true
}

func (r *ConnectorActionResolver) logConnectorAudit(ctx context.Context, request *approvals.Request, action *connectors.GovernedAction, actionName string) {
	if r == nil || r.audit == nil || request == nil || action == nil {
		return
	}

	resourceID := action.ConnectorID
	evt := AuditEvent{
		TenantID:     request.TenantID,
		UserID:       request.ReviewedBy,
		Action:       actionName,
		ResourceType: "connector",
		ResourceID:   &resourceID,
		Source:       "api",
		Metadata: map[string]any{
			"approval_id":        request.ID.String(),
			"governed_action_id": action.ID.String(),
			"connector_id":       action.ConnectorID.String(),
			"tool_name":          action.ToolName,
			"risk_class":         action.RiskClass,
			"target_type":        action.TargetType,
			"target_label":       action.TargetLabel,
			"correlation_id":     action.CorrelationID,
			"session_id":         action.SessionID,
		},
	}
	r.audit.Log(ctx, evt)
}
