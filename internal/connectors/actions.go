package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/FredAmartey/heimdall/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	GovernedActionStatusPending          = "pending"
	GovernedActionStatusAwaitingApproval = "awaiting_approval"
	GovernedActionStatusApproved         = "approved"
	GovernedActionStatusDenied           = "denied"
	GovernedActionStatusExecuted         = "executed"
	GovernedActionStatusFailed           = "failed"
)

var (
	ErrGovernedActionNotFound          = errors.New("governed connector action not found")
	ErrGovernedActionInvalidTransition = errors.New("invalid governed connector action transition")
)

type GovernedAction struct {
	ID                uuid.UUID       `json:"id"`
	TenantID          uuid.UUID       `json:"tenant_id"`
	AgentID           *uuid.UUID      `json:"agent_id,omitempty"`
	ApprovalRequestID *uuid.UUID      `json:"approval_request_id,omitempty"`
	ConnectorID       uuid.UUID       `json:"connector_id"`
	SessionID         string          `json:"session_id,omitempty"`
	CorrelationID     string          `json:"correlation_id,omitempty"`
	ToolName          string          `json:"tool_name"`
	RiskClass         string          `json:"risk_class"`
	TargetType        string          `json:"target_type"`
	TargetLabel       string          `json:"target_label"`
	ActionSummary     string          `json:"action_summary"`
	Arguments         json.RawMessage `json:"arguments"`
	Status            string          `json:"status"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

type CreateGovernedActionParams struct {
	TenantID      uuid.UUID
	AgentID       *uuid.UUID
	ConnectorID   uuid.UUID
	SessionID     string
	CorrelationID string
	ToolName      string
	RiskClass     string
	TargetType    string
	TargetLabel   string
	ActionSummary string
	Arguments     json.RawMessage
	Status        string
}

type GovernedActionStore struct{}

func NewGovernedActionStore() *GovernedActionStore {
	return &GovernedActionStore{}
}

func (s *GovernedActionStore) Create(ctx context.Context, q database.Querier, params CreateGovernedActionParams) (*GovernedAction, error) {
	if len(params.Arguments) == 0 {
		params.Arguments = json.RawMessage(`{}`)
	}
	if params.Status == "" {
		params.Status = GovernedActionStatusPending
	}

	action, err := scanGovernedAction(func(dest ...any) error {
		return q.QueryRow(ctx,
			`INSERT INTO governed_connector_actions (
				tenant_id, agent_id, connector_id, session_id, correlation_id, tool_name,
				risk_class, target_type, target_label, action_summary, arguments, status
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			RETURNING id, tenant_id, agent_id, approval_request_id, connector_id, session_id,
			          correlation_id, tool_name, risk_class, target_type, target_label,
			          action_summary, arguments, status, created_at, updated_at`,
			params.TenantID,
			params.AgentID,
			params.ConnectorID,
			params.SessionID,
			params.CorrelationID,
			params.ToolName,
			params.RiskClass,
			params.TargetType,
			params.TargetLabel,
			params.ActionSummary,
			params.Arguments,
			params.Status,
		).Scan(dest...)
	})
	if err != nil {
		return nil, fmt.Errorf("creating governed connector action: %w", err)
	}
	return action, nil
}

func (s *GovernedActionStore) GetByID(ctx context.Context, q database.Querier, id uuid.UUID) (*GovernedAction, error) {
	action, err := scanGovernedActionRow(q.QueryRow(ctx,
		`SELECT id, tenant_id, agent_id, approval_request_id, connector_id, session_id,
		        correlation_id, tool_name, risk_class, target_type, target_label,
		        action_summary, arguments, status, created_at, updated_at
		   FROM governed_connector_actions
		  WHERE id = $1
		    AND tenant_id = current_setting('app.current_tenant_id', true)::UUID`,
		id,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrGovernedActionNotFound
		}
		return nil, fmt.Errorf("getting governed connector action: %w", err)
	}
	return action, nil
}

func (s *GovernedActionStore) MarkAwaitingApproval(ctx context.Context, q database.Querier, id, approvalID uuid.UUID) (*GovernedAction, error) {
	return s.updateStatus(ctx, q, id, approvalID, GovernedActionStatusAwaitingApproval, map[string]struct{}{
		GovernedActionStatusPending: {},
	})
}

func (s *GovernedActionStore) MarkApproved(ctx context.Context, q database.Querier, id uuid.UUID) (*GovernedAction, error) {
	return s.updateStatus(ctx, q, id, uuid.Nil, GovernedActionStatusApproved, map[string]struct{}{
		GovernedActionStatusAwaitingApproval: {},
		GovernedActionStatusPending:          {},
	})
}

func (s *GovernedActionStore) MarkDenied(ctx context.Context, q database.Querier, id uuid.UUID) (*GovernedAction, error) {
	return s.updateStatus(ctx, q, id, uuid.Nil, GovernedActionStatusDenied, map[string]struct{}{
		GovernedActionStatusAwaitingApproval: {},
		GovernedActionStatusPending:          {},
	})
}

func (s *GovernedActionStore) MarkExecuted(ctx context.Context, q database.Querier, id uuid.UUID) (*GovernedAction, error) {
	return s.updateStatus(ctx, q, id, uuid.Nil, GovernedActionStatusExecuted, map[string]struct{}{
		GovernedActionStatusApproved: {},
		GovernedActionStatusPending:  {},
	})
}

func (s *GovernedActionStore) MarkFailed(ctx context.Context, q database.Querier, id uuid.UUID) (*GovernedAction, error) {
	return s.updateStatus(ctx, q, id, uuid.Nil, GovernedActionStatusFailed, map[string]struct{}{
		GovernedActionStatusPending:          {},
		GovernedActionStatusAwaitingApproval: {},
		GovernedActionStatusApproved:         {},
	})
}

func (s *GovernedActionStore) updateStatus(
	ctx context.Context,
	q database.Querier,
	id uuid.UUID,
	approvalID uuid.UUID,
	nextStatus string,
	allowed map[string]struct{},
) (*GovernedAction, error) {
	var approvalRef any
	if approvalID != uuid.Nil {
		approvalRef = approvalID
	}

	allowedStatuses := make([]string, 0, len(allowed))
	for status := range allowed {
		allowedStatuses = append(allowedStatuses, status)
	}

	action, err := scanGovernedActionRow(q.QueryRow(ctx,
		`UPDATE governed_connector_actions
		    SET status = $2,
		        approval_request_id = COALESCE($3, approval_request_id),
		        updated_at = now()
		  WHERE id = $1
		    AND tenant_id = current_setting('app.current_tenant_id', true)::UUID
		    AND status = ANY($4)
		  RETURNING id, tenant_id, agent_id, approval_request_id, connector_id, session_id,
		            correlation_id, tool_name, risk_class, target_type, target_label,
		            action_summary, arguments, status, created_at, updated_at`,
		id,
		nextStatus,
		approvalRef,
		allowedStatuses,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if _, getErr := s.GetByID(ctx, q, id); getErr != nil {
				return nil, getErr
			}
			return nil, ErrGovernedActionInvalidTransition
		}
		return nil, fmt.Errorf("updating governed connector action: %w", err)
	}
	return action, nil
}

func scanGovernedAction(scan func(dest ...any) error) (*GovernedAction, error) {
	var action GovernedAction
	if err := scan(
		&action.ID,
		&action.TenantID,
		&action.AgentID,
		&action.ApprovalRequestID,
		&action.ConnectorID,
		&action.SessionID,
		&action.CorrelationID,
		&action.ToolName,
		&action.RiskClass,
		&action.TargetType,
		&action.TargetLabel,
		&action.ActionSummary,
		&action.Arguments,
		&action.Status,
		&action.CreatedAt,
		&action.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &action, nil
}

func scanGovernedActionRow(row pgx.Row) (*GovernedAction, error) {
	return scanGovernedAction(row.Scan)
}
