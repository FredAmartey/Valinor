package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

const (
	StatusPending   = "pending"
	StatusApproved  = "approved"
	StatusDenied    = "denied"
	StatusExpired   = "expired"
	StatusCancelled = "cancelled" //nolint:misspell // Stored/API status spelling is already established.
)

var (
	ErrApprovalNotFound   = errors.New("approval request not found")
	ErrApprovalNotPending = errors.New("approval request is not pending")
	ErrApprovalSelfReview = errors.New("approval requester cannot review their own approval")
)

type Request struct {
	ID              uuid.UUID      `json:"id"`
	TenantID        uuid.UUID      `json:"tenant_id"`
	AgentID         *uuid.UUID     `json:"agent_id,omitempty"`
	RequestedBy     *uuid.UUID     `json:"requested_by,omitempty"`
	ReviewedBy      *uuid.UUID     `json:"reviewed_by,omitempty"`
	ChannelOutboxID *uuid.UUID     `json:"channel_outbox_id,omitempty"`
	RiskClass       string         `json:"risk_class"`
	Status          string         `json:"status"`
	TargetType      string         `json:"target_type"`
	TargetLabel     string         `json:"target_label"`
	ActionSummary   string         `json:"action_summary"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	ReviewedAt      *time.Time     `json:"reviewed_at,omitempty"`
	ExpiresAt       *time.Time     `json:"expires_at,omitempty"`
}

type CreateParams struct {
	TenantID        uuid.UUID
	AgentID         *uuid.UUID
	RequestedBy     *uuid.UUID
	ChannelOutboxID *uuid.UUID
	RiskClass       string
	TargetType      string
	TargetLabel     string
	ActionSummary   string
	Metadata        map[string]any
	ExpiresAt       *time.Time
}

type ListParams struct {
	TenantID uuid.UUID
	Status   *string
	Limit    int
}

type Store struct{}

func NewStore() *Store {
	return &Store{}
}

func (s *Store) Create(ctx context.Context, q database.Querier, params CreateParams) (*Request, error) {
	var metadataJSON []byte
	if params.Metadata != nil {
		var err error
		metadataJSON, err = json.Marshal(params.Metadata)
		if err != nil {
			return nil, fmt.Errorf("marshaling metadata: %w", err)
		}
	}

	request, err := scanRequest(func(dest ...any) error {
		return q.QueryRow(ctx,
			`INSERT INTO approval_requests (
		        tenant_id, agent_id, requested_by, channel_outbox_id, risk_class,
		        status, target_type, target_label, action_summary, metadata, expires_at
		 )
		 VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7, $8, $9, $10)
		 RETURNING id, tenant_id, agent_id, requested_by, reviewed_by, channel_outbox_id, risk_class,
		           status, target_type, target_label, action_summary, metadata, created_at, reviewed_at, expires_at`,
			params.TenantID,
			params.AgentID,
			params.RequestedBy,
			params.ChannelOutboxID,
			params.RiskClass,
			params.TargetType,
			params.TargetLabel,
			params.ActionSummary,
			metadataJSON,
			params.ExpiresAt,
		).Scan(dest...)
	})
	if err != nil {
		return nil, fmt.Errorf("creating approval request: %w", err)
	}
	return request, nil
}

func (s *Store) List(ctx context.Context, q database.Querier, params ListParams) ([]Request, error) {
	sql := `SELECT id, tenant_id, agent_id, requested_by, reviewed_by, channel_outbox_id, risk_class,
	               status, target_type, target_label, action_summary, metadata, created_at, reviewed_at, expires_at
	          FROM approval_requests
	         WHERE tenant_id = $1`
	args := []any{params.TenantID}
	if params.Status != nil {
		sql += ` AND status = $2`
		args = append(args, *params.Status)
		sql += ` ORDER BY created_at DESC LIMIT $3`
		args = append(args, params.Limit)
	} else {
		sql += ` ORDER BY created_at DESC LIMIT $2`
		args = append(args, params.Limit)
	}

	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("listing approval requests: %w", err)
	}
	defer rows.Close()

	var requests []Request
	for rows.Next() {
		request, err := scanRequest(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scanning approval request: %w", err)
		}
		requests = append(requests, *request)
	}
	return requests, rows.Err()
}

func (s *Store) Approve(ctx context.Context, q database.Querier, approvalID, reviewerID, tenantID uuid.UUID) (*Request, error) {
	return s.resolve(ctx, q, approvalID, reviewerID, tenantID, StatusApproved)
}

func (s *Store) Deny(ctx context.Context, q database.Querier, approvalID, reviewerID, tenantID uuid.UUID) (*Request, error) {
	return s.resolve(ctx, q, approvalID, reviewerID, tenantID, StatusDenied)
}

func (s *Store) resolve(ctx context.Context, q database.Querier, approvalID, reviewerID, tenantID uuid.UUID, status string) (*Request, error) {
	existing, err := s.getForResolve(ctx, q, approvalID, tenantID)
	if err != nil {
		return nil, err
	}
	if existing.RequestedBy != nil && *existing.RequestedBy == reviewerID {
		return nil, ErrApprovalSelfReview
	}
	if existing.Status != StatusPending {
		return nil, ErrApprovalNotPending
	}

	request, err := scanRequestRow(q.QueryRow(ctx,
		`UPDATE approval_requests
		    SET status = $2, reviewed_by = $3, reviewed_at = now()
		  WHERE id = $1
		    AND status = 'pending'
		    AND tenant_id = $4
		    AND (requested_by IS NULL OR requested_by <> $3)
		  RETURNING id, tenant_id, agent_id, requested_by, reviewed_by, channel_outbox_id, risk_class,
		            status, target_type, target_label, action_summary, metadata, created_at, reviewed_at, expires_at`,
		approvalID,
		status,
		reviewerID,
		tenantID,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrApprovalNotPending
		}
		return nil, fmt.Errorf("resolving approval request: %w", err)
	}
	if request.ChannelOutboxID != nil {
		if status == StatusApproved {
			_, err = q.Exec(ctx,
				`UPDATE channel_outbox
				    SET status = 'pending', next_attempt_at = now(), last_error = NULL, locked_at = NULL, updated_at = now()
				  WHERE id = $1 AND status = 'pending_approval'`,
				*request.ChannelOutboxID,
			)
		} else {
			_, err = q.Exec(ctx,
				`UPDATE channel_outbox
				    SET status = 'dead', last_error = 'approval denied', locked_at = NULL, updated_at = now()
				  WHERE id = $1 AND status = 'pending_approval'`,
				*request.ChannelOutboxID,
			)
		}
		if err != nil {
			return nil, fmt.Errorf("updating linked outbox status: %w", err)
		}
	}
	return request, nil
}

func (s *Store) getForResolve(ctx context.Context, q database.Querier, approvalID, tenantID uuid.UUID) (*Request, error) {
	request, err := scanRequestRow(q.QueryRow(ctx,
		`SELECT id, tenant_id, agent_id, requested_by, reviewed_by, channel_outbox_id, risk_class,
		        status, target_type, target_label, action_summary, metadata, created_at, reviewed_at, expires_at
		   FROM approval_requests
		  WHERE id = $1
		    AND tenant_id = $2`,
		approvalID,
		tenantID,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrApprovalNotFound
		}
		return nil, fmt.Errorf("loading approval request: %w", err)
	}
	return request, nil
}

func scanRequest(scan func(dest ...any) error) (*Request, error) {
	var (
		request      Request
		metadataJSON json.RawMessage
	)
	if err := scan(
		&request.ID,
		&request.TenantID,
		&request.AgentID,
		&request.RequestedBy,
		&request.ReviewedBy,
		&request.ChannelOutboxID,
		&request.RiskClass,
		&request.Status,
		&request.TargetType,
		&request.TargetLabel,
		&request.ActionSummary,
		&metadataJSON,
		&request.CreatedAt,
		&request.ReviewedAt,
		&request.ExpiresAt,
	); err != nil {
		return nil, err
	}
	if err := decodeRequestMetadata(metadataJSON, &request.Metadata); err != nil {
		return nil, err
	}
	return &request, nil
}

func scanRequestRow(row pgx.Row) (*Request, error) {
	return scanRequest(row.Scan)
}

func decodeRequestMetadata(metadataJSON json.RawMessage, dest *map[string]any) error {
	if len(metadataJSON) == 0 {
		return nil
	}
	if err := json.Unmarshal(metadataJSON, dest); err != nil {
		return fmt.Errorf("unmarshaling approval metadata: %w", err)
	}
	return nil
}
