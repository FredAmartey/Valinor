package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type scriptedQuerier struct {
	queryRows []pgx.Row
	queryErr  error

	queryRowCalls []queryCall
	execCalls     []queryCall
}

type queryCall struct {
	sql  string
	args []any
}

func (q *scriptedQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, q.queryErr
}

func (q *scriptedQuerier) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	q.execCalls = append(q.execCalls, queryCall{sql: sql, args: args})
	return pgconn.CommandTag{}, nil
}

func (q *scriptedQuerier) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	q.queryRowCalls = append(q.queryRowCalls, queryCall{sql: sql, args: args})
	if len(q.queryRows) == 0 {
		return errorRow{err: pgx.ErrNoRows}
	}
	row := q.queryRows[0]
	q.queryRows = q.queryRows[1:]
	return row
}

type errorRow struct {
	err error
}

func (r errorRow) Scan(...any) error {
	return r.err
}

type approvalRow struct {
	request Request
}

func (r approvalRow) Scan(dest ...any) error {
	if len(dest) != 15 {
		return errors.New("unexpected scan destination count")
	}
	*(dest[0].(*uuid.UUID)) = r.request.ID
	*(dest[1].(*uuid.UUID)) = r.request.TenantID
	agentIDPtr := dest[2].(**uuid.UUID)
	*agentIDPtr = r.request.AgentID
	requestedByPtr := dest[3].(**uuid.UUID)
	*requestedByPtr = r.request.RequestedBy
	reviewedByPtr := dest[4].(**uuid.UUID)
	*reviewedByPtr = r.request.ReviewedBy
	channelOutboxPtr := dest[5].(**uuid.UUID)
	*channelOutboxPtr = r.request.ChannelOutboxID
	*(dest[6].(*string)) = r.request.RiskClass
	*(dest[7].(*string)) = r.request.Status
	*(dest[8].(*string)) = r.request.TargetType
	*(dest[9].(*string)) = r.request.TargetLabel
	*(dest[10].(*string)) = r.request.ActionSummary
	if metadataDest, ok := dest[11].(*json.RawMessage); ok {
		if len(r.request.Metadata) == 0 {
			*metadataDest = nil
		} else {
			data, err := json.Marshal(r.request.Metadata)
			if err != nil {
				return err
			}
			*metadataDest = data
		}
	}
	*(dest[12].(*time.Time)) = r.request.CreatedAt
	reviewedAtPtr := dest[13].(**time.Time)
	*reviewedAtPtr = r.request.ReviewedAt
	expiresAtPtr := dest[14].(**time.Time)
	*expiresAtPtr = r.request.ExpiresAt
	return nil
}

func TestStoreApproveReturnsNotFoundWhenApprovalMissing(t *testing.T) {
	store := NewStore()
	q := &scriptedQuerier{
		queryRows: []pgx.Row{errorRow{err: pgx.ErrNoRows}},
	}

	_, err := store.Approve(context.Background(), q, uuid.New(), uuid.New(), uuid.New())

	require.ErrorIs(t, err, ErrApprovalNotFound)
	require.Len(t, q.queryRowCalls, 1)
	assert.Contains(t, q.queryRowCalls[0].sql, "FROM approval_requests")
	assert.Contains(t, q.queryRowCalls[0].sql, "tenant_id = $2")
}

func TestStoreApproveReturnsSelfApprovalError(t *testing.T) {
	store := NewStore()
	reviewerID := uuid.New()
	tenantID := uuid.New()
	approvalID := uuid.New()
	q := &scriptedQuerier{
		queryRows: []pgx.Row{approvalRow{request: Request{
			ID:          approvalID,
			TenantID:    tenantID,
			RequestedBy: &reviewerID,
			Status:      StatusPending,
			CreatedAt:   time.Now().UTC(),
		}}},
	}

	_, err := store.Approve(context.Background(), q, approvalID, reviewerID, tenantID)

	require.ErrorIs(t, err, ErrApprovalSelfReview)
	require.Len(t, q.queryRowCalls, 1)
	assert.Empty(t, q.execCalls)
}

func TestStoreApproveReturnsNotPendingForResolvedApproval(t *testing.T) {
	store := NewStore()
	reviewerID := uuid.New()
	tenantID := uuid.New()
	approvalID := uuid.New()
	q := &scriptedQuerier{
		queryRows: []pgx.Row{approvalRow{request: Request{
			ID:        approvalID,
			TenantID:  tenantID,
			Status:    StatusDenied,
			CreatedAt: time.Now().UTC(),
		}}},
	}

	_, err := store.Approve(context.Background(), q, approvalID, reviewerID, tenantID)

	require.ErrorIs(t, err, ErrApprovalNotPending)
	require.Len(t, q.queryRowCalls, 1)
	assert.Empty(t, q.execCalls)
}
