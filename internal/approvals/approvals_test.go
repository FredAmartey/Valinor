package approvals

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingQuerier struct {
	sql  string
	args []any
}

func (q *recordingQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("not implemented")
}

func (q *recordingQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("not implemented")
}

func (q *recordingQuerier) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	q.sql = sql
	q.args = args
	return errorRow{err: pgx.ErrNoRows}
}

type errorRow struct {
	err error
}

func (r errorRow) Scan(...any) error {
	return r.err
}

func TestStoreApproveScopesResolutionToTenant(t *testing.T) {
	store := NewStore()
	q := &recordingQuerier{}
	approvalID := uuid.New()
	reviewerID := uuid.New()
	tenantID := uuid.New()

	_, err := store.Approve(context.Background(), q, approvalID, reviewerID, tenantID)
	require.ErrorIs(t, err, ErrApprovalNotPending)
	assert.Contains(t, q.sql, "tenant_id = $4")
	require.Len(t, q.args, 4)
	assert.Equal(t, approvalID, q.args[0])
	assert.Equal(t, StatusApproved, q.args[1])
	assert.Equal(t, reviewerID, q.args[2])
	assert.Equal(t, tenantID, q.args[3])
}

func TestStoreApprovePreventsSelfApproval(t *testing.T) {
	store := NewStore()
	q := &recordingQuerier{}
	approvalID := uuid.New()
	reviewerID := uuid.New()
	tenantID := uuid.New()

	_, err := store.Approve(context.Background(), q, approvalID, reviewerID, tenantID)
	require.ErrorIs(t, err, ErrApprovalNotPending)
	assert.Contains(t, q.sql, "(requested_by IS NULL OR requested_by <> $3)")
}
