package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type scriptedQuerier struct {
	queryRows   []pgx.Row
	queryResult pgx.Rows
	queryErr    error

	queryRowCalls []queryCall
	queryCalls    []queryCall
	execCalls     []queryCall
}

type queryCall struct {
	sql  string
	args []any
}

func (q *scriptedQuerier) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	q.queryCalls = append(q.queryCalls, queryCall{sql: sql, args: args})
	return q.queryResult, q.queryErr
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
	request       Request
	rawMetadata   json.RawMessage
	metadataError error
}

func (r approvalRow) Scan(dest ...any) error {
	if len(dest) != 15 {
		return errors.New("unexpected scan destination count")
	}
	idDest, ok := dest[0].(*uuid.UUID)
	if !ok {
		return fmt.Errorf("unexpected id destination %T", dest[0])
	}
	*idDest = r.request.ID
	tenantDest, ok := dest[1].(*uuid.UUID)
	if !ok {
		return fmt.Errorf("unexpected tenant destination %T", dest[1])
	}
	*tenantDest = r.request.TenantID
	agentIDPtr, ok := dest[2].(**uuid.UUID)
	if !ok {
		return fmt.Errorf("unexpected agent destination %T", dest[2])
	}
	*agentIDPtr = r.request.AgentID
	requestedByPtr, ok := dest[3].(**uuid.UUID)
	if !ok {
		return fmt.Errorf("unexpected requester destination %T", dest[3])
	}
	*requestedByPtr = r.request.RequestedBy
	reviewedByPtr, ok := dest[4].(**uuid.UUID)
	if !ok {
		return fmt.Errorf("unexpected reviewer destination %T", dest[4])
	}
	*reviewedByPtr = r.request.ReviewedBy
	channelOutboxPtr, ok := dest[5].(**uuid.UUID)
	if !ok {
		return fmt.Errorf("unexpected channel outbox destination %T", dest[5])
	}
	*channelOutboxPtr = r.request.ChannelOutboxID
	riskClassDest, ok := dest[6].(*string)
	if !ok {
		return fmt.Errorf("unexpected risk class destination %T", dest[6])
	}
	*riskClassDest = r.request.RiskClass
	statusDest, ok := dest[7].(*string)
	if !ok {
		return fmt.Errorf("unexpected status destination %T", dest[7])
	}
	*statusDest = r.request.Status
	targetTypeDest, ok := dest[8].(*string)
	if !ok {
		return fmt.Errorf("unexpected target type destination %T", dest[8])
	}
	*targetTypeDest = r.request.TargetType
	targetLabelDest, ok := dest[9].(*string)
	if !ok {
		return fmt.Errorf("unexpected target label destination %T", dest[9])
	}
	*targetLabelDest = r.request.TargetLabel
	actionSummaryDest, ok := dest[10].(*string)
	if !ok {
		return fmt.Errorf("unexpected action summary destination %T", dest[10])
	}
	*actionSummaryDest = r.request.ActionSummary
	metadataDest, ok := dest[11].(*json.RawMessage)
	if !ok {
		return fmt.Errorf("unexpected metadata destination %T", dest[11])
	}
	if r.metadataError != nil {
		return r.metadataError
	}
	switch {
	case len(r.rawMetadata) > 0:
		*metadataDest = append((*metadataDest)[:0], r.rawMetadata...)
	case len(r.request.Metadata) == 0:
		*metadataDest = nil
	default:
		data, err := json.Marshal(r.request.Metadata)
		if err != nil {
			return err
		}
		*metadataDest = data
	}
	createdAtDest, ok := dest[12].(*time.Time)
	if !ok {
		return fmt.Errorf("unexpected created at destination %T", dest[12])
	}
	*createdAtDest = r.request.CreatedAt
	reviewedAtPtr, ok := dest[13].(**time.Time)
	if !ok {
		return fmt.Errorf("unexpected reviewed at destination %T", dest[13])
	}
	*reviewedAtPtr = r.request.ReviewedAt
	expiresAtPtr, ok := dest[14].(**time.Time)
	if !ok {
		return fmt.Errorf("unexpected expires at destination %T", dest[14])
	}
	*expiresAtPtr = r.request.ExpiresAt
	return nil
}

type scriptedRows struct {
	rows []pgx.Row
	idx  int
	err  error
}

func (r *scriptedRows) Close() {}

func (r *scriptedRows) Err() error { return r.err }

func (r *scriptedRows) CommandTag() pgconn.CommandTag { return pgconn.CommandTag{} }

func (r *scriptedRows) FieldDescriptions() []pgconn.FieldDescription { return nil }

func (r *scriptedRows) Next() bool {
	if r.idx >= len(r.rows) {
		return false
	}
	r.idx++
	return true
}

func (r *scriptedRows) Scan(dest ...any) error {
	if r.idx == 0 || r.idx > len(r.rows) {
		return errors.New("scan called without an active row")
	}
	return r.rows[r.idx-1].Scan(dest...)
}

func (r *scriptedRows) Values() ([]any, error) { return nil, nil }

func (r *scriptedRows) RawValues() [][]byte { return nil }

func (r *scriptedRows) Conn() *pgx.Conn { return nil }

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

func TestScanRequestRowReturnsMetadataDecodeError(t *testing.T) {
	t.Parallel()

	request := Request{
		ID:        uuid.New(),
		TenantID:  uuid.New(),
		Status:    StatusPending,
		CreatedAt: time.Now().UTC(),
	}

	_, err := scanRequestRow(approvalRow{
		request:     request,
		rawMetadata: json.RawMessage(`{"invalid"`),
	})

	require.Error(t, err)
	assert.ErrorContains(t, err, "unmarshaling approval metadata")
}

func TestStoreListReturnsMetadataDecodeError(t *testing.T) {
	t.Parallel()

	store := NewStore()
	tenantID := uuid.New()
	q := &scriptedQuerier{
		queryResult: &scriptedRows{
			rows: []pgx.Row{
				approvalRow{
					request: Request{
						ID:        uuid.New(),
						TenantID:  tenantID,
						Status:    StatusPending,
						CreatedAt: time.Now().UTC(),
					},
					rawMetadata: json.RawMessage(`{"invalid"`),
				},
			},
		},
	}

	_, err := store.List(context.Background(), q, ListParams{TenantID: tenantID, Limit: 10})

	require.Error(t, err)
	assert.ErrorContains(t, err, "unmarshaling approval metadata")
}
