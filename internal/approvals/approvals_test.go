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
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valinor-ai/valinor/internal/connectors"
	"github.com/valinor-ai/valinor/internal/platform/database"
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

type fakeGovernedActionWriter struct {
	createParams  []connectors.CreateGovernedActionParams
	awaitingCalls []struct {
		id         uuid.UUID
		approvalID uuid.UUID
	}
	created *connectors.GovernedAction
}

func (f *fakeGovernedActionWriter) Create(_ context.Context, _ database.Querier, params connectors.CreateGovernedActionParams) (*connectors.GovernedAction, error) {
	f.createParams = append(f.createParams, params)
	if f.created != nil {
		return f.created, nil
	}
	created := &connectors.GovernedAction{
		ID:            uuid.New(),
		TenantID:      params.TenantID,
		AgentID:       params.AgentID,
		ConnectorID:   params.ConnectorID,
		SessionID:     params.SessionID,
		CorrelationID: params.CorrelationID,
		ToolName:      params.ToolName,
		RiskClass:     params.RiskClass,
		TargetType:    params.TargetType,
		TargetLabel:   params.TargetLabel,
		ActionSummary: params.ActionSummary,
		Arguments:     params.Arguments,
		Status:        params.Status,
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	f.created = created
	return created, nil
}

func (f *fakeGovernedActionWriter) MarkAwaitingApproval(_ context.Context, _ database.Querier, id, approvalID uuid.UUID) (*connectors.GovernedAction, error) {
	f.awaitingCalls = append(f.awaitingCalls, struct {
		id         uuid.UUID
		approvalID uuid.UUID
	}{id: id, approvalID: approvalID})
	updated := *f.created
	updated.Status = connectors.GovernedActionStatusAwaitingApproval
	updated.ApprovalRequestID = &approvalID
	updated.UpdatedAt = time.Now().UTC()
	f.created = &updated
	return f.created, nil
}

type failingGovernedActionWriter struct {
	store *connectors.GovernedActionStore
	err   error
}

func (f *failingGovernedActionWriter) Create(ctx context.Context, q database.Querier, params connectors.CreateGovernedActionParams) (*connectors.GovernedAction, error) {
	return f.store.Create(ctx, q, params)
}

func (f *failingGovernedActionWriter) MarkAwaitingApproval(_ context.Context, _ database.Querier, _, _ uuid.UUID) (*connectors.GovernedAction, error) {
	return nil, f.err
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

func setupApprovalsIntegrationDB(t *testing.T) (*database.Pool, func()) {
	t.Helper()

	ctx := context.Background()
	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("valinor_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
		),
	)
	require.NoError(t, err)

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	require.NoError(t, database.RunMigrations(connStr, "file://../../migrations"))
	pool, err := database.Connect(ctx, connStr, 5)
	require.NoError(t, err)

	cleanup := func() {
		pool.Close()
		_ = container.Terminate(ctx)
	}
	return pool, cleanup
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

func TestStoreCreateForConnectorAction_PersistsApprovalMetadataAndAwaitingStatus(t *testing.T) {
	store := NewStore()
	tenantID := uuid.New()
	agentID := uuid.New()
	requestedBy := uuid.New()
	connectorID := uuid.New()
	writer := &fakeGovernedActionWriter{}

	approvalID := uuid.New()
	q := &scriptedQuerier{
		queryRows: []pgx.Row{approvalRow{request: Request{
			ID:            approvalID,
			TenantID:      tenantID,
			AgentID:       &agentID,
			RequestedBy:   &requestedBy,
			RiskClass:     "external_writes",
			Status:        StatusPending,
			TargetType:    "crm_record",
			TargetLabel:   "Contact 123",
			ActionSummary: "Update CRM contact",
			CreatedAt:     time.Now().UTC(),
		}}},
	}

	result, err := store.CreateForConnectorAction(context.Background(), q, writer, ConnectorActionParams{
		TenantID:      tenantID,
		AgentID:       &agentID,
		RequestedBy:   &requestedBy,
		ConnectorID:   connectorID,
		ConnectorName: "crm-api",
		SessionID:     "session-123",
		CorrelationID: "corr-123",
		ToolName:      "update_contact",
		RiskClass:     "external_writes",
		TargetType:    "crm_record",
		TargetLabel:   "Contact 123",
		ActionSummary: "Update CRM contact",
		Arguments:     json.RawMessage(`{"id":"123"}`),
		Metadata:      map[string]any{"source": "runtime"},
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Approval)
	require.NotNil(t, result.Action)
	require.Len(t, writer.createParams, 1)
	assert.Equal(t, connectors.GovernedActionStatusPending, writer.createParams[0].Status)
	require.Len(t, writer.awaitingCalls, 1)
	assert.Equal(t, writer.created.ID, writer.awaitingCalls[0].id)
	assert.Equal(t, approvalID, writer.awaitingCalls[0].approvalID)
	assert.Equal(t, connectors.GovernedActionStatusAwaitingApproval, result.Action.Status)
	require.NotNil(t, result.Action.ApprovalRequestID)
	assert.Equal(t, approvalID, *result.Action.ApprovalRequestID)

	require.Len(t, q.queryRowCalls, 1)
	metadataArg, ok := q.queryRowCalls[0].args[8].([]byte)
	require.True(t, ok)
	var metadata map[string]any
	require.NoError(t, json.Unmarshal(metadataArg, &metadata))
	assert.Equal(t, "runtime", metadata["source"])
	assert.Equal(t, connectorID.String(), metadata["connector_id"])
	assert.Equal(t, "crm-api", metadata["connector_name"])
	assert.Equal(t, "update_contact", metadata["tool_name"])
	assert.Equal(t, "corr-123", metadata["correlation_id"])
	assert.Equal(t, "session-123", metadata["session_id"])
	assert.Equal(t, writer.created.ID.String(), metadata["governed_action_id"])
	assert.Equal(t, `{"id":"123"}`, metadata["arguments"])
}

func TestConnectorActionService_CreateForConnectorAction_RollsBackOnAwaitingApprovalFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupApprovalsIntegrationDB(t)
	defer cleanup()

	ctx := context.Background()
	tenantSlug := "approvals-atomicity-" + uuid.NewString()[:8]

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id",
		"Tenant "+tenantSlug,
		tenantSlug,
	).Scan(&tenantID)
	require.NoError(t, err)

	connectorStore := connectors.NewStore()
	var connectorID uuid.UUID
	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		connector, createErr := connectorStore.Create(
			ctx,
			q,
			"crm-"+tenantSlug,
			"mcp",
			"https://example.com/"+tenantSlug,
			json.RawMessage(`{}`),
			json.RawMessage(`[{"name":"update_contact","action_type":"write","risk_class":"external_writes"}]`),
			json.RawMessage(`[]`),
		)
		if createErr != nil {
			return createErr
		}
		connectorID = connector.ID
		return nil
	})
	require.NoError(t, err)

	service := NewConnectorActionService(pool, NewStore(), &failingGovernedActionWriter{
		store: connectors.NewGovernedActionStore(),
		err:   errors.New("boom awaiting approval"),
	})

	_, err = service.CreateForConnectorAction(ctx, tenantID, ConnectorActionParams{
		TenantID:      mustUUID(t, tenantID),
		ConnectorID:   connectorID,
		ConnectorName: "crm-api",
		SessionID:     "session-123",
		CorrelationID: "corr-123",
		ToolName:      "update_contact",
		RiskClass:     "external_writes",
		TargetType:    "crm_record",
		TargetLabel:   "Contact 123",
		ActionSummary: "Update CRM contact",
		Arguments:     json.RawMessage(`{"id":"123"}`),
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "marking governed connector action awaiting approval")

	var approvalCount, actionCount int
	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		if scanErr := q.QueryRow(ctx, "SELECT COUNT(*) FROM approval_requests").Scan(&approvalCount); scanErr != nil {
			return scanErr
		}
		if scanErr := q.QueryRow(ctx, "SELECT COUNT(*) FROM governed_connector_actions").Scan(&actionCount); scanErr != nil {
			return scanErr
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 0, approvalCount)
	assert.Equal(t, 0, actionCount)
}

func mustUUID(t *testing.T, value string) uuid.UUID {
	t.Helper()
	parsed, err := uuid.Parse(value)
	require.NoError(t, err)
	return parsed
}
