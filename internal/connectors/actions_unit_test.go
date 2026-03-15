package connectors

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
	queryRows []pgx.Row
}

func (q *scriptedQuerier) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	return nil, errors.New("not implemented")
}

func (q *scriptedQuerier) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (q *scriptedQuerier) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	if len(q.queryRows) == 0 {
		return governedActionErrorRow{err: pgx.ErrNoRows}
	}
	row := q.queryRows[0]
	q.queryRows = q.queryRows[1:]
	return row
}

type governedActionErrorRow struct {
	err error
}

func (r governedActionErrorRow) Scan(...any) error {
	return r.err
}

type governedActionRow struct {
	action GovernedAction
}

func (r governedActionRow) Scan(dest ...any) error {
	if len(dest) != 16 {
		return fmt.Errorf("unexpected scan destination count: %d", len(dest))
	}
	idDest, ok := dest[0].(*uuid.UUID)
	if !ok {
		return fmt.Errorf("unexpected id destination %T", dest[0])
	}
	*idDest = r.action.ID
	tenantDest, ok := dest[1].(*uuid.UUID)
	if !ok {
		return fmt.Errorf("unexpected tenant destination %T", dest[1])
	}
	*tenantDest = r.action.TenantID
	agentDest, ok := dest[2].(**uuid.UUID)
	if !ok {
		return fmt.Errorf("unexpected agent destination %T", dest[2])
	}
	*agentDest = r.action.AgentID
	approvalDest, ok := dest[3].(**uuid.UUID)
	if !ok {
		return fmt.Errorf("unexpected approval destination %T", dest[3])
	}
	*approvalDest = r.action.ApprovalRequestID
	connectorDest, ok := dest[4].(*uuid.UUID)
	if !ok {
		return fmt.Errorf("unexpected connector destination %T", dest[4])
	}
	*connectorDest = r.action.ConnectorID
	sessionDest, ok := dest[5].(*string)
	if !ok {
		return fmt.Errorf("unexpected session destination %T", dest[5])
	}
	*sessionDest = r.action.SessionID
	correlationDest, ok := dest[6].(*string)
	if !ok {
		return fmt.Errorf("unexpected correlation destination %T", dest[6])
	}
	*correlationDest = r.action.CorrelationID
	toolDest, ok := dest[7].(*string)
	if !ok {
		return fmt.Errorf("unexpected tool destination %T", dest[7])
	}
	*toolDest = r.action.ToolName
	riskDest, ok := dest[8].(*string)
	if !ok {
		return fmt.Errorf("unexpected risk destination %T", dest[8])
	}
	*riskDest = r.action.RiskClass
	targetTypeDest, ok := dest[9].(*string)
	if !ok {
		return fmt.Errorf("unexpected target type destination %T", dest[9])
	}
	*targetTypeDest = r.action.TargetType
	targetLabelDest, ok := dest[10].(*string)
	if !ok {
		return fmt.Errorf("unexpected target label destination %T", dest[10])
	}
	*targetLabelDest = r.action.TargetLabel
	summaryDest, ok := dest[11].(*string)
	if !ok {
		return fmt.Errorf("unexpected summary destination %T", dest[11])
	}
	*summaryDest = r.action.ActionSummary
	argumentsDest, ok := dest[12].(*json.RawMessage)
	if !ok {
		return fmt.Errorf("unexpected arguments destination %T", dest[12])
	}
	*argumentsDest = append((*argumentsDest)[:0], r.action.Arguments...)
	statusDest, ok := dest[13].(*string)
	if !ok {
		return fmt.Errorf("unexpected status destination %T", dest[13])
	}
	*statusDest = r.action.Status
	createdAtDest, ok := dest[14].(*time.Time)
	if !ok {
		return fmt.Errorf("unexpected created at destination %T", dest[14])
	}
	*createdAtDest = r.action.CreatedAt
	updatedAtDest, ok := dest[15].(*time.Time)
	if !ok {
		return fmt.Errorf("unexpected updated at destination %T", dest[15])
	}
	*updatedAtDest = r.action.UpdatedAt
	return nil
}

func TestGovernedActionStore_MarkApprovedReturnsInvalidTransitionWhenStatusChangesBeforeUpdate(t *testing.T) {
	t.Parallel()

	store := NewGovernedActionStore()
	actionID := uuid.New()
	tenantID := uuid.New()
	connectorID := uuid.New()
	now := time.Now().UTC()

	q := &scriptedQuerier{
		queryRows: []pgx.Row{
			governedActionErrorRow{err: pgx.ErrNoRows},
			governedActionRow{action: GovernedAction{
				ID:            actionID,
				TenantID:      tenantID,
				ConnectorID:   connectorID,
				ToolName:      "update_contact",
				RiskClass:     "external_writes",
				TargetType:    "crm_record",
				TargetLabel:   "Contact 123",
				ActionSummary: "Update CRM contact",
				Arguments:     json.RawMessage(`{"id":"123"}`),
				Status:        GovernedActionStatusDenied,
				CreatedAt:     now,
				UpdatedAt:     now,
			}},
		},
	}

	_, err := store.MarkApproved(context.Background(), q, actionID)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrGovernedActionInvalidTransition)
}
