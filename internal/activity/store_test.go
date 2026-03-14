package activity

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildBatchInsert(t *testing.T) {
	tenantID := uuid.New()
	agentID := uuid.New()
	userID := uuid.New()

	events := []Event{
		{
			TenantID:          tenantID,
			AgentID:           &agentID,
			UserID:            &userID,
			SessionID:         "session-1",
			CorrelationID:     "corr-1",
			Kind:              KindPromptReceived,
			Status:            StatusAllowed,
			Source:            "api",
			Provenance:        ProvenanceControlPlaneHTTP,
			Binding:           "http",
			RuntimeSource:     "openclaw",
			InternalEventType: "request.accepted",
			DeliveryTarget:    "agent:session-1",
			Title:             "Prompt received",
			Summary:           "User prompt delivered to agent",
			Metadata: map[string]any{
				"message_length": 42,
			},
			SensitiveContentRef: &SensitiveContentRef{
				Store:   "channel_messages",
				Key:     "request_content",
				Preview: "Need transfer options for tomorrow",
			},
			OccurredAt: time.Date(2026, 3, 14, 10, 30, 0, 0, time.UTC),
		},
		{
			TenantID:  tenantID,
			Kind:      KindSecurityFlagged,
			Status:    StatusBlocked,
			RiskClass: RiskClassSensitiveDataAccess,
			Source:    "system",
			Title:     "Outbound action blocked",
			Summary:   "Potential secret leak detected",
		},
	}

	sql, args, err := buildBatchInsert(events)
	require.NoError(t, err)
	assert.Contains(t, sql, "INSERT INTO agent_activity_events")
	assert.Contains(t, sql, "($1, $2, $3")
	assert.Contains(t, sql, "internal_event_type")
	assert.Contains(t, sql, "provenance")
	assert.Contains(t, sql, "binding")
	assert.Contains(t, sql, "delivery_target")
	assert.Contains(t, sql, "runtime_source")
	assert.Len(t, args, 52)
	assert.Equal(t, tenantID, args[0])
	agentUUID, ok := args[1].(*uuid.UUID)
	require.True(t, ok)
	require.NotNil(t, agentUUID)
	require.Equal(t, agentID, *agentUUID)
	assert.Equal(t, ProvenanceControlPlaneHTTP, args[13])
	assert.Equal(t, "request.accepted", args[14])
	assert.Equal(t, "http", args[15])
	assert.Equal(t, "agent:session-1", args[16])
	assert.Equal(t, "openclaw", args[17])
}

func TestInsertBatch_Empty(t *testing.T) {
	store := NewStore()
	err := store.InsertBatch(context.Background(), nil, nil)
	require.NoError(t, err)
}

func TestBuildListQuery_NoFilters(t *testing.T) {
	tenantID := uuid.New()
	sql, args := buildListQuery(ListEventsParams{
		TenantID: tenantID,
		Limit:    50,
	})
	assert.Contains(t, sql, "FROM agent_activity_events")
	assert.Contains(t, sql, "WHERE tenant_id = $1")
	assert.Contains(t, sql, "ORDER BY occurred_at DESC")
	assert.Contains(t, sql, "LIMIT $2")
	assert.Equal(t, tenantID, args[0])
	assert.Equal(t, 50, args[1])
}

func TestBuildListQuery_AllFilters(t *testing.T) {
	tenantID := uuid.New()
	agentID := uuid.New()
	userID := uuid.New()
	departmentID := uuid.New()
	kind := KindToolCalled
	status := StatusBlocked
	riskClass := RiskClassExternalWrites
	source := "agent"
	after := time.Date(2026, 3, 14, 8, 0, 0, 0, time.UTC)
	before := time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)

	sql, args := buildListQuery(ListEventsParams{
		TenantID:     tenantID,
		AgentID:      &agentID,
		UserID:       &userID,
		DepartmentID: &departmentID,
		Kind:         &kind,
		Status:       &status,
		RiskClass:    &riskClass,
		Source:       &source,
		After:        &after,
		Before:       &before,
		Limit:        100,
	})

	assert.Contains(t, sql, "agent_id = $")
	assert.Contains(t, sql, "user_id = $")
	assert.Contains(t, sql, "department_id = $")
	assert.Contains(t, sql, "kind = $")
	assert.Contains(t, sql, "status = $")
	assert.Contains(t, sql, "risk_class = $")
	assert.Contains(t, sql, "source = $")
	assert.Contains(t, sql, "occurred_at > $")
	assert.Contains(t, sql, "occurred_at < $")
	assert.Len(t, args, 11)
}

func TestBuildSecurityListQuery(t *testing.T) {
	tenantID := uuid.New()
	sql, args := buildSecurityListQuery(ListEventsParams{
		TenantID: tenantID,
		Limit:    25,
	})

	assert.Contains(t, sql, "FROM agent_activity_events")
	assert.Contains(t, sql, "kind = 'security.flagged'")
	assert.Contains(t, sql, "status IN ('blocked', 'flagged', 'halted', 'approval_required')")
	assert.Equal(t, tenantID, args[0])
	assert.Equal(t, 25, args[1])
}

func TestBuildSecurityListQuery_PreservesAdditionalFilters(t *testing.T) {
	tenantID := uuid.New()
	agentID := uuid.New()
	status := StatusBlocked

	sql, args := buildSecurityListQuery(ListEventsParams{
		TenantID: tenantID,
		AgentID:  &agentID,
		Status:   &status,
		Limit:    10,
	})

	assert.Contains(t, sql, "tenant_id = $1")
	assert.Contains(t, sql, "(kind = 'security.flagged' OR status IN ('blocked', 'flagged', 'halted', 'approval_required'))")
	assert.Contains(t, sql, "agent_id = $2")
	assert.Contains(t, sql, "status = $3")
	assert.Equal(t, tenantID, args[0])
	assert.Equal(t, agentID, args[1])
	assert.Equal(t, status, args[2])
	assert.Equal(t, 10, args[3])
}
