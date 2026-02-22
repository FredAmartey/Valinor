package audit

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildBatchInsert(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()

	events := []Event{
		{
			TenantID:     tenantID,
			UserID:       &userID,
			Action:       "message.sent",
			ResourceType: "agent",
			ResourceID:   nil,
			Metadata:     map[string]any{"content_length": 42},
			Source:       "api",
		},
		{
			TenantID:     tenantID,
			UserID:       nil,
			Action:       "tool.blocked",
			ResourceType: "agent",
			Source:       "system",
		},
	}

	sql, args, err := buildBatchInsert(events)
	require.NoError(t, err)
	assert.Contains(t, sql, "INSERT INTO audit_events")
	assert.Contains(t, sql, "($1, $2, $3, $4, $5, $6, $7)")
	// 7 params per event x 2 events = 14 args
	assert.Len(t, args, 14)
	// First event's tenant_id
	assert.Equal(t, tenantID, args[0])
}

func TestBuildBatchInsert_Empty(t *testing.T) {
	store := NewStore()
	err := store.InsertBatch(context.Background(), nil, nil)
	require.NoError(t, err)
}
