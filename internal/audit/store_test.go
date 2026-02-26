package audit

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

func TestBuildListQuery_NoFilters(t *testing.T) {
	tenantID := uuid.New()
	params := ListEventsParams{
		TenantID: tenantID,
		Limit:    50,
	}
	sql, args := buildListQuery(params)
	assert.Contains(t, sql, "WHERE tenant_id = $1")
	assert.Contains(t, sql, "LIMIT $2")
	assert.Equal(t, tenantID, args[0])
	assert.Equal(t, 50, args[1])
}

func TestBuildListQuery_AllFilters(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	action := "user.created"
	resType := "user"
	source := "api"
	after := time.Date(2026, 2, 25, 0, 0, 0, 0, time.UTC)
	before := time.Date(2026, 2, 26, 0, 0, 0, 0, time.UTC)
	params := ListEventsParams{
		TenantID:     tenantID,
		Action:       &action,
		ResourceType: &resType,
		UserID:       &userID,
		Source:       &source,
		After:        &after,
		Before:       &before,
		Limit:        100,
	}
	sql, args := buildListQuery(params)
	assert.Contains(t, sql, "action = $")
	assert.Contains(t, sql, "resource_type = $")
	assert.Contains(t, sql, "user_id = $")
	assert.Contains(t, sql, "source = $")
	assert.Contains(t, sql, "created_at > $")
	assert.Contains(t, sql, "created_at < $")
	// tenant_id + 6 filters + limit = 8 args
	assert.Len(t, args, 8)
}

func TestBuildListQuery_PartialFilters(t *testing.T) {
	tenantID := uuid.New()
	action := "role.deleted"
	params := ListEventsParams{
		TenantID: tenantID,
		Action:   &action,
		Limit:    50,
	}
	sql, args := buildListQuery(params)
	assert.Contains(t, sql, "action = $2")
	assert.Contains(t, sql, "LIMIT $3")
	assert.Len(t, args, 3)
}
