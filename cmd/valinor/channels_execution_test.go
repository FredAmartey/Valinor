package main

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/audit"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/channels"
	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/rbac"
	"github.com/valinor-ai/valinor/internal/sentinel"
)

type captureAuditLogger struct {
	events []audit.Event
}

func (l *captureAuditLogger) Log(_ context.Context, event audit.Event) {
	l.events = append(l.events, event)
}

func (l *captureAuditLogger) Close() error {
	return nil
}

func testExecutionMessage() channels.ExecutionMessage {
	return channels.ExecutionMessage{
		TenantID:          "190f3a21-3b2c-42ce-b26e-2f448a58ec14",
		Platform:          "whatsapp",
		PlatformUserID:    "+15550001111",
		PlatformMessageID: "wamid.123",
		CorrelationID:     "corr-123",
		Content:           "hello",
		Link: channels.ChannelLink{
			TenantID: uuid.MustParse("190f3a21-3b2c-42ce-b26e-2f448a58ec14"),
			UserID:   uuid.MustParse("2f6a9b58-c56f-49d5-a06f-45b0145b9e1f"),
			State:    channels.LinkStateVerified,
		},
	}
}

func TestNewChannelExecutor_DeniesRBAC(t *testing.T) {
	logger := &captureAuditLogger{}
	listCalled := false
	dispatchCalled := false

	exec := newChannelExecutor(
		func(_ context.Context, _ string) (*auth.Identity, error) {
			return &auth.Identity{
				UserID:   "2f6a9b58-c56f-49d5-a06f-45b0145b9e1f",
				TenantID: "190f3a21-3b2c-42ce-b26e-2f448a58ec14",
				Roles:    []string{"standard_user"},
			}, nil
		},
		func(_ context.Context, _ *auth.Identity, _ string) (*rbac.Decision, error) {
			return &rbac.Decision{Allowed: false, Reason: "no permission"}, nil
		},
		func(_ context.Context, _ string) ([]orchestrator.AgentInstance, error) {
			listCalled = true
			return nil, nil
		},
		func(_ context.Context, _ orchestrator.AgentInstance, _ string) (string, error) {
			dispatchCalled = true
			return "", nil
		},
		nil,
		logger,
	)
	require.NotNil(t, exec)

	result := exec(context.Background(), testExecutionMessage())
	assert.Equal(t, channels.IngressDeniedRBAC, result.Decision)
	assert.False(t, listCalled)
	assert.False(t, dispatchCalled)
	require.Len(t, logger.events, 1)
	assert.Equal(t, audit.ActionChannelActionDeniedRBAC, logger.events[0].Action)
}

func TestNewChannelExecutor_RejectsTenantMismatch(t *testing.T) {
	logger := &captureAuditLogger{}
	lookupCalled := false

	exec := newChannelExecutor(
		func(_ context.Context, _ string) (*auth.Identity, error) {
			lookupCalled = true
			return &auth.Identity{}, nil
		},
		func(_ context.Context, _ *auth.Identity, _ string) (*rbac.Decision, error) {
			return &rbac.Decision{Allowed: true}, nil
		},
		func(_ context.Context, _ string) ([]orchestrator.AgentInstance, error) {
			return nil, nil
		},
		func(_ context.Context, _ orchestrator.AgentInstance, _ string) (string, error) {
			return "", nil
		},
		nil,
		logger,
	)
	require.NotNil(t, exec)

	msg := testExecutionMessage()
	msg.TenantID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	result := exec(context.Background(), msg)
	assert.Equal(t, channels.IngressDispatchFailed, result.Decision)
	assert.False(t, lookupCalled)
	require.Len(t, logger.events, 1)
	assert.Equal(t, audit.ActionChannelActionDispatchFailed, logger.events[0].Action)
}

func TestNewChannelExecutor_DeniesSentinel(t *testing.T) {
	logger := &captureAuditLogger{}
	listCalled := false

	exec := newChannelExecutor(
		func(_ context.Context, _ string) (*auth.Identity, error) {
			return &auth.Identity{
				UserID:      "2f6a9b58-c56f-49d5-a06f-45b0145b9e1f",
				TenantID:    "190f3a21-3b2c-42ce-b26e-2f448a58ec14",
				Roles:       []string{"standard_user"},
				Departments: []string{"dept-a"},
			}, nil
		},
		func(_ context.Context, _ *auth.Identity, _ string) (*rbac.Decision, error) {
			return &rbac.Decision{Allowed: true}, nil
		},
		func(_ context.Context, _ string) ([]orchestrator.AgentInstance, error) {
			listCalled = true
			return nil, nil
		},
		func(_ context.Context, _ orchestrator.AgentInstance, _ string) (string, error) {
			return "", nil
		},
		func(_ context.Context, _, _, _ string) (sentinel.ScanResult, error) {
			return sentinel.ScanResult{Allowed: false, Reason: "pattern:block", Score: 0.99}, nil
		},
		logger,
	)
	require.NotNil(t, exec)

	result := exec(context.Background(), testExecutionMessage())
	assert.Equal(t, channels.IngressDeniedSentinel, result.Decision)
	assert.False(t, listCalled)
	require.Len(t, logger.events, 1)
	assert.Equal(t, audit.ActionChannelActionDeniedSentinel, logger.events[0].Action)
}

func TestNewChannelExecutor_DeniesWhenNoRunningAgent(t *testing.T) {
	logger := &captureAuditLogger{}
	dispatchCalled := false

	exec := newChannelExecutor(
		func(_ context.Context, _ string) (*auth.Identity, error) {
			return &auth.Identity{
				UserID:      "2f6a9b58-c56f-49d5-a06f-45b0145b9e1f",
				TenantID:    "190f3a21-3b2c-42ce-b26e-2f448a58ec14",
				Roles:       []string{"standard_user"},
				Departments: []string{"dept-a"},
			}, nil
		},
		func(_ context.Context, _ *auth.Identity, _ string) (*rbac.Decision, error) {
			return &rbac.Decision{Allowed: true}, nil
		},
		func(_ context.Context, _ string) ([]orchestrator.AgentInstance, error) {
			return []orchestrator.AgentInstance{}, nil
		},
		func(_ context.Context, _ orchestrator.AgentInstance, _ string) (string, error) {
			dispatchCalled = true
			return "", nil
		},
		nil,
		logger,
	)
	require.NotNil(t, exec)

	result := exec(context.Background(), testExecutionMessage())
	assert.Equal(t, channels.IngressDeniedNoAgent, result.Decision)
	assert.False(t, dispatchCalled)
	require.Len(t, logger.events, 1)
	assert.Equal(t, audit.ActionChannelActionDeniedNoAgent, logger.events[0].Action)
}

func TestNewChannelExecutor_ExecutesAgainstPreferredDepartmentAgent(t *testing.T) {
	logger := &captureAuditLogger{}
	dispatchCalled := false
	var dispatchedAgentID string

	sharedCID := uint32(101)
	preferredCID := uint32(102)
	deptID := "dept-a"

	exec := newChannelExecutor(
		func(_ context.Context, _ string) (*auth.Identity, error) {
			return &auth.Identity{
				UserID:      "2f6a9b58-c56f-49d5-a06f-45b0145b9e1f",
				TenantID:    "190f3a21-3b2c-42ce-b26e-2f448a58ec14",
				Roles:       []string{"standard_user"},
				Departments: []string{deptID},
			}, nil
		},
		func(_ context.Context, _ *auth.Identity, _ string) (*rbac.Decision, error) {
			return &rbac.Decision{Allowed: true}, nil
		},
		func(_ context.Context, _ string) ([]orchestrator.AgentInstance, error) {
			return []orchestrator.AgentInstance{
				{
					ID:           "agent-shared",
					Status:       orchestrator.StatusRunning,
					VsockCID:     &sharedCID,
					DepartmentID: nil,
				},
				{
					ID:           "agent-dept-a",
					Status:       orchestrator.StatusRunning,
					VsockCID:     &preferredCID,
					DepartmentID: &deptID,
				},
			}, nil
		},
		func(_ context.Context, agent orchestrator.AgentInstance, _ string) (string, error) {
			dispatchCalled = true
			dispatchedAgentID = agent.ID
			return "agent response", nil
		},
		nil,
		logger,
	)
	require.NotNil(t, exec)

	result := exec(context.Background(), testExecutionMessage())
	assert.Equal(t, channels.IngressExecuted, result.Decision)
	assert.Equal(t, "agent-dept-a", result.AgentID)
	assert.True(t, dispatchCalled)
	assert.Equal(t, "agent-dept-a", dispatchedAgentID)
	require.Len(t, logger.events, 1)
	assert.Equal(t, audit.ActionChannelActionExecuted, logger.events[0].Action)
}

func TestNewChannelExecutor_MapsDispatchError(t *testing.T) {
	logger := &captureAuditLogger{}
	cid := uint32(101)

	exec := newChannelExecutor(
		func(_ context.Context, _ string) (*auth.Identity, error) {
			return &auth.Identity{
				UserID:   "2f6a9b58-c56f-49d5-a06f-45b0145b9e1f",
				TenantID: "190f3a21-3b2c-42ce-b26e-2f448a58ec14",
				Roles:    []string{"standard_user"},
			}, nil
		},
		func(_ context.Context, _ *auth.Identity, _ string) (*rbac.Decision, error) {
			return &rbac.Decision{Allowed: true}, nil
		},
		func(_ context.Context, _ string) ([]orchestrator.AgentInstance, error) {
			return []orchestrator.AgentInstance{{
				ID:       "agent-1",
				Status:   orchestrator.StatusRunning,
				VsockCID: &cid,
			}}, nil
		},
		func(_ context.Context, _ orchestrator.AgentInstance, _ string) (string, error) {
			return "", errors.New("downstream timeout")
		},
		nil,
		logger,
	)
	require.NotNil(t, exec)

	result := exec(context.Background(), testExecutionMessage())
	assert.Equal(t, channels.IngressDispatchFailed, result.Decision)
	assert.Equal(t, "agent-1", result.AgentID)
	require.Len(t, logger.events, 1)
	assert.Equal(t, audit.ActionChannelActionDispatchFailed, logger.events[0].Action)
}

func TestSelectChannelTargetAgent_FallbackToSharedThenAnyRunning(t *testing.T) {
	sharedCID := uint32(100)
	deptCID := uint32(101)
	deptID := "dept-x"

	target := selectChannelTargetAgent([]orchestrator.AgentInstance{
		{
			ID:           "agent-wrong-dept",
			Status:       orchestrator.StatusRunning,
			VsockCID:     &deptCID,
			DepartmentID: &deptID,
		},
		{
			ID:           "agent-shared",
			Status:       orchestrator.StatusRunning,
			VsockCID:     &sharedCID,
			DepartmentID: nil,
		},
	}, []string{"dept-y"})
	require.NotNil(t, target)
	assert.Equal(t, "agent-shared", target.ID)
}
