package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/audit"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/channels"
	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/proxy"
	"github.com/valinor-ai/valinor/internal/rbac"
	"github.com/valinor-ai/valinor/internal/sentinel"
)

type captureAuditLogger struct {
	events []audit.Event
}

func ptrString(v string) *string {
	return &v
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

func TestNewChannelExecutor_ReturnsNilWhenRequiredDepsMissing(t *testing.T) {
	lookup := func(_ context.Context, _ string) (*auth.Identity, error) { return &auth.Identity{}, nil }
	authorize := func(_ context.Context, _ *auth.Identity, _ string) (*rbac.Decision, error) {
		return &rbac.Decision{Allowed: true}, nil
	}
	listAgents := func(_ context.Context, _ string) ([]orchestrator.AgentInstance, error) { return nil, nil }
	dispatch := func(_ context.Context, _ orchestrator.AgentInstance, _ string, _ []channels.ChannelConversationTurn, _ string) (string, error) {
		return "", nil
	}

	assert.Nil(t, newChannelExecutor(nil, authorize, listAgents, dispatch, nil, nil, nil))
	assert.Nil(t, newChannelExecutor(lookup, nil, listAgents, dispatch, nil, nil, nil))
	assert.Nil(t, newChannelExecutor(lookup, authorize, nil, dispatch, nil, nil, nil))
	assert.Nil(t, newChannelExecutor(lookup, authorize, listAgents, nil, nil, nil, nil))
}

func TestNewChannelExecutor_EmptyContentShortCircuits(t *testing.T) {
	logger := &captureAuditLogger{}
	lookupCalled := false
	authorizeCalled := false
	listCalled := false
	dispatchCalled := false

	exec := newChannelExecutor(
		func(_ context.Context, _ string) (*auth.Identity, error) {
			lookupCalled = true
			return &auth.Identity{}, nil
		},
		func(_ context.Context, _ *auth.Identity, _ string) (*rbac.Decision, error) {
			authorizeCalled = true
			return &rbac.Decision{Allowed: true}, nil
		},
		func(_ context.Context, _ string) ([]orchestrator.AgentInstance, error) {
			listCalled = true
			return nil, nil
		},
		func(_ context.Context, _ orchestrator.AgentInstance, _ string, _ []channels.ChannelConversationTurn, _ string) (string, error) {
			dispatchCalled = true
			return "", nil
		},
		nil,
		nil,
		logger,
	)
	require.NotNil(t, exec)

	msg := testExecutionMessage()
	msg.Content = "   "
	result := exec(context.Background(), msg)
	assert.Equal(t, channels.IngressAccepted, result.Decision)
	assert.False(t, lookupCalled)
	assert.False(t, authorizeCalled)
	assert.False(t, listCalled)
	assert.False(t, dispatchCalled)
	assert.Empty(t, logger.events)
}

func TestNewChannelExecutor_RejectsMissingLinkUserID(t *testing.T) {
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
		func(_ context.Context, _ orchestrator.AgentInstance, _ string, _ []channels.ChannelConversationTurn, _ string) (string, error) {
			return "", nil
		},
		nil,
		nil,
		logger,
	)
	require.NotNil(t, exec)

	msg := testExecutionMessage()
	msg.Link.UserID = uuid.Nil
	result := exec(context.Background(), msg)
	assert.Equal(t, channels.IngressDispatchFailed, result.Decision)
	assert.False(t, lookupCalled)
	require.Len(t, logger.events, 1)
	assert.Equal(t, audit.ActionChannelActionDispatchFailed, logger.events[0].Action)
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
		func(_ context.Context, _ orchestrator.AgentInstance, _ string, _ []channels.ChannelConversationTurn, _ string) (string, error) {
			dispatchCalled = true
			return "", nil
		},
		nil,
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
		func(_ context.Context, _ orchestrator.AgentInstance, _ string, _ []channels.ChannelConversationTurn, _ string) (string, error) {
			return "", nil
		},
		nil,
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

func TestNewChannelExecutor_IdentityLookupError(t *testing.T) {
	logger := &captureAuditLogger{}
	authorizeCalled := false

	exec := newChannelExecutor(
		func(_ context.Context, _ string) (*auth.Identity, error) {
			return nil, errors.New("identity store unavailable")
		},
		func(_ context.Context, _ *auth.Identity, _ string) (*rbac.Decision, error) {
			authorizeCalled = true
			return &rbac.Decision{Allowed: true}, nil
		},
		func(_ context.Context, _ string) ([]orchestrator.AgentInstance, error) {
			return nil, nil
		},
		func(_ context.Context, _ orchestrator.AgentInstance, _ string, _ []channels.ChannelConversationTurn, _ string) (string, error) {
			return "", nil
		},
		nil,
		nil,
		logger,
	)
	require.NotNil(t, exec)

	result := exec(context.Background(), testExecutionMessage())
	assert.Equal(t, channels.IngressDispatchFailed, result.Decision)
	assert.False(t, authorizeCalled)
	require.Len(t, logger.events, 1)
	assert.Equal(t, audit.ActionChannelActionDispatchFailed, logger.events[0].Action)
}

func TestNewChannelExecutor_IdentityMissingUserID(t *testing.T) {
	logger := &captureAuditLogger{}
	authorizeCalled := false

	exec := newChannelExecutor(
		func(_ context.Context, _ string) (*auth.Identity, error) {
			return &auth.Identity{
				UserID:   "   ",
				TenantID: "190f3a21-3b2c-42ce-b26e-2f448a58ec14",
			}, nil
		},
		func(_ context.Context, _ *auth.Identity, _ string) (*rbac.Decision, error) {
			authorizeCalled = true
			return &rbac.Decision{Allowed: true}, nil
		},
		func(_ context.Context, _ string) ([]orchestrator.AgentInstance, error) {
			return nil, nil
		},
		func(_ context.Context, _ orchestrator.AgentInstance, _ string, _ []channels.ChannelConversationTurn, _ string) (string, error) {
			return "", nil
		},
		nil,
		nil,
		logger,
	)
	require.NotNil(t, exec)

	result := exec(context.Background(), testExecutionMessage())
	assert.Equal(t, channels.IngressDispatchFailed, result.Decision)
	assert.False(t, authorizeCalled)
	require.Len(t, logger.events, 1)
	assert.Equal(t, audit.ActionChannelActionDispatchFailed, logger.events[0].Action)
}

func TestNewChannelExecutor_AuthorizeError(t *testing.T) {
	logger := &captureAuditLogger{}
	listCalled := false

	exec := newChannelExecutor(
		func(_ context.Context, _ string) (*auth.Identity, error) {
			return &auth.Identity{
				UserID:   "2f6a9b58-c56f-49d5-a06f-45b0145b9e1f",
				TenantID: "190f3a21-3b2c-42ce-b26e-2f448a58ec14",
			}, nil
		},
		func(_ context.Context, _ *auth.Identity, _ string) (*rbac.Decision, error) {
			return nil, errors.New("rbac backend down")
		},
		func(_ context.Context, _ string) ([]orchestrator.AgentInstance, error) {
			listCalled = true
			return nil, nil
		},
		func(_ context.Context, _ orchestrator.AgentInstance, _ string, _ []channels.ChannelConversationTurn, _ string) (string, error) {
			return "", nil
		},
		nil,
		nil,
		logger,
	)
	require.NotNil(t, exec)

	result := exec(context.Background(), testExecutionMessage())
	assert.Equal(t, channels.IngressDispatchFailed, result.Decision)
	assert.False(t, listCalled)
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
		func(_ context.Context, _ orchestrator.AgentInstance, _ string, _ []channels.ChannelConversationTurn, _ string) (string, error) {
			return "", nil
		},
		nil,
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

func TestNewChannelExecutor_SentinelError(t *testing.T) {
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
		func(_ context.Context, _ orchestrator.AgentInstance, _ string, _ []channels.ChannelConversationTurn, _ string) (string, error) {
			return "", nil
		},
		nil,
		func(_ context.Context, _, _, _ string) (sentinel.ScanResult, error) {
			return sentinel.ScanResult{}, errors.New("sentinel unavailable")
		},
		logger,
	)
	require.NotNil(t, exec)

	result := exec(context.Background(), testExecutionMessage())
	assert.Equal(t, channels.IngressDispatchFailed, result.Decision)
	assert.False(t, listCalled)
	require.Len(t, logger.events, 1)
	assert.Equal(t, audit.ActionChannelActionDispatchFailed, logger.events[0].Action)
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
		func(_ context.Context, _ orchestrator.AgentInstance, _ string, _ []channels.ChannelConversationTurn, _ string) (string, error) {
			dispatchCalled = true
			return "", nil
		},
		nil,
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
					UserID:       ptrString("2f6a9b58-c56f-49d5-a06f-45b0145b9e1f"),
					Status:       orchestrator.StatusRunning,
					VsockCID:     &sharedCID,
					DepartmentID: nil,
				},
				{
					ID:           "agent-dept-a",
					UserID:       ptrString("2f6a9b58-c56f-49d5-a06f-45b0145b9e1f"),
					Status:       orchestrator.StatusRunning,
					VsockCID:     &preferredCID,
					DepartmentID: &deptID,
				},
			}, nil
		},
		func(_ context.Context, agent orchestrator.AgentInstance, _ string, _ []channels.ChannelConversationTurn, _ string) (string, error) {
			dispatchCalled = true
			dispatchedAgentID = agent.ID
			return "agent response", nil
		},
		nil,
		nil,
		logger,
	)
	require.NotNil(t, exec)

	result := exec(context.Background(), testExecutionMessage())
	assert.Equal(t, channels.IngressExecuted, result.Decision)
	assert.Equal(t, "agent-dept-a", result.AgentID)
	assert.Equal(t, "agent response", result.ResponseContent)
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
				UserID:   ptrString("2f6a9b58-c56f-49d5-a06f-45b0145b9e1f"),
				Status:   orchestrator.StatusRunning,
				VsockCID: &cid,
			}}, nil
		},
		func(_ context.Context, _ orchestrator.AgentInstance, _ string, _ []channels.ChannelConversationTurn, _ string) (string, error) {
			return "", errors.New("downstream timeout")
		},
		nil,
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

func TestNewChannelExecutor_PassesPersistedUserContextToDispatch(t *testing.T) {
	logger := &captureAuditLogger{}
	cid := uint32(121)
	var capturedContext string

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
				ID:       "agent-ctx",
				UserID:   ptrString("2f6a9b58-c56f-49d5-a06f-45b0145b9e1f"),
				Status:   orchestrator.StatusRunning,
				VsockCID: &cid,
			}}, nil
		},
		func(_ context.Context, _ orchestrator.AgentInstance, _ string, _ []channels.ChannelConversationTurn, userContext string) (string, error) {
			capturedContext = userContext
			return "ok", nil
		},
		func(_ context.Context, _, _, _ string) (string, error) {
			return "persisted context", nil
		},
		nil,
		logger,
	)
	require.NotNil(t, exec)

	result := exec(context.Background(), testExecutionMessage())
	assert.Equal(t, channels.IngressExecuted, result.Decision)
	assert.Equal(t, "persisted context", capturedContext)
}

func TestNewChannelExecutor_ContextLookupErrorFailsDispatch(t *testing.T) {
	logger := &captureAuditLogger{}
	cid := uint32(122)
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
			return &rbac.Decision{Allowed: true}, nil
		},
		func(_ context.Context, _ string) ([]orchestrator.AgentInstance, error) {
			return []orchestrator.AgentInstance{{
				ID:       "agent-ctx",
				UserID:   ptrString("2f6a9b58-c56f-49d5-a06f-45b0145b9e1f"),
				Status:   orchestrator.StatusRunning,
				VsockCID: &cid,
			}}, nil
		},
		func(_ context.Context, _ orchestrator.AgentInstance, _ string, _ []channels.ChannelConversationTurn, _ string) (string, error) {
			dispatchCalled = true
			return "ok", nil
		},
		func(_ context.Context, _, _, _ string) (string, error) {
			return "", errors.New("context lookup unavailable")
		},
		nil,
		logger,
	)
	require.NotNil(t, exec)

	result := exec(context.Background(), testExecutionMessage())
	assert.Equal(t, channels.IngressDispatchFailed, result.Decision)
	assert.False(t, dispatchCalled)
}

func TestSelectChannelTargetAgent_FallbackToSharedAgent(t *testing.T) {
	sharedCID := uint32(100)
	deptCID := uint32(101)
	deptID := "dept-x"

	target := selectChannelTargetAgent([]orchestrator.AgentInstance{
		{
			ID:           "agent-wrong-dept",
			UserID:       ptrString("user-a"),
			Status:       orchestrator.StatusRunning,
			VsockCID:     &deptCID,
			DepartmentID: &deptID,
		},
		{
			ID:           "agent-shared",
			UserID:       ptrString("user-a"),
			Status:       orchestrator.StatusRunning,
			VsockCID:     &sharedCID,
			DepartmentID: nil,
		},
	}, "user-a", []string{"dept-y"})
	require.NotNil(t, target)
	assert.Equal(t, "agent-shared", target.ID)
}

func TestSelectChannelTargetAgent_DoesNotFallbackToOtherDepartment(t *testing.T) {
	deptCID := uint32(101)
	deptID := "dept-x"

	target := selectChannelTargetAgent([]orchestrator.AgentInstance{
		{
			ID:           "agent-wrong-dept",
			UserID:       ptrString("user-b"),
			Status:       orchestrator.StatusRunning,
			VsockCID:     &deptCID,
			DepartmentID: &deptID,
		},
	}, "user-a", []string{"dept-y"})
	assert.Nil(t, target)
}

func TestSelectChannelTargetAgent_EmptyRequestedUserPrefersSharedAgents(t *testing.T) {
	affineCID := uint32(201)
	sharedCID := uint32(202)

	target := selectChannelTargetAgent([]orchestrator.AgentInstance{
		{
			ID:       "agent-user-affine",
			UserID:   ptrString("user-a"),
			Status:   orchestrator.StatusRunning,
			VsockCID: &affineCID,
		},
		{
			ID:       "agent-shared",
			UserID:   nil,
			Status:   orchestrator.StatusRunning,
			VsockCID: &sharedCID,
		},
	}, "   ", nil)
	require.NotNil(t, target)
	assert.Equal(t, "agent-shared", target.ID)
}

func TestSelectChannelTargetAgent_EmptyRequestedUserNoSharedCandidateReturnsNil(t *testing.T) {
	affineCID := uint32(203)

	target := selectChannelTargetAgent([]orchestrator.AgentInstance{
		{
			ID:       "agent-user-affine",
			UserID:   ptrString("user-a"),
			Status:   orchestrator.StatusRunning,
			VsockCID: &affineCID,
		},
	}, "", nil)
	assert.Nil(t, target)
}

func TestDispatchChannelMessageToAgent_IgnoresMismatchedFrameID(t *testing.T) {
	transport := proxy.NewTCPTransport(9860)
	connPool := proxy.NewConnPool(transport)
	defer connPool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cid := uint32(42)
	ln, listenErr := transport.Listen(ctx, cid)
	require.NoError(t, listenErr)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		ac := proxy.NewAgentConn(conn)
		frame, err := ac.Recv(ctx)
		if err != nil {
			return
		}

		_ = ac.Send(ctx, proxy.Frame{
			Type:    proxy.TypeChunk,
			ID:      "other-request-id",
			Payload: json.RawMessage(`{"content":"wrong","done":true}`),
		})
		_ = ac.Send(ctx, proxy.Frame{
			Type:    proxy.TypeChunk,
			ID:      frame.ID,
			Payload: json.RawMessage(`{"content":"right","done":true}`),
		})
	}()

	agent := orchestrator.AgentInstance{
		ID:       "agent-1",
		Status:   orchestrator.StatusRunning,
		VsockCID: &cid,
	}

	response, err := dispatchChannelMessageToAgent(ctx, connPool, agent, "hello", nil, "", 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "right", response)
}

func TestDispatchChannelMessageToAgent_ConcurrentRequestsRouteByFrameID(t *testing.T) {
	transport := proxy.NewTCPTransport(9865)
	connPool := proxy.NewConnPool(transport)
	defer connPool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cid := uint32(43)
	ln, listenErr := transport.Listen(ctx, cid)
	require.NoError(t, listenErr)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		ac := proxy.NewAgentConn(conn)
		first, err := ac.Recv(ctx)
		if err != nil {
			return
		}
		second, err := ac.Recv(ctx)
		if err != nil {
			return
		}

		type payload struct {
			Content string `json:"content"`
		}
		var firstPayload payload
		var secondPayload payload
		_ = json.Unmarshal(first.Payload, &firstPayload)
		_ = json.Unmarshal(second.Payload, &secondPayload)

		firstReply := "second"
		if firstPayload.Content == "request-first" {
			firstReply = "first"
		}
		secondReply := "second"
		if secondPayload.Content == "request-first" {
			secondReply = "first"
		}

		_ = ac.Send(ctx, proxy.Frame{
			Type:    proxy.TypeChunk,
			ID:      second.ID,
			Payload: json.RawMessage(`{"content":"` + secondReply + `","done":true}`),
		})
		_ = ac.Send(ctx, proxy.Frame{
			Type:    proxy.TypeChunk,
			ID:      first.ID,
			Payload: json.RawMessage(`{"content":"` + firstReply + `","done":true}`),
		})
	}()

	agent := orchestrator.AgentInstance{
		ID:       "agent-concurrent",
		Status:   orchestrator.StatusRunning,
		VsockCID: &cid,
	}

	_, getErr := connPool.Get(ctx, agent.ID, cid)
	require.NoError(t, getErr)

	type result struct {
		name string
		resp string
		err  error
	}
	results := make(chan result, 2)

	go func() {
		resp, err := dispatchChannelMessageToAgent(ctx, connPool, agent, "request-first", nil, "", 5*time.Second)
		results <- result{name: "first", resp: resp, err: err}
	}()
	go func() {
		resp, err := dispatchChannelMessageToAgent(ctx, connPool, agent, "request-second", nil, "", 5*time.Second)
		results <- result{name: "second", resp: resp, err: err}
	}()

	var firstResp, secondResp string
	for i := 0; i < 2; i++ {
		res := <-results
		require.NoError(t, res.err)
		if res.name == "first" {
			firstResp = res.resp
		} else {
			secondResp = res.resp
		}
	}

	assert.Equal(t, "first", firstResp)
	assert.Equal(t, "second", secondResp)
}

func TestDispatchChannelMessageToAgent_IncludesConversationMessages(t *testing.T) {
	transport := proxy.NewTCPTransport(9870)
	connPool := proxy.NewConnPool(transport)
	defer connPool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cid := uint32(44)
	ln, listenErr := transport.Listen(ctx, cid)
	require.NoError(t, listenErr)
	defer ln.Close()

	payloadSeen := make(chan map[string]any, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		ac := proxy.NewAgentConn(conn)
		frame, err := ac.Recv(ctx)
		if err != nil {
			return
		}

		var payload map[string]any
		_ = json.Unmarshal(frame.Payload, &payload)
		payloadSeen <- payload

		_ = ac.Send(ctx, proxy.Frame{
			Type:    proxy.TypeChunk,
			ID:      frame.ID,
			Payload: json.RawMessage(`{"content":"ok","done":true}`),
		})
	}()

	agent := orchestrator.AgentInstance{
		ID:       "agent-history",
		Status:   orchestrator.StatusRunning,
		VsockCID: &cid,
	}

	history := []channels.ChannelConversationTurn{
		{RequestContent: "older request", ResponseContent: "older response"},
		{RequestContent: "recent request", ResponseContent: ""},
	}
	response, err := dispatchChannelMessageToAgent(ctx, connPool, agent, "latest request", history, "", 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "ok", response)

	payload := <-payloadSeen
	messagesRaw, ok := payload["messages"].([]any)
	require.True(t, ok)
	require.Len(t, messagesRaw, 4)

	first, ok := messagesRaw[0].(map[string]any)
	require.True(t, ok)
	second, ok := messagesRaw[1].(map[string]any)
	require.True(t, ok)
	third, ok := messagesRaw[2].(map[string]any)
	require.True(t, ok)
	fourth, ok := messagesRaw[3].(map[string]any)
	require.True(t, ok)

	assert.Equal(t, "user", first["role"])
	assert.Equal(t, "older request", first["content"])
	assert.Equal(t, "assistant", second["role"])
	assert.Equal(t, "older response", second["content"])
	assert.Equal(t, "user", third["role"])
	assert.Equal(t, "recent request", third["content"])
	assert.Equal(t, "user", fourth["role"])
	assert.Equal(t, "latest request", fourth["content"])
}

func TestDispatchChannelMessageToAgent_IncludesPersistedUserContextMessage(t *testing.T) {
	transport := proxy.NewTCPTransport(9872)
	connPool := proxy.NewConnPool(transport)
	defer connPool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cid := uint32(46)
	ln, listenErr := transport.Listen(ctx, cid)
	require.NoError(t, listenErr)
	defer ln.Close()

	payloadSeen := make(chan map[string]any, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		ac := proxy.NewAgentConn(conn)
		frame, err := ac.Recv(ctx)
		if err != nil {
			return
		}

		var payload map[string]any
		_ = json.Unmarshal(frame.Payload, &payload)
		payloadSeen <- payload

		_ = ac.Send(ctx, proxy.Frame{
			Type:    proxy.TypeChunk,
			ID:      frame.ID,
			Payload: json.RawMessage(`{"content":"ok","done":true}`),
		})
	}()

	agent := orchestrator.AgentInstance{
		ID:       "agent-context",
		Status:   orchestrator.StatusRunning,
		VsockCID: &cid,
	}

	response, err := dispatchChannelMessageToAgent(
		ctx,
		connPool,
		agent,
		"latest request",
		[]channels.ChannelConversationTurn{{RequestContent: "older request"}},
		"Persisted scouting context",
		5*time.Second,
	)
	require.NoError(t, err)
	assert.Equal(t, "ok", response)

	payload := <-payloadSeen
	messagesRaw, ok := payload["messages"].([]any)
	require.True(t, ok)
	require.Len(t, messagesRaw, 3)

	systemMessage, ok := messagesRaw[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "system", systemMessage["role"])
	assert.Contains(t, systemMessage["content"], "Persisted scouting context")
}

func TestDispatchChannelMessageToAgent_PreservesLegacyRoleContentFields(t *testing.T) {
	transport := proxy.NewTCPTransport(9871)
	connPool := proxy.NewConnPool(transport)
	defer connPool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cid := uint32(45)
	ln, listenErr := transport.Listen(ctx, cid)
	require.NoError(t, listenErr)
	defer ln.Close()

	payloadSeen := make(chan map[string]any, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		ac := proxy.NewAgentConn(conn)
		frame, err := ac.Recv(ctx)
		if err != nil {
			return
		}

		var payload map[string]any
		_ = json.Unmarshal(frame.Payload, &payload)
		payloadSeen <- payload

		_ = ac.Send(ctx, proxy.Frame{
			Type:    proxy.TypeChunk,
			ID:      frame.ID,
			Payload: json.RawMessage(`{"content":"ok","done":true}`),
		})
	}()

	agent := orchestrator.AgentInstance{
		ID:       "agent-legacy",
		Status:   orchestrator.StatusRunning,
		VsockCID: &cid,
	}

	response, err := dispatchChannelMessageToAgent(
		ctx,
		connPool,
		agent,
		"latest request",
		[]channels.ChannelConversationTurn{{RequestContent: "older request"}},
		"",
		5*time.Second,
	)
	require.NoError(t, err)
	assert.Equal(t, "ok", response)

	payload := <-payloadSeen
	assert.Equal(t, "user", payload["role"])
	assert.Equal(t, "latest request", payload["content"])

	messagesRaw, ok := payload["messages"].([]any)
	require.True(t, ok)
	require.Len(t, messagesRaw, 2)
}
