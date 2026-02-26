package tenant

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valinor-ai/valinor/internal/audit"
	"github.com/valinor-ai/valinor/internal/auth"
)

// captureLogger is a test helper that captures audit events.
type captureLogger struct {
	mu     sync.Mutex
	events []audit.Event
}

func (l *captureLogger) Log(_ context.Context, e audit.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *captureLogger) Close() error { return nil }

func (l *captureLogger) Events() []audit.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]audit.Event{}, l.events...)
}

func TestNewHandler_AcceptsAuditLogger(t *testing.T) {
	logger := &captureLogger{}
	h := NewHandler(nil, logger)
	assert.NotNil(t, h)
}

func TestNewDepartmentHandler_AcceptsAuditLogger(t *testing.T) {
	logger := &captureLogger{}
	h := NewDepartmentHandler(nil, nil, logger)
	assert.NotNil(t, h)
}

func TestNewUserHandler_AcceptsAuditLogger(t *testing.T) {
	logger := &captureLogger{}
	h := NewUserHandler(nil, nil, nil, logger)
	assert.NotNil(t, h)
}

func TestNewRoleHandler_AcceptsAuditLogger(t *testing.T) {
	logger := &captureLogger{}
	h := NewRoleHandler(nil, nil, nil, nil, nil, logger)
	assert.NotNil(t, h)
}

func TestActorIDFromContext_WithIdentity(t *testing.T) {
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		UserID:   "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
		TenantID: "t1",
	})
	actorID := audit.ActorIDFromContext(ctx)
	assert.NotNil(t, actorID)
	assert.Equal(t, "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", actorID.String())
}

func TestActorIDFromContext_NoIdentity(t *testing.T) {
	actorID := audit.ActorIDFromContext(context.Background())
	assert.Nil(t, actorID)
}

func TestActorIDFromContext_InvalidUserID(t *testing.T) {
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		UserID:   "not-a-uuid",
		TenantID: "t1",
	})
	actorID := audit.ActorIDFromContext(ctx)
	assert.Nil(t, actorID)
}
