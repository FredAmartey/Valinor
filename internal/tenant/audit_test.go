package tenant

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valinor-ai/valinor/internal/audit"
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
