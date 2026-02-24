package proxy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

var (
	// ErrUserContextNotFound indicates no persisted context snapshot exists.
	ErrUserContextNotFound = errors.New("user context not found")
)

// UserContextStore persists and resolves per-user context snapshots.
type UserContextStore interface {
	UpsertUserContext(ctx context.Context, tenantID, agentID, userID, context string) error
	GetUserContext(ctx context.Context, tenantID, agentID, userID string) (string, error)
}

// DBUserContextStore stores user context snapshots in Postgres.
type DBUserContextStore struct {
	pool *database.Pool
}

// NewDBUserContextStore creates a DB-backed user context store.
func NewDBUserContextStore(pool *database.Pool) *DBUserContextStore {
	return &DBUserContextStore{pool: pool}
}

// UpsertUserContext writes or overwrites the latest context snapshot.
func (s *DBUserContextStore) UpsertUserContext(ctx context.Context, tenantID, agentID, userID, contextText string) error {
	if s == nil || s.pool == nil {
		return errors.New("context store is not configured")
	}
	tenantID = strings.TrimSpace(tenantID)
	agentID = strings.TrimSpace(agentID)
	userID = strings.TrimSpace(userID)
	contextText = strings.TrimSpace(contextText)
	if tenantID == "" {
		return errors.New("tenant id is required")
	}
	if agentID == "" {
		return errors.New("agent id is required")
	}
	if _, err := uuid.Parse(agentID); err != nil {
		return fmt.Errorf("invalid agent id: %w", err)
	}
	if userID == "" {
		return errors.New("user id is required")
	}
	if contextText == "" {
		return errors.New("context is required")
	}

	return database.WithTenantConnection(ctx, s.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		_, err := q.Exec(ctx,
			`INSERT INTO agent_context_snapshots (tenant_id, agent_id, user_id, context)
			 VALUES (current_setting('app.current_tenant_id', true)::UUID, $1::UUID, $2, $3)
			 ON CONFLICT (tenant_id, agent_id, user_id)
			 DO UPDATE SET context = EXCLUDED.context, updated_at = now()`,
			agentID, userID, contextText,
		)
		if err != nil {
			return fmt.Errorf("upserting user context: %w", err)
		}
		return nil
	})
}

// GetUserContext returns the latest persisted context snapshot for a user+agent.
func (s *DBUserContextStore) GetUserContext(ctx context.Context, tenantID, agentID, userID string) (string, error) {
	if s == nil || s.pool == nil {
		return "", errors.New("context store is not configured")
	}
	tenantID = strings.TrimSpace(tenantID)
	agentID = strings.TrimSpace(agentID)
	userID = strings.TrimSpace(userID)
	if tenantID == "" {
		return "", errors.New("tenant id is required")
	}
	if agentID == "" {
		return "", errors.New("agent id is required")
	}
	if _, err := uuid.Parse(agentID); err != nil {
		return "", fmt.Errorf("invalid agent id: %w", err)
	}
	if userID == "" {
		return "", errors.New("user id is required")
	}

	var contextText string
	err := database.WithTenantConnection(ctx, s.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		return q.QueryRow(ctx,
			`SELECT context
			 FROM agent_context_snapshots
			 WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
			   AND agent_id = $1::UUID
			   AND user_id = $2`,
			agentID, userID,
		).Scan(&contextText)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrUserContextNotFound
		}
		return "", fmt.Errorf("getting user context: %w", err)
	}
	return contextText, nil
}
