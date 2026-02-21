package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier abstracts pgx query methods so callers can work with both
// pool connections and transactions.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// WithTenantConnection acquires a dedicated connection from the pool,
// sets the Postgres session variable for RLS, then calls fn.
// The tenant context is reset before the connection is released back
// to the pool, preventing cross-tenant data leaks via connection reuse.
func WithTenantConnection(ctx context.Context, pool *pgxpool.Pool, tenantID string, fn func(ctx context.Context, q Querier) error) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquiring connection: %w", err)
	}
	defer func() {
		// Reset tenant context before returning connection to pool.
		// Use background context since the request context may be canceled.
		_, _ = conn.Exec(context.Background(), "SELECT set_config('app.current_tenant_id', '', false)")
		conn.Release()
	}()

	// Set the tenant context for RLS policies
	_, err = conn.Exec(ctx, "SELECT set_config('app.current_tenant_id', $1, false)", tenantID)
	if err != nil {
		return fmt.Errorf("setting tenant context: %w", err)
	}

	return fn(ctx, conn)
}
