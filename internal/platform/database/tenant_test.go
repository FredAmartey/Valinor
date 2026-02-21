package database_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

func TestWithTenantConnection_SetsVariable(t *testing.T) {
	dbURL := os.Getenv("VALINOR_DATABASE_URL")
	if dbURL == "" {
		t.Skip("VALINOR_DATABASE_URL not set, skipping integration test")
	}

	ctx := context.Background()
	pool, err := database.Connect(ctx, dbURL, 5)
	require.NoError(t, err)
	defer pool.Close()

	err = database.WithTenantConnection(ctx, pool, "test-tenant-123", func(ctx context.Context, q database.Querier) error {
		var tenantID string
		scanErr := q.QueryRow(ctx, "SELECT current_setting('app.current_tenant_id')").Scan(&tenantID)
		if scanErr != nil {
			return scanErr
		}
		assert.Equal(t, "test-tenant-123", tenantID)
		return nil
	})
	require.NoError(t, err)
}

// Verify the Querier interface is satisfied by pgx types.
var _ database.Querier = (*pgx.Conn)(nil)
