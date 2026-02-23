package database_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

func TestIsolationProof_CrossTenantConnectorReadDenied(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	rlsPool, superConnStr, cleanup := setupRLSTestDB(t)
	defer cleanup()

	tenantA, tenantB := seedTwoTenants(t, superConnStr)
	ctx := context.Background()

	superPool, err := database.Connect(ctx, superConnStr, 2)
	require.NoError(t, err)
	defer superPool.Close()

	var connectorBID string
	err = superPool.QueryRow(ctx, "SELECT id FROM connectors WHERE tenant_id = $1", tenantB).Scan(&connectorBID)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, rlsPool, tenantA, func(ctx context.Context, q database.Querier) error {
		var gotID string
		scanErr := q.QueryRow(ctx, "SELECT id FROM connectors WHERE id = $1", connectorBID).Scan(&gotID)
		assert.ErrorIs(t, scanErr, pgx.ErrNoRows)
		return nil
	})
	require.NoError(t, err)
}

func TestIsolationProof_CrossTenantUserRoleVisibilityDenied(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	rlsPool, superConnStr, cleanup := setupRLSTestDB(t)
	defer cleanup()

	tenantA, tenantB := seedTwoTenants(t, superConnStr)
	ctx := context.Background()

	err := database.WithTenantConnection(ctx, rlsPool, tenantA, func(ctx context.Context, q database.Querier) error {
		var count int
		queryErr := q.QueryRow(ctx, `
			SELECT COUNT(*) FROM user_roles ur
			JOIN users u ON u.id = ur.user_id
			WHERE u.tenant_id = $1
		`, tenantB).Scan(&count)
		require.NoError(t, queryErr)
		assert.Equal(t, 0, count)
		return nil
	})
	require.NoError(t, err)
}
