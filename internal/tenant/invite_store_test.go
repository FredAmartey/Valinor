package tenant_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/FredAmartey/heimdall/internal/platform/database"
	"github.com/FredAmartey/heimdall/internal/tenant"
)

// createTestUser inserts a user in the given tenant using the owner pool (bypasses RLS).
func createTestUser(t *testing.T, ctx context.Context, pool *database.Pool, tenantID, email string) string {
	t.Helper()
	var userID string
	err := pool.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, display_name) VALUES ($1, $2, $3) RETURNING id`,
		tenantID, email, "Test User",
	).Scan(&userID)
	require.NoError(t, err)
	return userID
}

func TestInviteStore_Create(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	inviteStore := tenant.NewInviteStore(pool)
	ctx := context.Background()

	tn, err := store.Create(ctx, "Invite Test Org", "invite-test-org")
	require.NoError(t, err)

	userID := createTestUser(t, ctx, pool, tn.ID, "inviter@example.com")

	inv, err := inviteStore.Create(ctx, tn.ID, userID, "standard_user", 24*time.Hour)
	require.NoError(t, err)
	assert.NotEmpty(t, inv.Code)
	assert.Equal(t, tn.ID, inv.TenantID)
	assert.Equal(t, "standard_user", inv.Role)
	assert.Nil(t, inv.UsedAt)
}

func TestInviteStore_GetByCode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	inviteStore := tenant.NewInviteStore(pool)
	ctx := context.Background()

	tn, err := store.Create(ctx, "Code Test Org", "code-test-org")
	require.NoError(t, err)

	userID := createTestUser(t, ctx, pool, tn.ID, "coder@example.com")

	inv, err := inviteStore.Create(ctx, tn.ID, userID, "standard_user", 24*time.Hour)
	require.NoError(t, err)

	found, err := inviteStore.GetByCode(ctx, inv.Code)
	require.NoError(t, err)
	assert.Equal(t, inv.ID, found.ID)

	_, err = inviteStore.GetByCode(ctx, "nonexistent")
	assert.ErrorIs(t, err, tenant.ErrInviteNotFound)
}

func TestInviteStore_ListByTenant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	inviteStore := tenant.NewInviteStore(pool)
	ctx := context.Background()

	tn, err := store.Create(ctx, "List Test Org", "list-test-org")
	require.NoError(t, err)

	userID := createTestUser(t, ctx, pool, tn.ID, "lister@example.com")

	_, err = inviteStore.Create(ctx, tn.ID, userID, "standard_user", 24*time.Hour)
	require.NoError(t, err)
	_, err = inviteStore.Create(ctx, tn.ID, userID, "dept_head", 48*time.Hour)
	require.NoError(t, err)

	invites, err := inviteStore.ListByTenant(ctx, tn.ID)
	require.NoError(t, err)
	assert.Len(t, invites, 2)
}

func TestInviteStore_Redeem(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	inviteStore := tenant.NewInviteStore(pool)
	ctx := context.Background()

	tn, err := store.Create(ctx, "Redeem Test Org", "redeem-test-org")
	require.NoError(t, err)

	creatorID := createTestUser(t, ctx, pool, tn.ID, "creator@example.com")
	redeemerID := createTestUser(t, ctx, pool, tn.ID, "redeemer@example.com")
	anotherID := createTestUser(t, ctx, pool, tn.ID, "another@example.com")

	inv, err := inviteStore.Create(ctx, tn.ID, creatorID, "standard_user", 24*time.Hour)
	require.NoError(t, err)

	redeemed, err := inviteStore.Redeem(ctx, inv.Code, redeemerID)
	require.NoError(t, err)
	assert.Equal(t, inv.ID, redeemed.ID)
	assert.Equal(t, tn.ID, redeemed.TenantID)

	// Double redeem fails
	_, err = inviteStore.Redeem(ctx, inv.Code, anotherID)
	assert.ErrorIs(t, err, tenant.ErrInviteUsed)
}

func TestInviteStore_RedeemExpired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	inviteStore := tenant.NewInviteStore(pool)
	ctx := context.Background()

	tn, err := store.Create(ctx, "Expired Test Org", "expired-test-org")
	require.NoError(t, err)

	creatorID := createTestUser(t, ctx, pool, tn.ID, "exp-creator@example.com")
	redeemerID := createTestUser(t, ctx, pool, tn.ID, "exp-redeemer@example.com")

	// Create invite with 1ms TTL — expires immediately
	inv, err := inviteStore.Create(ctx, tn.ID, creatorID, "standard_user", time.Millisecond)
	require.NoError(t, err)

	// Wait for expiry
	time.Sleep(5 * time.Millisecond)

	_, err = inviteStore.Redeem(ctx, inv.Code, redeemerID)
	assert.ErrorIs(t, err, tenant.ErrInviteExpired)
}

func TestInviteStore_Delete(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	inviteStore := tenant.NewInviteStore(pool)
	ctx := context.Background()

	tn, err := store.Create(ctx, "Delete Test Org", "delete-test-org")
	require.NoError(t, err)

	userID := createTestUser(t, ctx, pool, tn.ID, "deleter@example.com")

	inv, err := inviteStore.Create(ctx, tn.ID, userID, "standard_user", 24*time.Hour)
	require.NoError(t, err)

	err = inviteStore.Delete(ctx, inv.ID, tn.ID)
	require.NoError(t, err)

	// Delete again fails
	err = inviteStore.Delete(ctx, inv.ID, tn.ID)
	assert.ErrorIs(t, err, tenant.ErrInviteNotFound)
}
