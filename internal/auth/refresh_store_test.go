package auth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

// createTestTenantAndUser inserts a tenant and user for refresh store tests.
func createTestTenantAndUser(t *testing.T, pool *database.Pool) (tenantID, userID string) {
	t.Helper()
	ctx := context.Background()

	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id",
		"Chelsea FC", "chelsea-fc",
	).Scan(&tenantID)
	require.NoError(t, err)

	err = pool.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, display_name, oidc_subject, oidc_issuer)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		tenantID, "scout@chelsea.com", "Scout A", "google-123", "https://accounts.google.com",
	).Scan(&userID)
	require.NoError(t, err)

	return tenantID, userID
}

func TestRefreshTokenStore_CreateFamily(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := auth.NewRefreshTokenStore(pool)
	tenantID, userID := createTestTenantAndUser(t, pool)

	tokenHash := auth.HashToken("some-jwt-string")
	familyID, err := store.CreateFamily(ctx, tenantID, userID, tokenHash)
	require.NoError(t, err)
	assert.NotEmpty(t, familyID)

	family, err := store.GetFamily(ctx, familyID, tenantID)
	require.NoError(t, err)
	assert.Equal(t, 1, family.CurrentGeneration)
	assert.Equal(t, tokenHash, family.CurrentTokenHash)
	assert.Nil(t, family.RevokedAt)
}

func TestRefreshTokenStore_CreateFamilyAndReturnID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := auth.NewRefreshTokenStore(pool)
	tenantID, userID := createTestTenantAndUser(t, pool)

	familyID, err := store.CreateFamilyAndReturnID(ctx, tenantID, userID)
	require.NoError(t, err)
	assert.NotEmpty(t, familyID)

	// Set initial hash
	tokenHash := auth.HashToken("final-jwt")
	err = store.SetInitialTokenHash(ctx, familyID, tenantID, tokenHash)
	require.NoError(t, err)

	family, err := store.GetFamily(ctx, familyID, tenantID)
	require.NoError(t, err)
	assert.Equal(t, tokenHash, family.CurrentTokenHash)
}

func TestRefreshTokenStore_RotateToken_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := auth.NewRefreshTokenStore(pool)
	tenantID, userID := createTestTenantAndUser(t, pool)

	oldHash := auth.HashToken("old-jwt")
	familyID, err := store.CreateFamily(ctx, tenantID, userID, oldHash)
	require.NoError(t, err)

	newHash := auth.HashToken("new-jwt")
	family, err := store.RotateToken(ctx, familyID, tenantID, oldHash, 1, newHash)
	require.NoError(t, err)
	assert.Equal(t, 2, family.CurrentGeneration)
	assert.Equal(t, newHash, family.CurrentTokenHash)
}

func TestRefreshTokenStore_RotateToken_ReuseDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := auth.NewRefreshTokenStore(pool)
	tenantID, userID := createTestTenantAndUser(t, pool)

	gen1Hash := auth.HashToken("gen1-jwt")
	familyID, err := store.CreateFamily(ctx, tenantID, userID, gen1Hash)
	require.NoError(t, err)

	// Legitimate rotation: gen1 -> gen2
	gen2Hash := auth.HashToken("gen2-jwt")
	_, err = store.RotateToken(ctx, familyID, tenantID, gen1Hash, 1, gen2Hash)
	require.NoError(t, err)

	// Attacker replays gen1 token (reuse!)
	_, err = store.RotateToken(ctx, familyID, tenantID, gen1Hash, 1, auth.HashToken("attacker-jwt"))
	assert.ErrorIs(t, err, auth.ErrTokenReuse)

	// Verify the entire family is now revoked
	family, err := store.GetFamily(ctx, familyID, tenantID)
	require.NoError(t, err)
	assert.NotNil(t, family.RevokedAt)

	// Legitimate user now also fails (family revoked)
	_, err = store.RotateToken(ctx, familyID, tenantID, gen2Hash, 2, auth.HashToken("legit-gen3"))
	assert.ErrorIs(t, err, auth.ErrFamilyRevoked)
}

func TestRefreshTokenStore_RotateToken_AlreadyRevoked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := auth.NewRefreshTokenStore(pool)
	tenantID, userID := createTestTenantAndUser(t, pool)

	tokenHash := auth.HashToken("some-jwt")
	familyID, err := store.CreateFamily(ctx, tenantID, userID, tokenHash)
	require.NoError(t, err)

	err = store.RevokeFamily(ctx, familyID, tenantID)
	require.NoError(t, err)

	_, err = store.RotateToken(ctx, familyID, tenantID, tokenHash, 1, auth.HashToken("new"))
	assert.ErrorIs(t, err, auth.ErrFamilyRevoked)
}

func TestRefreshTokenStore_RevokeAllForUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := auth.NewRefreshTokenStore(pool)
	tenantID, userID := createTestTenantAndUser(t, pool)

	fam1, err := store.CreateFamily(ctx, tenantID, userID, auth.HashToken("jwt-1"))
	require.NoError(t, err)
	fam2, err := store.CreateFamily(ctx, tenantID, userID, auth.HashToken("jwt-2"))
	require.NoError(t, err)

	err = store.RevokeAllForUser(ctx, userID, tenantID)
	require.NoError(t, err)

	family1, err := store.GetFamily(ctx, fam1, tenantID)
	require.NoError(t, err)
	assert.NotNil(t, family1.RevokedAt)

	family2, err := store.GetFamily(ctx, fam2, tenantID)
	require.NoError(t, err)
	assert.NotNil(t, family2.RevokedAt)
}

func TestRefreshTokenStore_GetFamily_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := auth.NewRefreshTokenStore(pool)

	_, err := store.GetFamily(ctx, "00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000000")
	assert.ErrorIs(t, err, auth.ErrFamilyNotFound)
}

func TestRefreshTokenStore_LegacyUpgrade_ReplayRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := auth.NewRefreshTokenStore(pool)
	tenantID, userID := createTestTenantAndUser(t, pool)

	legacyHash := auth.HashToken("legacy-jwt")

	// First upgrade succeeds
	familyID, err := store.CreateFamilyForLegacyUpgrade(ctx, tenantID, userID, legacyHash)
	require.NoError(t, err)
	assert.NotEmpty(t, familyID)

	// IsLegacyTokenUpgraded returns true
	upgraded, err := store.IsLegacyTokenUpgraded(ctx, userID, tenantID, legacyHash)
	require.NoError(t, err)
	assert.True(t, upgraded)

	// Different legacy token is not upgraded
	upgraded2, err := store.IsLegacyTokenUpgraded(ctx, userID, tenantID, auth.HashToken("other-jwt"))
	require.NoError(t, err)
	assert.False(t, upgraded2)
}

func TestHashToken_Deterministic(t *testing.T) {
	hash1 := auth.HashToken("same-input")
	hash2 := auth.HashToken("same-input")
	assert.Equal(t, hash1, hash2)
	assert.Len(t, hash1, 64) // SHA-256 hex = 64 chars
}

func TestHashToken_DifferentInputs(t *testing.T) {
	hash1 := auth.HashToken("input-a")
	hash2 := auth.HashToken("input-b")
	assert.NotEqual(t, hash1, hash2)
}
