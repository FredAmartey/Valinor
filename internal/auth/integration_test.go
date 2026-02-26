package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/rbac"
)

func TestIntegration_AuthRBACFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Setup: create tenant, user, role, assignment
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id",
		"Chelsea FC", "chelsea-fc",
	).Scan(&tenantID)
	require.NoError(t, err)

	var userID string
	err = pool.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, display_name, oidc_subject, oidc_issuer)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		tenantID, "scout@chelsea.com", "Scout A", "google-123", "https://accounts.google.com",
	).Scan(&userID)
	require.NoError(t, err)

	var roleID string
	err = pool.QueryRow(ctx,
		`INSERT INTO roles (tenant_id, name, permissions) VALUES ($1, $2, $3) RETURNING id`,
		tenantID, "standard_user", `["agents:read","agents:message"]`,
	).Scan(&roleID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx,
		"INSERT INTO user_roles (user_id, role_id, scope_type, scope_id) VALUES ($1, $2, $3, $4)",
		userID, roleID, "org", tenantID,
	)
	require.NoError(t, err)

	// Auth services
	tokenSvc := auth.NewTokenService("integration-test-key-must-be-32!!", "valinor", 24, 168)
	store := auth.NewStore(pool)

	// Load identity and create tokens
	identity, err := store.GetIdentityWithRoles(ctx, userID)
	require.NoError(t, err)

	accessToken, err := tokenSvc.CreateAccessToken(identity)
	require.NoError(t, err)

	refreshToken, err := tokenSvc.CreateRefreshToken(identity)
	require.NoError(t, err)

	// RBAC setup
	rbacEngine := rbac.NewEvaluator(nil)
	rbacEngine.RegisterRole(tenantID, "standard_user", []string{"agents:read", "agents:message"})

	// Test 1: Auth middleware accepts valid token
	t.Run("valid token passes auth", func(t *testing.T) {
		handler := auth.Middleware(tokenSvc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := auth.GetIdentity(r.Context())
			assert.Equal(t, userID, got.UserID)
			assert.Equal(t, tenantID, got.TenantID)
			assert.Contains(t, got.Roles, "standard_user")
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	// Test 2: RBAC allows permitted action
	t.Run("RBAC allows agents:read", func(t *testing.T) {
		decision, err := rbacEngine.Authorize(ctx, identity, "agents:read", "", "")
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	})

	// Test 3: RBAC denies unpermitted action
	t.Run("RBAC denies users:manage", func(t *testing.T) {
		decision, err := rbacEngine.Authorize(ctx, identity, "users:manage", "", "")
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})

	// Test 4: Refresh token flow (stateless, no RefreshStore)
	t.Run("refresh token produces new tokens", func(t *testing.T) {
		stateStore := auth.NewStateStore([]byte("integration-test-key-must-be-32!!"), 10*time.Minute)
		handler := auth.NewHandler(auth.HandlerConfig{TokenSvc: tokenSvc, Store: store, StateStore: stateStore})

		body := `{"refresh_token":"` + refreshToken + `"}`
		req := httptest.NewRequest(http.MethodPost, "/auth/token/refresh", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.HandleRefresh(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp["access_token"])
		// Validate the new access token is usable
		newIdentity, err := tokenSvc.ValidateToken(resp["access_token"])
		require.NoError(t, err)
		assert.Equal(t, userID, newIdentity.UserID)
		assert.Equal(t, "access", newIdentity.TokenType)
	})
}

func TestIntegration_RefreshTokenRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Setup tenant and user
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id",
		"Chelsea FC", "chelsea-fc",
	).Scan(&tenantID)
	require.NoError(t, err)

	var userID string
	err = pool.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, display_name, oidc_subject, oidc_issuer)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		tenantID, "scout@chelsea.com", "Scout A", "google-123", "https://accounts.google.com",
	).Scan(&userID)
	require.NoError(t, err)

	tokenSvc := auth.NewTokenService("integration-test-key-must-be-32!!", "valinor", 24, 168)
	authStore := auth.NewStore(pool)
	refreshStore := auth.NewRefreshTokenStore(pool)
	stateStore := auth.NewStateStore([]byte("integration-test-key-must-be-32!!"), 10*time.Minute)

	handler := auth.NewHandler(auth.HandlerConfig{
		TokenSvc:     tokenSvc,
		Store:        authStore,
		RefreshStore: refreshStore,
		StateStore:   stateStore,
	})

	identity, err := authStore.GetIdentityWithRoles(ctx, userID)
	require.NoError(t, err)

	// Helper to call HandleRefresh and parse response
	doRefresh := func(t *testing.T, refreshJWT string) (int, map[string]string) {
		t.Helper()
		body := `{"refresh_token":"` + refreshJWT + `"}`
		req := httptest.NewRequest(http.MethodPost, "/auth/token/refresh", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.HandleRefresh(w, req)

		var resp map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return w.Code, resp
	}

	t.Run("legacy token upgrade creates family and rejects replay", func(t *testing.T) {
		legacyToken, err := tokenSvc.CreateRefreshToken(identity)
		require.NoError(t, err)

		parsed, err := tokenSvc.ValidateToken(legacyToken)
		require.NoError(t, err)
		assert.Empty(t, parsed.FamilyID)

		code, resp := doRefresh(t, legacyToken)
		require.Equal(t, http.StatusOK, code)

		newParsed, err := tokenSvc.ValidateToken(resp["refresh_token"])
		require.NoError(t, err)
		assert.NotEmpty(t, newParsed.FamilyID)
		assert.Equal(t, 1, newParsed.Generation)

		// Replay of the same legacy token is rejected
		code2, resp2 := doRefresh(t, legacyToken)
		assert.Equal(t, http.StatusUnauthorized, code2)
		assert.Equal(t, "legacy token already upgraded", resp2["error"])
	})

	t.Run("normal rotation increments generation", func(t *testing.T) {
		familyID, err := refreshStore.CreateFamilyAndReturnID(ctx, tenantID, userID)
		require.NoError(t, err)

		genIdentity := *identity
		genIdentity.FamilyID = familyID
		genIdentity.Generation = 1

		gen1Token, err := tokenSvc.CreateRefreshToken(&genIdentity)
		require.NoError(t, err)

		err = refreshStore.SetInitialTokenHash(ctx, familyID, tenantID, auth.HashToken(gen1Token))
		require.NoError(t, err)

		// gen1 -> gen2
		code, resp := doRefresh(t, gen1Token)
		require.Equal(t, http.StatusOK, code)

		gen2Parsed, err := tokenSvc.ValidateToken(resp["refresh_token"])
		require.NoError(t, err)
		assert.Equal(t, familyID, gen2Parsed.FamilyID)
		assert.Equal(t, 2, gen2Parsed.Generation)

		// gen2 -> gen3
		code2, resp2 := doRefresh(t, resp["refresh_token"])
		require.Equal(t, http.StatusOK, code2)

		gen3Parsed, err := tokenSvc.ValidateToken(resp2["refresh_token"])
		require.NoError(t, err)
		assert.Equal(t, 3, gen3Parsed.Generation)
	})

	t.Run("reuse detection revokes family", func(t *testing.T) {
		familyID, err := refreshStore.CreateFamilyAndReturnID(ctx, tenantID, userID)
		require.NoError(t, err)

		genIdentity := *identity
		genIdentity.FamilyID = familyID
		genIdentity.Generation = 1

		gen1Token, err := tokenSvc.CreateRefreshToken(&genIdentity)
		require.NoError(t, err)

		err = refreshStore.SetInitialTokenHash(ctx, familyID, tenantID, auth.HashToken(gen1Token))
		require.NoError(t, err)

		// Legitimate refresh: gen1 -> gen2
		code, resp := doRefresh(t, gen1Token)
		require.Equal(t, http.StatusOK, code)
		gen2Token := resp["refresh_token"]

		// Attacker replays gen1 token
		code2, resp2 := doRefresh(t, gen1Token)
		assert.Equal(t, http.StatusUnauthorized, code2)
		assert.Equal(t, "token reuse detected", resp2["error"])

		// Legitimate user's gen2 token is also now invalid (family revoked)
		code3, resp3 := doRefresh(t, gen2Token)
		assert.Equal(t, http.StatusUnauthorized, code3)
		assert.Equal(t, "token family revoked", resp3["error"])
	})
}
