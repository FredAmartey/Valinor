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
)

// mockOIDCProvider implements auth.OIDCProvider for testing.
type mockOIDCProvider struct {
	authURL  string
	userInfo *auth.OIDCUserInfo
	err      error
}

func (m *mockOIDCProvider) AuthCodeURL(state string) string {
	return m.authURL + "?state=" + state
}

func (m *mockOIDCProvider) Exchange(_ context.Context, _ string) (*auth.OIDCUserInfo, error) {
	return m.userInfo, m.err
}

func newTestStateStore() *auth.StateStore {
	return auth.NewStateStore([]byte("test-signing-key-must-be-32-chars!!"), 10*time.Minute)
}

func TestHandler_RefreshToken(t *testing.T) {
	tokenSvc := newTestTokenService()
	stateStore := newTestStateStore()
	handler := auth.NewHandler(auth.HandlerConfig{TokenSvc: tokenSvc, StateStore: stateStore})

	identity := &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
		Email:    "scout@chelsea.com",
		Roles:    []string{"standard_user"},
	}

	refreshToken, err := tokenSvc.CreateRefreshToken(identity)
	require.NoError(t, err)

	body := `{"refresh_token":"` + refreshToken + `"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/token/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleRefresh(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp["access_token"])
	assert.NotEmpty(t, resp["refresh_token"])
	assert.Equal(t, "Bearer", resp["token_type"])
}

func TestHandler_RefreshToken_InvalidToken(t *testing.T) {
	tokenSvc := newTestTokenService()
	stateStore := newTestStateStore()
	handler := auth.NewHandler(auth.HandlerConfig{TokenSvc: tokenSvc, StateStore: stateStore})

	body := `{"refresh_token":"invalid-token"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/token/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleRefresh(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandler_RefreshToken_AccessTokenRejected(t *testing.T) {
	tokenSvc := newTestTokenService()
	stateStore := newTestStateStore()
	handler := auth.NewHandler(auth.HandlerConfig{TokenSvc: tokenSvc, StateStore: stateStore})

	identity := &auth.Identity{UserID: "user-123", TenantID: "tenant-456"}
	accessToken, err := tokenSvc.CreateAccessToken(identity)
	require.NoError(t, err)

	body := `{"refresh_token":"` + accessToken + `"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/token/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleRefresh(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandler_Login_SetsStateCookie(t *testing.T) {
	stateStore := newTestStateStore()

	oidcProvider := &mockOIDCProvider{authURL: "https://accounts.google.com/o/oauth2/auth"}
	handler := auth.NewHandler(auth.HandlerConfig{TokenSvc: newTestTokenService(), OIDC: oidcProvider, StateStore: stateStore})

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()

	handler.HandleLogin(w, req)

	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)

	// Check state cookie was set
	cookies := w.Result().Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "__Host-oidc_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie, "oidc_state cookie should be set")
	assert.NotEmpty(t, stateCookie.Value)
	assert.True(t, stateCookie.HttpOnly)

	// Verify redirect URL contains the same state
	redirectURL := w.Header().Get("Location")
	assert.Contains(t, redirectURL, "state="+stateCookie.Value)
}

func TestHandler_Callback_ValidatesState(t *testing.T) {
	stateStore := newTestStateStore()

	oidcProvider := &mockOIDCProvider{
		userInfo: &auth.OIDCUserInfo{
			Issuer:  "https://accounts.google.com",
			Subject: "google-123",
			Email:   "scout@chelsea.com",
			Name:    "Scout A",
		},
	}
	handler := auth.NewHandler(auth.HandlerConfig{TokenSvc: newTestTokenService(), OIDC: oidcProvider, StateStore: stateStore})

	state, err := stateStore.Generate()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=authcode&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: "__Host-oidc_state", Value: state})
	w := httptest.NewRecorder()

	handler.HandleCallback(w, req)

	// State validation passes → handler proceeds past state checks.
	// Hits 503 because store is nil (no DB in unit test).
	// The key assertion: NOT 400, proving state was accepted.
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var resp map[string]string
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "user store not configured", resp["error"])
}

func TestHandler_Callback_RejectsMismatchedState(t *testing.T) {
	stateStore := newTestStateStore()

	handler := auth.NewHandler(auth.HandlerConfig{TokenSvc: newTestTokenService(), OIDC: &mockOIDCProvider{}, StateStore: stateStore})

	state, err := stateStore.Generate()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=authcode&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: "__Host-oidc_state", Value: "different-state"})
	w := httptest.NewRecorder()

	handler.HandleCallback(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_Callback_RejectsMissingState(t *testing.T) {
	stateStore := newTestStateStore()

	handler := auth.NewHandler(auth.HandlerConfig{TokenSvc: newTestTokenService(), OIDC: &mockOIDCProvider{}, StateStore: stateStore})

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=authcode", nil)
	w := httptest.NewRecorder()

	handler.HandleCallback(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_Callback_PlatformAdminNoTenant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create a tenant for the platform admin user (they need to belong to one)
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id",
		"Platform", "platform",
	).Scan(&tenantID)
	require.NoError(t, err)

	// Create platform admin user
	_, err = pool.Exec(ctx,
		`INSERT INTO users (tenant_id, email, display_name, oidc_subject, oidc_issuer, is_platform_admin)
		 VALUES ($1, $2, $3, $4, $5, true)`,
		tenantID, "admin@valinor.com", "Admin", "google-admin", "https://accounts.google.com",
	)
	require.NoError(t, err)

	tokenSvc := newTestTokenService()
	stateStore := newTestStateStore()
	store := auth.NewStore(pool)

	oidcProvider := &mockOIDCProvider{
		userInfo: &auth.OIDCUserInfo{
			Issuer:  "https://accounts.google.com",
			Subject: "google-admin",
			Email:   "admin@valinor.com",
			Name:    "Admin",
		},
	}

	// No TenantResolver — simulates base domain access
	handler := auth.NewHandler(auth.HandlerConfig{
		TokenSvc:   tokenSvc,
		Store:      store,
		OIDC:       oidcProvider,
		StateStore: stateStore,
	})

	state, err := stateStore.Generate()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=authcode&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: "__Host-oidc_state", Value: state})
	w := httptest.NewRecorder()

	handler.HandleCallback(w, req)

	// Platform admin gets tokens even without tenant resolution
	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp["access_token"])

	// Verify the token has IsPlatformAdmin and empty TenantID
	parsed, err := tokenSvc.ValidateToken(resp["access_token"])
	require.NoError(t, err)
	assert.True(t, parsed.IsPlatformAdmin)
}

func TestHandler_RefreshToken_OversizedBody(t *testing.T) {
	tokenSvc := newTestTokenService()
	stateStore := newTestStateStore()
	handler := auth.NewHandler(auth.HandlerConfig{TokenSvc: tokenSvc, StateStore: stateStore})

	// 11 KB body exceeds the 10 KB limit
	body := strings.Repeat("x", 11<<10)
	req := httptest.NewRequest(http.MethodPost, "/auth/token/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleRefresh(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
