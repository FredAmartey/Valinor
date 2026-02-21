package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
)

func newTestTokenService() *auth.TokenService {
	return auth.NewTokenService("test-signing-key-must-be-32-chars!!", "valinor", 24, 168)
}

func TestAuthMiddleware_ValidToken(t *testing.T) {
	tokenSvc := newTestTokenService()
	identity := &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
		Roles:    []string{"admin"},
	}

	token, err := tokenSvc.CreateAccessToken(identity)
	require.NoError(t, err)

	var gotIdentity *auth.Identity
	handler := auth.Middleware(tokenSvc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = auth.GetIdentity(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, gotIdentity)
	assert.Equal(t, "user-123", gotIdentity.UserID)
	assert.Equal(t, "tenant-456", gotIdentity.TenantID)
}

func TestAuthMiddleware_MissingToken(t *testing.T) {
	tokenSvc := newTestTokenService()

	handler := auth.Middleware(tokenSvc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var body map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, "missing authorization header", body["error"])
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	tokenSvc := newTestTokenService()

	handler := auth.Middleware(tokenSvc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_RefreshTokenRejected(t *testing.T) {
	tokenSvc := newTestTokenService()
	identity := &auth.Identity{UserID: "user-123", TenantID: "tenant-456"}

	// Create a refresh token (not an access token)
	refreshToken, err := tokenSvc.CreateRefreshToken(identity)
	require.NoError(t, err)

	handler := auth.Middleware(tokenSvc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called with refresh token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+refreshToken)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_DevModeAPIKey(t *testing.T) {
	tokenSvc := newTestTokenService()

	devIdentity := &auth.Identity{
		UserID:   "dev-user",
		TenantID: "dev-tenant",
		Roles:    []string{"org_admin"},
	}

	handler := auth.MiddlewareWithDevMode(tokenSvc, devIdentity)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := auth.GetIdentity(r.Context())
		assert.Equal(t, "dev-user", got.UserID)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer dev")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
