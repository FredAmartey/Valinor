package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

// setupExchangeTestDB creates a disposable Postgres container for integration
// tests that live inside package auth (not auth_test). Mirrors setupTestDB in
// store_test.go but returns *pgxpool.Pool directly (no database.Pool alias
// indirection) so internal types like Store and TenantResolver can be used.
func setupExchangeTestDB(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()
	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("valinor_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2),
		),
	)
	require.NoError(t, err)

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	err = database.RunMigrations(connStr, "file://../../migrations")
	require.NoError(t, err)

	pool, err := database.Connect(ctx, connStr, 5)
	require.NoError(t, err)

	cleanup := func() {
		pool.Close()
		_ = container.Terminate(ctx)
	}

	return pool, cleanup
}

func setupExchangeTest(t *testing.T) (*Handler, *rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "test-kid"
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buildJWKS(t, kid, &priv.PublicKey))
	}))
	t.Cleanup(jwksSrv.Close)

	tokenSvc := NewTokenService("test-signing-key-must-be-32-chars!!", "valinor", 24, 168)

	h := NewHandler(HandlerConfig{
		TokenSvc:   tokenSvc,
		StateStore: NewStateStore([]byte("test-signing-key-must-be-32-chars!!"), 10*time.Minute),
	})
	h.idTokenValidator = NewIDTokenValidator(IDTokenValidatorConfig{
		JWKSUrl:  jwksSrv.URL,
		Issuer:   "https://clerk.example.com",
		Audience: "client_123",
		CacheTTL: 1 * time.Hour,
	})

	return h, priv, kid
}

func TestHandleExchange_MissingBody(t *testing.T) {
	h, _, _ := setupExchangeTest(t)

	req := httptest.NewRequest("POST", "/auth/exchange", nil)
	rec := httptest.NewRecorder()
	h.HandleExchange(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleExchange_InvalidToken(t *testing.T) {
	h, _, _ := setupExchangeTest(t)

	body, _ := json.Marshal(map[string]string{"id_token": "invalid.jwt.token"})
	req := httptest.NewRequest("POST", "/auth/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.HandleExchange(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleExchange_ValidToken_NoStore(t *testing.T) {
	h, priv, kid := setupExchangeTest(t)

	tok := signIDToken(t, priv, kid, jwt.MapClaims{
		"iss":   "https://clerk.example.com",
		"aud":   "client_123",
		"sub":   "user_abc",
		"email": "turgon@gondolin.fc",
		"name":  "Turgon",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})

	body, _ := json.Marshal(map[string]string{"id_token": tok})
	req := httptest.NewRequest("POST", "/auth/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.HandleExchange(rec, req)

	// Without a store, user lookup fails → 503
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleExchange_TenantSlug_NoOrigin verifies that a tenant_slug in the
// request body is used for tenant resolution when no Origin header is present.
// This reproduces the bug where server-side fetches (e.g. NextAuth callbacks)
// cannot resolve the tenant because they lack a browser Origin header.
func TestHandleExchange_TenantSlug_NoOrigin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupExchangeTestDB(t)
	defer cleanup()

	ctx := t.Context()

	// Create a tenant with a known slug.
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id",
		"Gondolin FC", "gondolin-fc",
	).Scan(&tenantID)
	require.NoError(t, err)

	// Create a user linked via OIDC subject.
	_, err = pool.Exec(ctx,
		`INSERT INTO users (tenant_id, email, display_name, oidc_subject, oidc_issuer)
		 VALUES ($1, $2, $3, $4, $5)`,
		tenantID, "turgon@gondolin.fc", "Turgon", "user_abc", "https://clerk.example.com",
	)
	require.NoError(t, err)

	// Set up handler with TenantResolver and Store but NO Origin header.
	h, priv, kid := setupExchangeTest(t)
	h.store = NewStore(pool)
	h.tenantResolver = NewTenantResolver(pool, "valinor.example.com")

	tok := signIDToken(t, priv, kid, jwt.MapClaims{
		"iss":   "https://clerk.example.com",
		"aud":   "client_123",
		"sub":   "user_abc",
		"email": "turgon@gondolin.fc",
		"name":  "Turgon",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})

	// Send tenant_slug in the body, no Origin header.
	body, _ := json.Marshal(map[string]string{
		"id_token":    tok,
		"tenant_slug": "gondolin-fc",
	})
	req := httptest.NewRequest("POST", "/auth/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Deliberately NO Origin header.
	rec := httptest.NewRecorder()
	h.HandleExchange(rec, req)

	// Should succeed — tenant resolved via slug, user found.
	assert.Equal(t, http.StatusOK, rec.Code, "expected 200 when tenant_slug is provided; got body: %s", rec.Body.String())

	var resp devLoginResponse
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.Equal(t, tenantID, resp.User.TenantID)
}

func TestHandleExchange_NotConfigured(t *testing.T) {
	tokenSvc := NewTokenService("test-signing-key-must-be-32-chars!!", "valinor", 24, 168)
	h := NewHandler(HandlerConfig{
		TokenSvc:   tokenSvc,
		StateStore: NewStateStore([]byte("test-signing-key-must-be-32-chars!!"), 10*time.Minute),
	})
	// No idTokenValidator set

	body, _ := json.Marshal(map[string]string{"id_token": "some.jwt.token"})
	req := httptest.NewRequest("POST", "/auth/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.HandleExchange(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
