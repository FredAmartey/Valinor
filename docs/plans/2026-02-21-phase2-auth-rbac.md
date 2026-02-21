# Phase 2: Auth + RBAC — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add OAuth2/OIDC authentication, JWT issuance/validation, and hybrid RBAC (roles + resource policies) enforcement so every API request is authenticated and authorized.

**Architecture:** Auth module handles OIDC login flow and JWT lifecycle. RBAC module evaluates permissions on every request via middleware. Both integrate into the existing server via a Dependencies struct. Dev mode allows API key auth for local development without an OIDC provider.

**Tech Stack:** `github.com/coreos/go-oidc/v3`, `github.com/golang-jwt/jwt/v5`, existing pgx/v5 pool

**Builds on:** Phase 1 foundation — `config.Load()`, `database.Connect()`, `server.New()`, `middleware.*`, `telemetry.*`

**Design Doc:** `docs/plans/2026-02-21-valinor-design.md`

---

### Task 1: Extend Config for Auth + RBAC Settings

**Files:**
- Modify: `internal/platform/config/config.go`
- Modify: `internal/platform/config/config_test.go`
- Modify: `config.yaml`

**Step 1: Write the failing test**

Add to `internal/platform/config/config_test.go`:
```go
func TestLoad_AuthDefaults(t *testing.T) {
	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, false, cfg.Auth.DevMode)
	assert.Equal(t, "valinor", cfg.Auth.JWT.Issuer)
	assert.Equal(t, 24, cfg.Auth.JWT.ExpiryHours)
	assert.Equal(t, 168, cfg.Auth.JWT.RefreshExpiryHours)
}

func TestLoad_AuthEnvOverrides(t *testing.T) {
	os.Setenv("VALINOR_AUTH_DEVMODE", "true")
	os.Setenv("VALINOR_AUTH_OIDC_ISSUERURL", "https://accounts.google.com")
	os.Setenv("VALINOR_AUTH_OIDC_CLIENTID", "test-client-id")
	os.Setenv("VALINOR_AUTH_OIDC_CLIENTSECRET", "test-secret")
	os.Setenv("VALINOR_AUTH_JWT_SIGNINGKEY", "super-secret-key-at-least-32-chars!!")
	defer func() {
		os.Unsetenv("VALINOR_AUTH_DEVMODE")
		os.Unsetenv("VALINOR_AUTH_OIDC_ISSUERURL")
		os.Unsetenv("VALINOR_AUTH_OIDC_CLIENTID")
		os.Unsetenv("VALINOR_AUTH_OIDC_CLIENTSECRET")
		os.Unsetenv("VALINOR_AUTH_JWT_SIGNINGKEY")
	}()

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.True(t, cfg.Auth.DevMode)
	assert.Equal(t, "https://accounts.google.com", cfg.Auth.OIDC.IssuerURL)
	assert.Equal(t, "test-client-id", cfg.Auth.OIDC.ClientID)
	assert.Equal(t, "test-secret", cfg.Auth.OIDC.ClientSecret)
	assert.Equal(t, "super-secret-key-at-least-32-chars!!", cfg.Auth.JWT.SigningKey)
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/platform/config/ -v -run TestLoad_Auth
```
Expected: FAIL — `cfg.Auth` doesn't exist.

**Step 3: Add auth config types**

Add to `internal/platform/config/config.go` — extend the `Config` struct and add new types:
```go
type Config struct {
	Server   ServerConfig   `koanf:"server"`
	Database DatabaseConfig `koanf:"database"`
	Log      LogConfig      `koanf:"log"`
	Auth     AuthConfig     `koanf:"auth"`
}

type AuthConfig struct {
	DevMode bool       `koanf:"devmode"`
	OIDC    OIDCConfig `koanf:"oidc"`
	JWT     JWTConfig  `koanf:"jwt"`
}

type OIDCConfig struct {
	IssuerURL    string `koanf:"issuerurl"`
	ClientID     string `koanf:"clientid"`
	ClientSecret string `koanf:"clientsecret"`
	RedirectURL  string `koanf:"redirecturl"`
}

type JWTConfig struct {
	SigningKey         string `koanf:"signingkey"`
	Issuer             string `koanf:"issuer"`
	ExpiryHours        int    `koanf:"expiryhours"`
	RefreshExpiryHours int    `koanf:"refreshexpiryhours"`
}
```

Add defaults in the `Load` function's confmap:
```go
"auth.devmode":                false,
"auth.jwt.issuer":             "valinor",
"auth.jwt.expiryhours":        24,
"auth.jwt.refreshexpiryhours": 168,
"auth.oidc.redirecturl":       "http://localhost:8080/auth/callback",
```

**Step 4: Run tests to verify they pass**

```bash
go test ./internal/platform/config/ -v
```
Expected: PASS (all tests including new auth tests).

**Step 5: Update config.yaml**

Add auth section to `config.yaml`:
```yaml
auth:
  devmode: true  # Set to false in production
  oidc:
    issuerurl: ""
    clientid: ""
    clientsecret: ""
    redirecturl: "http://localhost:8080/auth/callback"
  jwt:
    signingkey: "dev-signing-key-change-in-production-must-be-32-chars"
    issuer: "valinor"
    expiryhours: 24
    refreshexpiryhours: 168
```

**Step 6: Commit**

```bash
git add internal/platform/config/ config.yaml
git commit -m "feat(auth): extend config with auth, OIDC, and JWT settings"
```

---

### Task 2: JWT Token Service

**Files:**
- Create: `internal/auth/auth.go` (Service interface)
- Create: `internal/auth/token.go` (JWT implementation)
- Create: `internal/auth/token_test.go`

**Step 1: Write the failing test**

Create `internal/auth/token_test.go`:
```go
package auth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
)

func TestTokenService_CreateAndValidate(t *testing.T) {
	svc := auth.NewTokenService("test-signing-key-must-be-32-chars!!", "valinor", 24, 168)

	identity := &auth.Identity{
		UserID:      "user-123",
		TenantID:    "tenant-456",
		Email:       "scout@chelsea.com",
		DisplayName: "Scout A",
		Roles:       []string{"standard_user"},
		Departments: []string{"dept-scouting"},
	}

	token, err := svc.CreateAccessToken(identity)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Validate the token
	got, err := svc.ValidateToken(token)
	require.NoError(t, err)

	assert.Equal(t, identity.UserID, got.UserID)
	assert.Equal(t, identity.TenantID, got.TenantID)
	assert.Equal(t, identity.Email, got.Email)
	assert.Equal(t, identity.Roles, got.Roles)
	assert.Equal(t, identity.Departments, got.Departments)
}

func TestTokenService_CreateRefreshToken(t *testing.T) {
	svc := auth.NewTokenService("test-signing-key-must-be-32-chars!!", "valinor", 24, 168)

	identity := &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
	}

	refreshToken, err := svc.CreateRefreshToken(identity)
	require.NoError(t, err)
	assert.NotEmpty(t, refreshToken)

	got, err := svc.ValidateToken(refreshToken)
	require.NoError(t, err)
	assert.Equal(t, "user-123", got.UserID)
	assert.Equal(t, "refresh", got.TokenType)
}

func TestTokenService_ExpiredToken(t *testing.T) {
	svc := auth.NewTokenService("test-signing-key-must-be-32-chars!!", "valinor", 0, 0) // 0 hours = expires immediately

	identity := &auth.Identity{UserID: "user-123", TenantID: "tenant-456"}

	token, err := svc.CreateAccessToken(identity)
	require.NoError(t, err)

	// Token should be expired
	time.Sleep(time.Second)
	_, err = svc.ValidateToken(token)
	assert.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrTokenExpired)
}

func TestTokenService_InvalidSignature(t *testing.T) {
	svc1 := auth.NewTokenService("signing-key-one-must-be-32-chars!!", "valinor", 24, 168)
	svc2 := auth.NewTokenService("signing-key-two-must-be-32-chars!!", "valinor", 24, 168)

	identity := &auth.Identity{UserID: "user-123", TenantID: "tenant-456"}

	token, err := svc1.CreateAccessToken(identity)
	require.NoError(t, err)

	_, err = svc2.ValidateToken(token)
	assert.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrTokenInvalid)
}

func TestTokenService_MalformedToken(t *testing.T) {
	svc := auth.NewTokenService("test-signing-key-must-be-32-chars!!", "valinor", 24, 168)

	_, err := svc.ValidateToken("not.a.jwt")
	assert.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrTokenInvalid)
}
```

**Step 2: Run test to verify it fails**

```bash
go get github.com/golang-jwt/jwt/v5
go test ./internal/auth/ -v
```
Expected: FAIL — package doesn't exist.

**Step 3: Create auth service interface**

Create `internal/auth/auth.go`:
```go
package auth

import (
	"context"
	"errors"
)

var (
	ErrTokenExpired  = errors.New("token expired")
	ErrTokenInvalid  = errors.New("token invalid")
	ErrUserNotFound  = errors.New("user not found")
	ErrUnauthorized  = errors.New("unauthorized")
)

// Identity represents an authenticated user's claims.
type Identity struct {
	UserID      string   `json:"user_id"`
	TenantID    string   `json:"tenant_id"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Roles       []string `json:"roles"`
	Departments []string `json:"departments"`
	TokenType   string   `json:"token_type"` // "access" or "refresh"
}

// Service defines the authentication interface.
type Service interface {
	// CreateAccessToken creates a JWT access token for the given identity.
	CreateAccessToken(identity *Identity) (string, error)
	// CreateRefreshToken creates a JWT refresh token for the given identity.
	CreateRefreshToken(identity *Identity) (string, error)
	// ValidateToken validates a JWT and returns the identity.
	ValidateToken(tokenString string) (*Identity, error)
	// GetIdentityByOIDC looks up a user by OIDC issuer and subject.
	GetIdentityByOIDC(ctx context.Context, issuer, subject string) (*Identity, error)
}
```

**Step 4: Implement JWT token service**

Create `internal/auth/token.go`:
```go
package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type valinorClaims struct {
	jwt.RegisteredClaims
	UserID      string   `json:"uid"`
	TenantID    string   `json:"tid"`
	Email       string   `json:"email,omitempty"`
	DisplayName string   `json:"name,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Departments []string `json:"depts,omitempty"`
	TokenType   string   `json:"type"`
}

// TokenService handles JWT creation and validation.
type TokenService struct {
	signingKey         []byte
	issuer             string
	expiryHours        int
	refreshExpiryHours int
}

func NewTokenService(signingKey, issuer string, expiryHours, refreshExpiryHours int) *TokenService {
	return &TokenService{
		signingKey:         []byte(signingKey),
		issuer:             issuer,
		expiryHours:        expiryHours,
		refreshExpiryHours: refreshExpiryHours,
	}
}

func (s *TokenService) CreateAccessToken(identity *Identity) (string, error) {
	return s.createToken(identity, "access", s.expiryHours)
}

func (s *TokenService) CreateRefreshToken(identity *Identity) (string, error) {
	return s.createToken(identity, "refresh", s.refreshExpiryHours)
}

func (s *TokenService) createToken(identity *Identity, tokenType string, expiryHours int) (string, error) {
	now := time.Now()

	claims := valinorClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   identity.UserID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(expiryHours) * time.Hour)),
		},
		UserID:      identity.UserID,
		TenantID:    identity.TenantID,
		Email:       identity.Email,
		DisplayName: identity.DisplayName,
		Roles:       identity.Roles,
		Departments: identity.Departments,
		TokenType:   tokenType,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.signingKey)
}

func (s *TokenService) ValidateToken(tokenString string) (*Identity, error) {
	token, err := jwt.ParseWithClaims(tokenString, &valinorClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.signingKey, nil
	})

	if err != nil {
		if isExpiredErr(err) {
			return nil, fmt.Errorf("%w: %v", ErrTokenExpired, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	claims, ok := token.Claims.(*valinorClaims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}

	return &Identity{
		UserID:      claims.UserID,
		TenantID:    claims.TenantID,
		Email:       claims.Email,
		DisplayName: claims.DisplayName,
		Roles:       claims.Roles,
		Departments: claims.Departments,
		TokenType:   claims.TokenType,
	}, nil
}

func isExpiredErr(err error) bool {
	// jwt/v5 wraps expiration errors
	return err != nil && (fmt.Sprintf("%v", err) != "" && containsExpired(err))
}

func containsExpired(err error) bool {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if _, ok := e.(*jwt.TokenExpiredError); ok {
			return true
		}
	}
	// Fallback: check string
	return false
}
```

Note: The `isExpiredErr` helper may need adjustment. A cleaner approach with jwt/v5:

Replace `isExpiredErr` and `containsExpired` with:
```go
func isExpiredErr(err error) bool {
	return errors.Is(err, jwt.ErrTokenExpired)
}
```

Remove the `containsExpired` function.

**Step 5: Run tests to verify they pass**

```bash
go test ./internal/auth/ -v
```
Expected: PASS (5 tests).

**Step 6: Commit**

```bash
git add internal/auth/ go.mod go.sum
git commit -m "feat(auth): add JWT token service with create/validate/refresh"
```

---

### Task 3: Auth Middleware

**Files:**
- Create: `internal/auth/middleware.go`
- Create: `internal/auth/middleware_test.go`

**Step 1: Write the failing test**

Create `internal/auth/middleware_test.go`:
```go
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
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/auth/ -v -run TestAuthMiddleware
```
Expected: FAIL — Middleware doesn't exist.

**Step 3: Implement auth middleware**

Create `internal/auth/middleware.go`:
```go
package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type identityContextKey struct{}

// Middleware returns HTTP middleware that validates JWT access tokens.
func Middleware(tokenSvc *TokenService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := extractBearerToken(r)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, err.Error())
				return
			}

			identity, err := tokenSvc.ValidateToken(token)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "invalid token")
				return
			}

			// Reject refresh tokens on non-refresh endpoints
			if identity.TokenType != "access" {
				writeAuthError(w, http.StatusUnauthorized, "access token required")
				return
			}

			ctx := context.WithValue(r.Context(), identityContextKey{}, identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// MiddlewareWithDevMode returns auth middleware that also accepts "Bearer dev" in dev mode.
func MiddlewareWithDevMode(tokenSvc *TokenService, devIdentity *Identity) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := extractBearerToken(r)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, err.Error())
				return
			}

			// Dev mode: accept "dev" as token
			if token == "dev" && devIdentity != nil {
				ctx := context.WithValue(r.Context(), identityContextKey{}, devIdentity)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			identity, err := tokenSvc.ValidateToken(token)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "invalid token")
				return
			}

			if identity.TokenType != "access" {
				writeAuthError(w, http.StatusUnauthorized, "access token required")
				return
			}

			ctx := context.WithValue(r.Context(), identityContextKey{}, identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetIdentity retrieves the authenticated identity from the request context.
func GetIdentity(ctx context.Context) *Identity {
	identity, _ := ctx.Value(identityContextKey{}).(*Identity)
	return identity
}

func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", ErrUnauthorized
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", ErrUnauthorized
	}

	return parts[1], nil
}

func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
```

Note: Update `extractBearerToken` error message — the tests expect "missing authorization header":
```go
func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return parts[1], nil
}
```

Add `"fmt"` to the imports.

**Step 4: Run tests to verify they pass**

```bash
go test ./internal/auth/ -v
```
Expected: PASS (all 10 tests — 5 token + 5 middleware).

**Step 5: Commit**

```bash
git add internal/auth/middleware.go internal/auth/middleware_test.go
git commit -m "feat(auth): add auth middleware with JWT validation and dev mode"
```

---

### Task 4: User Store (Database Operations for Auth)

**Files:**
- Create: `internal/auth/store.go`
- Create: `internal/auth/store_test.go`

**Step 1: Write the failing test**

Create `internal/auth/store_test.go`:
```go
package auth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

func setupTestDB(t *testing.T) (*database.Pool, func()) {
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

	// Run migrations
	err = database.RunMigrations(connStr, "file:///Users/fred/Documents/Valinor/migrations")
	require.NoError(t, err)

	pool, err := database.Connect(ctx, connStr, 5)
	require.NoError(t, err)

	cleanup := func() {
		pool.Close()
		container.Terminate(ctx)
	}

	return pool, cleanup
}

func TestStore_FindOrCreateByOIDC_NewUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := auth.NewStore(pool)
	ctx := context.Background()

	// First, create a tenant
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id",
		"Chelsea FC", "chelsea-fc",
	).Scan(&tenantID)
	require.NoError(t, err)

	// Find or create user by OIDC
	identity, created, err := store.FindOrCreateByOIDC(ctx, auth.OIDCUserInfo{
		Issuer:  "https://accounts.google.com",
		Subject: "google-123",
		Email:   "scout@chelsea.com",
		Name:    "Scout A",
	}, tenantID)
	require.NoError(t, err)

	assert.True(t, created)
	assert.NotEmpty(t, identity.UserID)
	assert.Equal(t, tenantID, identity.TenantID)
	assert.Equal(t, "scout@chelsea.com", identity.Email)
	assert.Equal(t, "Scout A", identity.DisplayName)
}

func TestStore_FindOrCreateByOIDC_ExistingUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := auth.NewStore(pool)
	ctx := context.Background()

	// Create tenant
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id",
		"Chelsea FC", "chelsea-fc",
	).Scan(&tenantID)
	require.NoError(t, err)

	userInfo := auth.OIDCUserInfo{
		Issuer:  "https://accounts.google.com",
		Subject: "google-123",
		Email:   "scout@chelsea.com",
		Name:    "Scout A",
	}

	// Create user first time
	identity1, created1, err := store.FindOrCreateByOIDC(ctx, userInfo, tenantID)
	require.NoError(t, err)
	assert.True(t, created1)

	// Find same user second time
	identity2, created2, err := store.FindOrCreateByOIDC(ctx, userInfo, tenantID)
	require.NoError(t, err)
	assert.False(t, created2)
	assert.Equal(t, identity1.UserID, identity2.UserID)
}

func TestStore_GetIdentityWithRoles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := auth.NewStore(pool)
	ctx := context.Background()

	// Setup: tenant, user, role, assignment
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id",
		"Chelsea FC", "chelsea-fc",
	).Scan(&tenantID)
	require.NoError(t, err)

	var userID string
	err = pool.QueryRow(ctx,
		"INSERT INTO users (tenant_id, email, display_name, oidc_subject, oidc_issuer) VALUES ($1, $2, $3, $4, $5) RETURNING id",
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

	// Create a department and assign user
	var deptID string
	err = pool.QueryRow(ctx,
		"INSERT INTO departments (tenant_id, name) VALUES ($1, $2) RETURNING id",
		tenantID, "Scouting",
	).Scan(&deptID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx,
		"INSERT INTO user_departments (user_id, department_id) VALUES ($1, $2)",
		userID, deptID,
	)
	require.NoError(t, err)

	// Get full identity
	identity, err := store.GetIdentityWithRoles(ctx, userID)
	require.NoError(t, err)

	assert.Equal(t, userID, identity.UserID)
	assert.Equal(t, tenantID, identity.TenantID)
	assert.Equal(t, "scout@chelsea.com", identity.Email)
	assert.Contains(t, identity.Roles, "standard_user")
	assert.Contains(t, identity.Departments, deptID)
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/auth/ -v -run TestStore -count=1
```
Expected: FAIL — Store doesn't exist.

**Step 3: Implement store**

Create `internal/auth/store.go`:
```go
package auth

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OIDCUserInfo represents user info returned from an OIDC provider.
type OIDCUserInfo struct {
	Issuer  string
	Subject string
	Email   string
	Name    string
}

// Store handles user-related database operations for authentication.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// FindOrCreateByOIDC finds a user by OIDC credentials or creates a new one.
// Returns the identity, whether the user was created, and any error.
func (s *Store) FindOrCreateByOIDC(ctx context.Context, info OIDCUserInfo, defaultTenantID string) (*Identity, bool, error) {
	// Try to find existing user
	var userID, tenantID, email, displayName string
	err := s.pool.QueryRow(ctx,
		"SELECT id, tenant_id, email, COALESCE(display_name, '') FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2",
		info.Issuer, info.Subject,
	).Scan(&userID, &tenantID, &email, &displayName)

	if err == nil {
		// User exists, fetch full identity
		identity, err := s.GetIdentityWithRoles(ctx, userID)
		if err != nil {
			return nil, false, fmt.Errorf("getting identity: %w", err)
		}
		return identity, false, nil
	}

	if err != pgx.ErrNoRows {
		return nil, false, fmt.Errorf("querying user: %w", err)
	}

	// User doesn't exist, create one
	err = s.pool.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, display_name, oidc_issuer, oidc_subject)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id`,
		defaultTenantID, info.Email, info.Name, info.Issuer, info.Subject,
	).Scan(&userID)
	if err != nil {
		return nil, false, fmt.Errorf("creating user: %w", err)
	}

	return &Identity{
		UserID:      userID,
		TenantID:    defaultTenantID,
		Email:       info.Email,
		DisplayName: info.Name,
	}, true, nil
}

// GetIdentityWithRoles fetches a user's full identity including roles and departments.
func (s *Store) GetIdentityWithRoles(ctx context.Context, userID string) (*Identity, error) {
	// Get user base info
	var tenantID, email, displayName string
	err := s.pool.QueryRow(ctx,
		"SELECT tenant_id, email, COALESCE(display_name, '') FROM users WHERE id = $1",
		userID,
	).Scan(&tenantID, &email, &displayName)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("querying user: %w", err)
	}

	// Get role names
	rows, err := s.pool.Query(ctx,
		`SELECT r.name FROM roles r
		 JOIN user_roles ur ON ur.role_id = r.id
		 WHERE ur.user_id = $1`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying roles: %w", err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scanning role: %w", err)
		}
		roles = append(roles, name)
	}

	// Get department IDs
	deptRows, err := s.pool.Query(ctx,
		"SELECT department_id FROM user_departments WHERE user_id = $1",
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying departments: %w", err)
	}
	defer deptRows.Close()

	var departments []string
	for deptRows.Next() {
		var deptID string
		if err := deptRows.Scan(&deptID); err != nil {
			return nil, fmt.Errorf("scanning department: %w", err)
		}
		departments = append(departments, deptID)
	}

	return &Identity{
		UserID:      userID,
		TenantID:    tenantID,
		Email:       email,
		DisplayName: displayName,
		Roles:       roles,
		Departments: departments,
		TokenType:   "access",
	}, nil
}
```

**Step 4: Run tests to verify they pass**

```bash
go test ./internal/auth/ -v -count=1
```
Expected: PASS (all tests).

**Step 5: Commit**

```bash
git add internal/auth/store.go internal/auth/store_test.go
git commit -m "feat(auth): add user store with OIDC lookup and role/department loading"
```

---

### Task 5: Auth HTTP Handlers (Login, Callback, Refresh)

**Files:**
- Create: `internal/auth/handler.go`
- Create: `internal/auth/handler_test.go`

**Step 1: Write the failing test**

Create `internal/auth/handler_test.go`:
```go
package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
)

func TestHandler_RefreshToken(t *testing.T) {
	tokenSvc := newTestTokenService()
	handler := auth.NewHandler(tokenSvc, nil, nil) // nil store/oidc for unit test

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
	handler := auth.NewHandler(tokenSvc, nil, nil)

	body := `{"refresh_token":"invalid-token"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/token/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleRefresh(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandler_RefreshToken_AccessTokenRejected(t *testing.T) {
	tokenSvc := newTestTokenService()
	handler := auth.NewHandler(tokenSvc, nil, nil)

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
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/auth/ -v -run TestHandler -count=1
```
Expected: FAIL — Handler doesn't exist.

**Step 3: Implement handler**

Create `internal/auth/handler.go`:
```go
package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// OIDCProvider is an interface for OIDC operations (allows mocking).
type OIDCProvider interface {
	AuthCodeURL(state string) string
	Exchange(ctx context.Context, code string) (*OIDCUserInfo, error)
}

// Handler handles authentication HTTP endpoints.
type Handler struct {
	tokenSvc *TokenService
	store    *Store
	oidc     OIDCProvider
}

func NewHandler(tokenSvc *TokenService, store *Store, oidc OIDCProvider) *Handler {
	return &Handler{
		tokenSvc: tokenSvc,
		store:    store,
		oidc:     oidc,
	}
}

// RegisterRoutes registers auth routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/login", h.HandleLogin)
	mux.HandleFunc("GET /auth/callback", h.HandleCallback)
	mux.HandleFunc("POST /auth/token/refresh", h.HandleRefresh)
}

// HandleLogin initiates the OIDC login flow.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if h.oidc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "OIDC not configured",
		})
		return
	}

	// Generate state parameter (in production, store in session/cookie)
	state := generateState()
	url := h.oidc.AuthCodeURL(state)

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// HandleCallback processes the OIDC callback.
func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if h.oidc == nil || h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "OIDC not configured",
		})
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "missing code parameter",
		})
		return
	}

	// Exchange code for user info
	userInfo, err := h.oidc.Exchange(r.Context(), code)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "OIDC exchange failed",
		})
		return
	}

	// Find or create user (TODO: tenant resolution - for MVP, use a default tenant)
	// This will need to be improved to support multi-tenant OIDC
	identity, _, err := h.store.FindOrCreateByOIDC(r.Context(), *userInfo, "")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "user lookup failed",
		})
		return
	}

	// Load full identity with roles
	fullIdentity, err := h.store.GetIdentityWithRoles(r.Context(), identity.UserID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "identity loading failed",
		})
		return
	}

	// Issue tokens
	accessToken, err := h.tokenSvc.CreateAccessToken(fullIdentity)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "token creation failed",
		})
		return
	}

	refreshToken, err := h.tokenSvc.CreateRefreshToken(fullIdentity)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "token creation failed",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
	})
}

// HandleRefresh exchanges a refresh token for new access + refresh tokens.
func (h *Handler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	// Validate refresh token
	identity, err := h.tokenSvc.ValidateToken(req.RefreshToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "invalid refresh token",
		})
		return
	}

	if identity.TokenType != "refresh" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "refresh token required",
		})
		return
	}

	// Issue new tokens
	accessToken, err := h.tokenSvc.CreateAccessToken(identity)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "token creation failed",
		})
		return
	}

	refreshToken, err := h.tokenSvc.CreateRefreshToken(identity)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "token creation failed",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
```

Add necessary imports: `"context"`, `"crypto/rand"`, `"encoding/hex"`.

**Step 4: Run tests to verify they pass**

```bash
go test ./internal/auth/ -v -count=1
```
Expected: PASS (all tests).

**Step 5: Commit**

```bash
git add internal/auth/handler.go internal/auth/handler_test.go
git commit -m "feat(auth): add auth handlers (login, callback, refresh)"
```

---

### Task 6: RBAC Policy Engine

**Files:**
- Create: `internal/rbac/rbac.go` (interface)
- Create: `internal/rbac/evaluator.go` (implementation)
- Create: `internal/rbac/evaluator_test.go`

**Step 1: Write the failing test**

Create `internal/rbac/evaluator_test.go`:
```go
package rbac_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/rbac"
)

func TestEvaluator_PermissionGranted(t *testing.T) {
	eval := rbac.NewEvaluator(nil) // nil store for unit tests with in-memory permissions

	identity := &auth.Identity{
		UserID:      "user-123",
		TenantID:    "tenant-456",
		Roles:       []string{"standard_user"},
		Departments: []string{"dept-scouting"},
	}

	// Register role permissions
	eval.RegisterRole("standard_user", []string{
		"agents:read",
		"agents:message",
	})

	decision, err := eval.Authorize(context.Background(), identity, "agents:read", "", "")
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestEvaluator_PermissionDenied(t *testing.T) {
	eval := rbac.NewEvaluator(nil)

	identity := &auth.Identity{
		UserID:      "user-123",
		TenantID:    "tenant-456",
		Roles:       []string{"standard_user"},
		Departments: []string{"dept-scouting"},
	}

	eval.RegisterRole("standard_user", []string{
		"agents:read",
		"agents:message",
	})

	decision, err := eval.Authorize(context.Background(), identity, "users:manage", "", "")
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.NotEmpty(t, decision.Reason)
}

func TestEvaluator_OrgAdminHasAllPermissions(t *testing.T) {
	eval := rbac.NewEvaluator(nil)

	identity := &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
		Roles:    []string{"org_admin"},
	}

	eval.RegisterRole("org_admin", []string{"*"}) // wildcard = all permissions

	decision, err := eval.Authorize(context.Background(), identity, "anything:here", "", "")
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestEvaluator_MultipleRoles(t *testing.T) {
	eval := rbac.NewEvaluator(nil)

	identity := &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
		Roles:    []string{"standard_user", "dept_head"},
	}

	eval.RegisterRole("standard_user", []string{"agents:read", "agents:message"})
	eval.RegisterRole("dept_head", []string{"agents:read", "agents:write", "users:read"})

	// Should have union of permissions
	d1, err := eval.Authorize(context.Background(), identity, "agents:message", "", "")
	require.NoError(t, err)
	assert.True(t, d1.Allowed) // from standard_user

	d2, err := eval.Authorize(context.Background(), identity, "users:read", "", "")
	require.NoError(t, err)
	assert.True(t, d2.Allowed) // from dept_head
}

func TestEvaluator_NoRoles(t *testing.T) {
	eval := rbac.NewEvaluator(nil)

	identity := &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
		Roles:    []string{},
	}

	decision, err := eval.Authorize(context.Background(), identity, "agents:read", "", "")
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/rbac/ -v
```
Expected: FAIL — package doesn't exist.

**Step 3: Create RBAC interface**

Create `internal/rbac/rbac.go`:
```go
package rbac

import (
	"context"

	"github.com/valinor-ai/valinor/internal/auth"
)

// Decision represents the result of an authorization check.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// PolicyEngine defines the authorization interface.
type PolicyEngine interface {
	// Authorize checks if the identity has permission to perform the action
	// on the given resource. resourceType and resourceID can be empty for
	// broad permission checks.
	Authorize(ctx context.Context, identity *auth.Identity, action string, resourceType string, resourceID string) (*Decision, error)
}
```

**Step 4: Implement evaluator**

Create `internal/rbac/evaluator.go`:
```go
package rbac

import (
	"context"
	"fmt"
	"sync"

	"github.com/valinor-ai/valinor/internal/auth"
)

// Evaluator is the in-memory RBAC policy evaluation engine.
type Evaluator struct {
	store       Store // can be nil for unit testing
	roles       map[string][]string // role name -> permissions
	mu          sync.RWMutex
}

// Store defines the database interface for RBAC (for loading resource policies).
type Store interface {
	GetResourcePolicies(ctx context.Context, subjectType string, subjectID string, action string, resourceType string, resourceID string) ([]ResourcePolicy, error)
}

// ResourcePolicy represents a fine-grained resource-level policy.
type ResourcePolicy struct {
	Effect       string // "allow" or "deny"
	Action       string
	ResourceType string
	ResourceID   string
}

func NewEvaluator(store Store) *Evaluator {
	return &Evaluator{
		store: store,
		roles: make(map[string][]string),
	}
}

// RegisterRole adds a role with its permissions to the in-memory cache.
func (e *Evaluator) RegisterRole(name string, permissions []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.roles[name] = permissions
}

// Authorize checks if the identity has the required permission.
// Evaluation order: deny-by-default → role permissions → resource policies.
func (e *Evaluator) Authorize(ctx context.Context, identity *auth.Identity, action string, resourceType string, resourceID string) (*Decision, error) {
	if identity == nil {
		return &Decision{Allowed: false, Reason: "no identity"}, nil
	}

	// Phase 1: Check role-based permissions
	if e.checkRolePermissions(identity.Roles, action) {
		// Phase 2: If resource specified, check resource policies for explicit deny
		if resourceType != "" && resourceID != "" && e.store != nil {
			denied, err := e.checkResourceDeny(ctx, identity, action, resourceType, resourceID)
			if err != nil {
				return nil, fmt.Errorf("checking resource policies: %w", err)
			}
			if denied {
				return &Decision{
					Allowed: false,
					Reason:  fmt.Sprintf("resource policy denies %s on %s/%s", action, resourceType, resourceID),
				}, nil
			}
		}
		return &Decision{Allowed: true}, nil
	}

	// Phase 3: If role check failed, check for explicit resource-level allow
	if resourceType != "" && resourceID != "" && e.store != nil {
		allowed, err := e.checkResourceAllow(ctx, identity, action, resourceType, resourceID)
		if err != nil {
			return nil, fmt.Errorf("checking resource policies: %w", err)
		}
		if allowed {
			return &Decision{Allowed: true}, nil
		}
	}

	return &Decision{
		Allowed: false,
		Reason:  fmt.Sprintf("no permission for %s", action),
	}, nil
}

func (e *Evaluator) checkRolePermissions(roles []string, action string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, role := range roles {
		perms, ok := e.roles[role]
		if !ok {
			continue
		}
		for _, perm := range perms {
			if perm == "*" || perm == action {
				return true
			}
		}
	}
	return false
}

func (e *Evaluator) checkResourceDeny(ctx context.Context, identity *auth.Identity, action, resourceType, resourceID string) (bool, error) {
	policies, err := e.store.GetResourcePolicies(ctx, "user", identity.UserID, action, resourceType, resourceID)
	if err != nil {
		return false, err
	}

	for _, p := range policies {
		if p.Effect == "deny" {
			return true, nil
		}
	}
	return false, nil
}

func (e *Evaluator) checkResourceAllow(ctx context.Context, identity *auth.Identity, action, resourceType, resourceID string) (bool, error) {
	policies, err := e.store.GetResourcePolicies(ctx, "user", identity.UserID, action, resourceType, resourceID)
	if err != nil {
		return false, err
	}

	for _, p := range policies {
		if p.Effect == "allow" {
			return true, nil
		}
	}
	return false, nil
}
```

**Step 5: Run tests to verify they pass**

```bash
go test ./internal/rbac/ -v
```
Expected: PASS (5 tests).

**Step 6: Commit**

```bash
git add internal/rbac/
git commit -m "feat(rbac): add policy evaluation engine with role permissions and resource policies"
```

---

### Task 7: RBAC Middleware

**Files:**
- Create: `internal/rbac/middleware.go`
- Create: `internal/rbac/middleware_test.go`

**Step 1: Write the failing test**

Create `internal/rbac/middleware_test.go`:
```go
package rbac_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/rbac"
)

func setIdentity(r *http.Request, identity *auth.Identity) *http.Request {
	ctx := context.WithValue(r.Context(), auth.IdentityContextKey(), identity)
	return r.WithContext(ctx)
}

func TestRBACMiddleware_Allowed(t *testing.T) {
	eval := rbac.NewEvaluator(nil)
	eval.RegisterRole("standard_user", []string{"agents:read"})

	handler := rbac.RequirePermission(eval, "agents:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = setIdentity(req, &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
		Roles:    []string{"standard_user"},
	})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRBACMiddleware_Denied(t *testing.T) {
	eval := rbac.NewEvaluator(nil)
	eval.RegisterRole("standard_user", []string{"agents:read"})

	handler := rbac.RequirePermission(eval, "users:manage")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = setIdentity(req, &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
		Roles:    []string{"standard_user"},
	})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)

	var body map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Contains(t, body["error"], "forbidden")
}

func TestRBACMiddleware_NoIdentity(t *testing.T) {
	eval := rbac.NewEvaluator(nil)

	handler := rbac.RequirePermission(eval, "agents:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// No identity in context
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
```

**Step 2: Run test to verify it fails**

Note: The test uses `auth.IdentityContextKey()` — we need to export the context key. Add to `internal/auth/middleware.go`:
```go
func IdentityContextKey() identityContextKey {
	return identityContextKey{}
}
```

```bash
go test ./internal/rbac/ -v -run TestRBACMiddleware
```
Expected: FAIL — RequirePermission doesn't exist.

**Step 3: Implement RBAC middleware**

Create `internal/rbac/middleware.go`:
```go
package rbac

import (
	"encoding/json"
	"net/http"

	"github.com/valinor-ai/valinor/internal/auth"
)

// RequirePermission returns middleware that checks if the authenticated user
// has the specified permission.
func RequirePermission(engine *Evaluator, permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity := auth.GetIdentity(r.Context())
			if identity == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "authentication required",
				})
				return
			}

			decision, err := engine.Authorize(r.Context(), identity, permission, "", "")
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "authorization check failed",
				})
				return
			}

			if !decision.Allowed {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{
					"error":  "forbidden",
					"reason": decision.Reason,
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
```

**Step 4: Run tests to verify they pass**

```bash
go test ./internal/rbac/ -v
```
Expected: PASS (8 tests — 5 evaluator + 3 middleware).

**Step 5: Commit**

```bash
git add internal/rbac/middleware.go internal/rbac/middleware_test.go internal/auth/middleware.go
git commit -m "feat(rbac): add RequirePermission middleware"
```

---

### Task 8: Tenant Context Middleware (RLS Setup)

**Files:**
- Create: `internal/platform/middleware/tenant.go`
- Create: `internal/platform/middleware/tenant_test.go`

**Step 1: Write the failing test**

Create `internal/platform/middleware/tenant_test.go`:
```go
package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

func TestTenantContext_SetsContextValue(t *testing.T) {
	var gotTenantID string
	handler := middleware.TenantContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenantID = middleware.GetTenantID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := context.WithValue(req.Context(), auth.IdentityContextKey(), &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, "tenant-456", gotTenantID)
}

func TestTenantContext_NoIdentity(t *testing.T) {
	handler := middleware.TenantContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := middleware.GetTenantID(r.Context())
		assert.Empty(t, tenantID)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/platform/middleware/ -v -run TestTenantContext
```
Expected: FAIL.

**Step 3: Implement tenant context middleware**

Create `internal/platform/middleware/tenant.go`:
```go
package middleware

import (
	"context"
	"net/http"

	"github.com/valinor-ai/valinor/internal/auth"
)

type tenantContextKey struct{}

// TenantContext extracts the tenant ID from the authenticated identity
// and sets it in the request context for RLS and downstream use.
func TenantContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := auth.GetIdentity(r.Context())
		if identity != nil && identity.TenantID != "" {
			ctx := context.WithValue(r.Context(), tenantContextKey{}, identity.TenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GetTenantID retrieves the tenant ID from the request context.
func GetTenantID(ctx context.Context) string {
	if id, ok := ctx.Value(tenantContextKey{}).(string); ok {
		return id
	}
	return ""
}
```

**Step 4: Run tests to verify they pass**

```bash
go test ./internal/platform/middleware/ -v
```
Expected: PASS (all middleware tests).

**Step 5: Commit**

```bash
git add internal/platform/middleware/tenant.go internal/platform/middleware/tenant_test.go
git commit -m "feat(auth): add tenant context middleware for RLS support"
```

---

### Task 9: Wire Auth + RBAC into Server

**Files:**
- Modify: `internal/platform/server/server.go`
- Modify: `cmd/valinor/main.go`

**Step 1: Update server to accept Dependencies struct**

Update `internal/platform/server/server.go` — replace the constructor:

```go
type Dependencies struct {
	Pool     *pgxpool.Pool
	Auth     *auth.TokenService
	AuthHandler *auth.Handler
	RBAC     *rbac.Evaluator
	DevMode  bool
	DevIdentity *auth.Identity
	Logger   *slog.Logger
}

func New(addr string, deps Dependencies) *Server {
	mux := http.NewServeMux()

	s := &Server{
		httpServer: &http.Server{
			Addr:         addr,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		mux:  mux,
		pool: deps.Pool,
	}

	// Build middleware chain
	var handler http.Handler = mux
	handler = middleware.TenantContext(handler)

	// Auth middleware (wraps tenant context)
	if deps.Auth != nil {
		if deps.DevMode && deps.DevIdentity != nil {
			handler = auth.MiddlewareWithDevMode(deps.Auth, deps.DevIdentity)(handler)
		} else {
			handler = auth.Middleware(deps.Auth)(handler)
		}
	}

	if deps.Logger != nil {
		handler = middleware.Logging(deps.Logger)(handler)
	}
	handler = middleware.RequestID(handler)

	s.httpServer.Handler = handler

	// Register routes
	s.registerRoutes()
	if deps.AuthHandler != nil {
		deps.AuthHandler.RegisterRoutes(mux)
	}

	return s
}
```

Add necessary imports for `auth`, `rbac`, `middleware` packages.

**Step 2: Update main.go to wire auth + RBAC**

Update `cmd/valinor/main.go`:
```go
func run() error {
	cfg, err := config.Load("config.yaml")
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	logger := telemetry.NewLogger(cfg.Log.Level, cfg.Log.Format)
	telemetry.SetDefault(logger)

	slog.Info("valinor starting", "version", "0.2.0", "port", cfg.Server.Port)

	ctx := context.Background()

	// Database
	var pool *database.Pool
	if cfg.Database.URL != "" {
		slog.Info("connecting to database")
		p, err := database.Connect(ctx, cfg.Database.URL, cfg.Database.MaxConns)
		if err != nil {
			slog.Warn("database connection failed", "error", err)
		} else {
			pool = p
			defer pool.Close()

			migrationsURL := fmt.Sprintf("file://%s", cfg.Database.MigrationsPath)
			if err := database.RunMigrations(cfg.Database.URL, migrationsURL); err != nil {
				return fmt.Errorf("running migrations: %w", err)
			}
			slog.Info("migrations complete")
		}
	}

	// Auth
	tokenSvc := auth.NewTokenService(
		cfg.Auth.JWT.SigningKey,
		cfg.Auth.JWT.Issuer,
		cfg.Auth.JWT.ExpiryHours,
		cfg.Auth.JWT.RefreshExpiryHours,
	)

	var authStore *auth.Store
	if pool != nil {
		authStore = auth.NewStore(pool)
	}

	authHandler := auth.NewHandler(tokenSvc, authStore, nil) // OIDC provider wired later

	// RBAC
	rbacEngine := rbac.NewEvaluator(nil) // DB-backed store wired later

	// Register default system roles
	rbacEngine.RegisterRole("org_admin", []string{"*"})
	rbacEngine.RegisterRole("dept_head", []string{
		"agents:read", "agents:write", "agents:message",
		"users:read", "users:write",
		"departments:read",
	})
	rbacEngine.RegisterRole("standard_user", []string{
		"agents:read", "agents:message",
	})
	rbacEngine.RegisterRole("read_only", []string{
		"agents:read",
	})

	// Dev mode identity
	var devIdentity *auth.Identity
	if cfg.Auth.DevMode {
		slog.Warn("running in dev mode — authentication bypassed with 'Bearer dev'")
		devIdentity = &auth.Identity{
			UserID:   "dev-user",
			TenantID: "dev-tenant",
			Roles:    []string{"org_admin"},
		}
	}

	// Server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := server.New(addr, server.Dependencies{
		Pool:        pool,
		Auth:        tokenSvc,
		AuthHandler: authHandler,
		RBAC:        rbacEngine,
		DevMode:     cfg.Auth.DevMode,
		DevIdentity: devIdentity,
		Logger:      logger,
	})

	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	slog.Info("server ready", "addr", addr, "dev_mode", cfg.Auth.DevMode)
	return srv.Start(ctx)
}
```

**Step 3: Build and verify**

```bash
go build ./cmd/valinor
```
Expected: builds successfully.

**Step 4: Test dev mode auth**

```bash
# Start server in dev mode
VALINOR_AUTH_DEVMODE=true ./bin/valinor &

# Test unauthenticated request
curl -s http://localhost:8080/healthz | jq .
# Expected: {"status": "ok"} (health check doesn't require auth)

# Test authenticated request in dev mode
curl -s -H "Authorization: Bearer dev" http://localhost:8080/readyz | jq .
# Expected: response (not 401)

# Cleanup
kill %1
```

**Step 5: Run all tests**

```bash
go test ./... -short -v
```
Expected: all unit tests pass.

**Step 6: Commit**

```bash
git add internal/platform/server/server.go cmd/valinor/main.go
git commit -m "feat(auth): wire auth middleware, RBAC engine, and dev mode into server"
```

---

### Task 10: Integration Test — Full Auth + RBAC Flow

**Files:**
- Create: `internal/auth/integration_test.go`

**Step 1: Write the integration test**

Create `internal/auth/integration_test.go`:
```go
package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

	// Load identity and create token
	identity, err := store.GetIdentityWithRoles(ctx, userID)
	require.NoError(t, err)

	accessToken, err := tokenSvc.CreateAccessToken(identity)
	require.NoError(t, err)

	refreshToken, err := tokenSvc.CreateRefreshToken(identity)
	require.NoError(t, err)

	// RBAC setup
	rbacEngine := rbac.NewEvaluator(nil)
	rbacEngine.RegisterRole("standard_user", []string{"agents:read", "agents:message"})

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

	// Test 4: Refresh token flow
	t.Run("refresh token produces new tokens", func(t *testing.T) {
		handler := auth.NewHandler(tokenSvc, store, nil)

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
		assert.NotEqual(t, accessToken, resp["access_token"]) // new token
	})
}
```

**Step 2: Run integration test**

```bash
go test ./internal/auth/ -v -run TestIntegration -count=1
```
Expected: PASS.

**Step 3: Run full test suite**

```bash
go test ./... -v -count=1
```
Expected: all tests pass.

**Step 4: Commit**

```bash
git add internal/auth/integration_test.go
git commit -m "feat(auth): add integration test for full auth + RBAC flow"
```

**Step 5: Final commit for Phase 2**

```bash
git add -A
git commit -m "feat: Phase 2 Auth + RBAC complete — JWT, OIDC, middleware, RBAC engine, dev mode"
```

---

## Summary

After completing all 10 tasks, Phase 2 delivers:

| Component | Status |
|-----------|--------|
| Auth config (OIDC + JWT settings) | Working + tested |
| JWT token service (create/validate/refresh) | Working + tested |
| Auth middleware (Bearer token validation) | Working + tested |
| Dev mode auth bypass (Bearer dev) | Working + tested |
| User store (OIDC lookup, role/dept loading) | Working + integration tested |
| Auth handlers (login, callback, refresh) | Working + tested |
| RBAC policy engine (roles + resource policies) | Working + tested |
| RBAC middleware (RequirePermission) | Working + tested |
| Tenant context middleware (for RLS) | Working + tested |
| Server wiring (Dependencies struct, middleware chain) | Working |
| System roles (org_admin, dept_head, standard_user, read_only) | Registered |
| Full integration test (auth + RBAC end-to-end) | Passing |

**Next:** Phase 3 — Tenant + Users (Tenant CRUD, department hierarchy, user management, role assignment API endpoints)
