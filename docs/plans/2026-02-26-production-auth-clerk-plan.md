# Production Auth via Clerk — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Clerk as a production OIDC provider alongside the existing dev-mode credentials login, using a token exchange pattern where the dashboard authenticates with Clerk and exchanges the id_token for Valinor JWTs.

**Architecture:** Dashboard adds Clerk as a NextAuth OIDC provider. On sign-in, the NextAuth `signIn` callback sends Clerk's `id_token` to a new `POST /auth/exchange` endpoint on the Go backend. The backend validates the token via Clerk's JWKS, resolves the tenant from the request origin subdomain, creates/finds the user by OIDC subject, and returns Valinor access + refresh tokens. The existing JWT/session callbacks store these tokens identically to the dev-mode path.

**Tech Stack:** Go (stdlib `crypto`, `net/http`), NextAuth v5, Clerk OIDC, PostgreSQL

**Design doc:** `docs/plans/2026-02-26-production-auth-clerk-design.md`

---

### Task 1: Extend OIDCConfig with JWKS URL

**Files:**
- Modify: `internal/platform/config/config.go:32-37`

**Step 1: Add JWKSUrl field to OIDCConfig**

In `internal/platform/config/config.go`, add `Enabled` and `JWKSUrl` to the existing `OIDCConfig` struct:

```go
type OIDCConfig struct {
	Enabled      bool   `koanf:"enabled"`
	IssuerURL    string `koanf:"issuerurl"`
	ClientID     string `koanf:"clientid"`
	ClientSecret string `koanf:"clientsecret"`
	RedirectURL  string `koanf:"redirecturl"`
	JWKSUrl      string `koanf:"jwksurl"`
}
```

**Step 2: Verify build**

Run: `cd /Users/fred/Documents/Valinor && go build ./...`
Expected: Clean build (no code references the new fields yet)

**Step 3: Commit**

```bash
git add internal/platform/config/config.go
git commit -m "feat(auth): add Enabled and JWKSUrl fields to OIDCConfig"
```

---

### Task 2: Build the JWKS client

**Files:**
- Create: `internal/auth/jwks.go`
- Create: `internal/auth/jwks_test.go`

**Step 1: Write the failing test**

Create `internal/auth/jwks_test.go`:

```go
package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper: build a minimal JWKS JSON from an RSA public key
func buildJWKS(t *testing.T, kid string, pub *rsa.PublicKey) []byte {
	t.Helper()
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
	b, err := json.Marshal(jwks)
	require.NoError(t, err)
	return b
}

func TestJWKSClient_GetKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "test-key-1"
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildJWKS(t, kid, &priv.PublicKey))
	}))
	defer srv.Close()

	client := NewJWKSClient(srv.URL, 1*time.Hour)

	t.Run("fetches key on first call", func(t *testing.T) {
		key, err := client.GetKey(kid)
		require.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, 1, calls)
	})

	t.Run("returns cached key on second call", func(t *testing.T) {
		key, err := client.GetKey(kid)
		require.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, 1, calls, "should not re-fetch")
	})

	t.Run("unknown kid triggers refresh", func(t *testing.T) {
		_, err := client.GetKey("unknown-kid")
		assert.Error(t, err)
		assert.Equal(t, 2, calls, "should have re-fetched once")
	})
}

func TestJWKSClient_CacheExpiry(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "test-key-1"
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildJWKS(t, kid, &priv.PublicKey))
	}))
	defer srv.Close()

	// Very short TTL to test expiry
	client := NewJWKSClient(srv.URL, 1*time.Millisecond)

	_, err = client.GetKey(kid)
	require.NoError(t, err)
	assert.Equal(t, 1, calls)

	time.Sleep(5 * time.Millisecond)

	_, err = client.GetKey(kid)
	require.NoError(t, err)
	assert.Equal(t, 2, calls, "should re-fetch after TTL expiry")
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/fred/Documents/Valinor && go test ./internal/auth/ -run TestJWKS -v`
Expected: FAIL — `NewJWKSClient` undefined

**Step 3: Write the implementation**

Create `internal/auth/jwks.go`:

```go
package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// JWKSClient fetches and caches RSA public keys from a JWKS endpoint.
type JWKSClient struct {
	url string
	ttl time.Duration

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

// NewJWKSClient creates a new JWKS client that caches keys for the given TTL.
func NewJWKSClient(url string, ttl time.Duration) *JWKSClient {
	return &JWKSClient{
		url:  url,
		ttl:  ttl,
		keys: make(map[string]*rsa.PublicKey),
	}
}

// GetKey returns the RSA public key for the given key ID.
// It fetches from the JWKS endpoint on first call, caches for TTL,
// and re-fetches if the kid is unknown (handles key rotation).
func (c *JWKSClient) GetKey(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	if key, ok := c.keys[kid]; ok && time.Since(c.fetchedAt) < c.ttl {
		c.mu.RUnlock()
		return key, nil
	}
	c.mu.RUnlock()

	if err := c.refresh(); err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok := c.keys[kid]
	if !ok {
		return nil, fmt.Errorf("key %q not found in JWKS", kid)
	}
	return key, nil
}

func (c *JWKSClient) refresh() error {
	resp, err := http.Get(c.url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", c.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", c.url, resp.StatusCode)
	}

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("decoding JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			continue // skip malformed keys
		}
		keys[k.Kid] = pub
	}

	c.mu.Lock()
	c.keys = keys
	c.fetchedAt = time.Now()
	c.mu.Unlock()
	return nil
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decoding n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decoding e: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/fred/Documents/Valinor && go test ./internal/auth/ -run TestJWKS -v`
Expected: PASS (all 4 subtests)

**Step 5: Commit**

```bash
git add internal/auth/jwks.go internal/auth/jwks_test.go
git commit -m "feat(auth): add JWKS client with in-memory key cache"
```

---

### Task 3: Build the id_token validator

**Files:**
- Create: `internal/auth/idtoken.go`
- Create: `internal/auth/idtoken_test.go`

**Step 1: Write the failing test**

Create `internal/auth/idtoken_test.go`:

```go
package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupIDTokenValidator(t *testing.T) (*IDTokenValidator, *rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "test-kid"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildJWKS(t, kid, &priv.PublicKey))
	}))
	t.Cleanup(srv.Close)

	v := NewIDTokenValidator(IDTokenValidatorConfig{
		JWKSUrl:  srv.URL,
		Issuer:   "https://clerk.example.com",
		Audience: "client_123",
		CacheTTL: 1 * time.Hour,
	})
	return v, priv, kid
}

func signIDToken(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(priv)
	require.NoError(t, err)
	return signed
}

func TestIDTokenValidator_ValidToken(t *testing.T) {
	v, priv, kid := setupIDTokenValidator(t)

	tok := signIDToken(t, priv, kid, jwt.MapClaims{
		"iss":   "https://clerk.example.com",
		"aud":   "client_123",
		"sub":   "user_abc",
		"email": "turgon@gondolin.fc",
		"name":  "Turgon",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})

	info, err := v.Validate(tok)
	require.NoError(t, err)
	assert.Equal(t, "https://clerk.example.com", info.Issuer)
	assert.Equal(t, "user_abc", info.Subject)
	assert.Equal(t, "turgon@gondolin.fc", info.Email)
	assert.Equal(t, "Turgon", info.Name)
}

func TestIDTokenValidator_ExpiredToken(t *testing.T) {
	v, priv, kid := setupIDTokenValidator(t)

	tok := signIDToken(t, priv, kid, jwt.MapClaims{
		"iss": "https://clerk.example.com",
		"aud": "client_123",
		"sub": "user_abc",
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	})

	_, err := v.Validate(tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestIDTokenValidator_WrongIssuer(t *testing.T) {
	v, priv, kid := setupIDTokenValidator(t)

	tok := signIDToken(t, priv, kid, jwt.MapClaims{
		"iss": "https://evil.example.com",
		"aud": "client_123",
		"sub": "user_abc",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	_, err := v.Validate(tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestIDTokenValidator_WrongAudience(t *testing.T) {
	v, priv, kid := setupIDTokenValidator(t)

	tok := signIDToken(t, priv, kid, jwt.MapClaims{
		"iss": "https://clerk.example.com",
		"aud": "wrong_client",
		"sub": "user_abc",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	_, err := v.Validate(tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience")
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/fred/Documents/Valinor && go test ./internal/auth/ -run TestIDTokenValidator -v`
Expected: FAIL — `NewIDTokenValidator` undefined

**Step 3: Write the implementation**

Create `internal/auth/idtoken.go`:

```go
package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IDTokenValidatorConfig holds configuration for validating external id_tokens.
type IDTokenValidatorConfig struct {
	JWKSUrl  string
	Issuer   string
	Audience string
	CacheTTL time.Duration
}

// IDTokenValidator validates external OIDC id_tokens using JWKS.
type IDTokenValidator struct {
	jwks     *JWKSClient
	issuer   string
	audience string
}

// NewIDTokenValidator creates a validator for external id_tokens.
func NewIDTokenValidator(cfg IDTokenValidatorConfig) *IDTokenValidator {
	ttl := cfg.CacheTTL
	if ttl == 0 {
		ttl = 1 * time.Hour
	}
	return &IDTokenValidator{
		jwks:     NewJWKSClient(cfg.JWKSUrl, ttl),
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
	}
}

// Validate parses and validates an external id_token.
// Returns the user info extracted from the verified claims.
func (v *IDTokenValidator) Validate(tokenString string) (*OIDCUserInfo, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}
		return v.jwks.GetKey(kid)
	},
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("validating id_token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("missing sub claim")
	}

	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	issuer, _ := claims["iss"].(string)

	return &OIDCUserInfo{
		Issuer:  issuer,
		Subject: sub,
		Email:   email,
		Name:    name,
	}, nil
}
```

**Step 4: Check if golang-jwt/jwt/v5 is already a dependency**

Run: `cd /Users/fred/Documents/Valinor && grep 'golang-jwt' go.mod`

If not present, run: `go get github.com/golang-jwt/jwt/v5`

Note: The existing `internal/auth/token.go` already uses `github.com/golang-jwt/jwt/v5`, so it should already be in `go.mod`.

**Step 5: Run test to verify it passes**

Run: `cd /Users/fred/Documents/Valinor && go test ./internal/auth/ -run TestIDTokenValidator -v`
Expected: PASS (all 4 tests)

**Step 6: Commit**

```bash
git add internal/auth/idtoken.go internal/auth/idtoken_test.go
git commit -m "feat(auth): add id_token validator with JWKS signature verification"
```

---

### Task 4: Add the `POST /auth/exchange` handler

**Files:**
- Modify: `internal/auth/handler.go:49-60` (add route + method)

**Step 1: Write the failing test**

Create `internal/auth/exchange_test.go`:

```go
package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupExchangeTest(t *testing.T) (*Handler, *rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "test-kid"
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildJWKS(t, kid, &priv.PublicKey))
	}))
	t.Cleanup(jwksSrv.Close)

	tokenSvc := NewTokenService("test-signing-key-32-chars-long!!", "valinor", 1, 24)

	h := NewHandler(HandlerConfig{
		TokenSvc: tokenSvc,
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

func TestHandleExchange_NotConfigured(t *testing.T) {
	tokenSvc := NewTokenService("test-signing-key-32-chars-long!!", "valinor", 1, 24)
	h := NewHandler(HandlerConfig{TokenSvc: tokenSvc})
	// No idTokenValidator set

	body, _ := json.Marshal(map[string]string{"id_token": "some.jwt.token"})
	req := httptest.NewRequest("POST", "/auth/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.HandleExchange(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/fred/Documents/Valinor && go test ./internal/auth/ -run TestHandleExchange -v`
Expected: FAIL — `HandleExchange` undefined, `idTokenValidator` unknown field

**Step 3: Write the implementation**

Add to `internal/auth/handler.go`:

1. Add `idTokenValidator` field to the `Handler` struct (after line 35):
```go
type Handler struct {
	tokenSvc         *TokenService
	store            *Store
	refreshStore     *RefreshTokenStore
	oidc             OIDCProvider
	stateStore       *StateStore
	tenantResolver   *TenantResolver
	idTokenValidator *IDTokenValidator
}
```

2. Update `NewHandler` to include the new field (line 38-47):
```go
func NewHandler(cfg HandlerConfig) *Handler {
	return &Handler{
		tokenSvc:       cfg.TokenSvc,
		store:          cfg.Store,
		refreshStore:   cfg.RefreshStore,
		oidc:           cfg.OIDC,
		stateStore:     cfg.StateStore,
		tenantResolver: cfg.TenantResolver,
	}
}
```
(Note: `idTokenValidator` is set separately, not via config, to keep backward compatibility. It gets set in main.go when OIDC is configured.)

3. Register the exchange route. Add to `RegisterRoutes` (after line 53):
```go
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/login", h.HandleLogin)
	mux.HandleFunc("GET /auth/callback", h.HandleCallback)
	mux.HandleFunc("POST /auth/token/refresh", h.HandleRefresh)
	mux.HandleFunc("POST /auth/exchange", h.HandleExchange)
}
```

4. Add the `HandleExchange` method (new method, add after `HandleDevLogin` around line 171):

```go
// HandleExchange validates an external OIDC id_token and returns Valinor tokens.
// Used by the dashboard to exchange Clerk id_tokens for platform JWTs.
func (h *Handler) HandleExchange(w http.ResponseWriter, r *http.Request) {
	if h.idTokenValidator == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "OIDC token exchange not configured",
		})
		return
	}

	var req struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IDToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "missing or invalid id_token",
		})
		return
	}

	userInfo, err := h.idTokenValidator.Validate(req.IDToken)
	if err != nil {
		slog.Warn("id_token validation failed", "error", err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "invalid id_token",
		})
		return
	}

	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "auth store not configured",
		})
		return
	}

	// Resolve tenant from Origin header subdomain.
	var tenantID string
	if h.tenantResolver != nil {
		origin := r.Header.Get("Origin")
		if origin != "" {
			tid, err := h.tenantResolver.ResolveFromOrigin(origin)
			if err != nil {
				slog.Warn("tenant resolution failed", "origin", origin, "error", err)
			} else {
				tenantID = tid
			}
		}
	}

	// Platform admin bypass: if no tenant resolved, check if user is a platform admin.
	if tenantID == "" {
		adminIdentity, err := h.store.LookupPlatformAdminByOIDC(r.Context(), userInfo.Issuer, userInfo.Subject)
		if err != nil || adminIdentity == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{
				"error": "tenant not found",
			})
			return
		}
		// Platform admin — proceed without tenant scope
	}

	identity, _, err := h.store.FindOrCreateByOIDC(r.Context(), *userInfo, tenantID)
	if err != nil {
		slog.Error("exchange: user resolution failed", "error", err, "subject", userInfo.Subject)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "user resolution failed",
		})
		return
	}

	// Load full identity with roles.
	fullIdentity, err := h.store.GetIdentityWithRoles(r.Context(), identity.UserID)
	if err != nil {
		slog.Error("exchange: loading identity failed", "error", err, "user_id", identity.UserID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "loading identity failed",
		})
		return
	}

	accessToken, err := h.tokenSvc.CreateAccessToken(fullIdentity)
	if err != nil {
		slog.Error("exchange: access token creation failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "token creation failed",
		})
		return
	}

	refreshToken, err := h.tokenSvc.CreateRefreshToken(fullIdentity)
	if err != nil {
		slog.Error("exchange: refresh token creation failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "token creation failed",
		})
		return
	}

	slog.Info("token exchange successful",
		"subject", userInfo.Subject,
		"email", userInfo.Email,
		"user_id", fullIdentity.UserID,
	)

	writeJSON(w, http.StatusOK, devLoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    h.tokenSvc.AccessTokenExpirySeconds(),
		User: devLoginUserInfo{
			ID:              fullIdentity.UserID,
			Email:           fullIdentity.Email,
			DisplayName:     fullIdentity.DisplayName,
			TenantID:        fullIdentity.TenantID,
			IsPlatformAdmin: fullIdentity.IsPlatformAdmin,
		},
	})
}
```

**Step 4: Check if `TenantResolver.ResolveFromOrigin` exists**

Run: `grep -n "ResolveFromOrigin\|func.*TenantResolver" internal/auth/*.go`

If `ResolveFromOrigin` doesn't exist, we need to check what method the TenantResolver exposes and use that. The OIDC callback handler (around line 274-294) shows how it resolves tenants — follow that pattern.

**Step 5: Run test to verify it passes**

Run: `cd /Users/fred/Documents/Valinor && go test ./internal/auth/ -run TestHandleExchange -v`
Expected: PASS (all 4 tests)

**Step 6: Commit**

```bash
git add internal/auth/handler.go internal/auth/exchange_test.go
git commit -m "feat(auth): add POST /auth/exchange endpoint for OIDC token exchange"
```

---

### Task 5: Wire the exchange endpoint in main.go

**Files:**
- Modify: `cmd/valinor/main.go:98-105`

**Step 1: Add id_token validator wiring**

In `cmd/valinor/main.go`, after the `authHandler` is created (around line 105), add the OIDC configuration:

```go
	authHandler := auth.NewHandler(auth.HandlerConfig{
		TokenSvc:       tokenSvc,
		Store:          authStore,
		RefreshStore:   refreshStore,
		StateStore:     stateStore,
		TenantResolver: tenantResolver,
		// OIDC provider wired when configured
	})

	// Wire OIDC token exchange when configured.
	if cfg.Auth.OIDC.Enabled && cfg.Auth.OIDC.JWKSUrl != "" {
		authHandler.SetIDTokenValidator(auth.NewIDTokenValidator(auth.IDTokenValidatorConfig{
			JWKSUrl:  cfg.Auth.OIDC.JWKSUrl,
			Issuer:   cfg.Auth.OIDC.IssuerURL,
			Audience: cfg.Auth.OIDC.ClientID,
			CacheTTL: 1 * time.Hour,
		}))
		slog.Info("OIDC token exchange enabled", "issuer", cfg.Auth.OIDC.IssuerURL)
	}
```

**Step 2: Add the setter method to Handler**

In `internal/auth/handler.go`, add after `NewHandler`:

```go
// SetIDTokenValidator configures the handler for external id_token exchange.
func (h *Handler) SetIDTokenValidator(v *IDTokenValidator) {
	h.idTokenValidator = v
}
```

**Step 3: Verify build**

Run: `cd /Users/fred/Documents/Valinor && go build ./...`
Expected: Clean build

**Step 4: Run full test suite**

Run: `cd /Users/fred/Documents/Valinor && go test ./... 2>&1 | tail -20`
Expected: All packages pass

**Step 5: Commit**

```bash
git add cmd/valinor/main.go internal/auth/handler.go
git commit -m "feat(auth): wire OIDC token exchange in main.go when configured"
```

---

### Task 6: Add Clerk as NextAuth OIDC provider

**Files:**
- Modify: `dashboard/src/lib/auth.ts:1-93`
- Modify: `dashboard/.env.example`

**Step 1: Update auth.ts providers**

In `dashboard/src/lib/auth.ts`, replace the `providers` array (lines 59-93) with dual-provider support:

```typescript
import NextAuth from "next-auth"
import Credentials from "next-auth/providers/credentials"
import type { NextAuthConfig, Account } from "next-auth"

// ... (keep existing type declarations lines 6-54 unchanged) ...

const VALINOR_API_URL = process.env.VALINOR_API_URL ?? "http://localhost:8080"

// Exchange an external OIDC id_token for Valinor platform tokens.
async function exchangeIDToken(idToken: string): Promise<{
  accessToken: string
  refreshToken: string
  expiresIn: number
  user: { id: string; email: string; display_name: string; tenant_id: string; is_platform_admin: boolean }
} | null> {
  const res = await fetch(`${VALINOR_API_URL}/auth/exchange`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id_token: idToken }),
  })
  if (!res.ok) {
    console.error(`Token exchange failed: ${res.status} ${res.statusText}`)
    return null
  }
  return res.json()
}

export const authConfig: NextAuthConfig = {
  providers: [
    // Dev mode credentials (when VALINOR_DEV_MODE is set)
    ...(process.env.VALINOR_DEV_MODE
      ? [
          Credentials({
            credentials: {
              email: { label: "Email", type: "email" },
            },
            async authorize(credentials) {
              if (!credentials?.email) return null

              const res = await fetch(`${VALINOR_API_URL}/auth/dev/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: credentials.email }),
              })

              if (!res.ok) {
                console.error(`Dev login failed: ${res.status} ${res.statusText}`)
                return null
              }

              const data = await res.json()
              const roles = decodeJwtRoles(data.access_token)
              return {
                id: data.user.id,
                email: data.user.email,
                name: data.user.display_name ?? data.user.email,
                tenantId: data.user.tenant_id ?? null,
                isPlatformAdmin: data.user.is_platform_admin ?? false,
                accessToken: data.access_token,
                refreshToken: data.refresh_token,
                expiresIn: data.expires_in ?? 86400,
                roles,
              }
            },
          }),
        ]
      : []),

    // Production OIDC via Clerk (when AUTH_CLERK_ISSUER is set)
    ...(process.env.AUTH_CLERK_ISSUER
      ? [
          {
            id: "clerk",
            name: "Clerk",
            type: "oidc" as const,
            issuer: process.env.AUTH_CLERK_ISSUER,
            clientId: process.env.AUTH_CLERK_ID!,
            clientSecret: process.env.AUTH_CLERK_SECRET!,
          },
        ]
      : []),
  ],
  callbacks: {
    authorized({ auth, request }) {
      const isLoggedIn = !!auth?.user
      const isOnLogin = request.nextUrl.pathname.startsWith("/login")
      if (isOnLogin) return true
      return isLoggedIn
    },
    async signIn({ account }) {
      // For OIDC providers (Clerk), we don't block sign-in here.
      // Token exchange happens in the jwt callback.
      return true
    },
    async jwt({ token, user, account }) {
      // Initial sign-in from credentials (dev mode)
      if (user && account?.provider === "credentials") {
        token.accessToken = user.accessToken
        token.refreshToken = user.refreshToken
        token.expiresAt = Math.floor(Date.now() / 1000) + (user.expiresIn ?? 86400)
        token.userId = user.id ?? ""
        token.tenantId = user.tenantId ?? null
        token.isPlatformAdmin = user.isPlatformAdmin ?? false
        token.roles = user.roles ?? []
        return token
      }

      // Initial sign-in from OIDC (Clerk) — exchange id_token for Valinor tokens
      if (account?.provider === "clerk" && account.id_token) {
        const data = await exchangeIDToken(account.id_token)
        if (!data) {
          throw new Error("Valinor token exchange failed")
        }
        const roles = decodeJwtRoles(data.accessToken)
        token.accessToken = data.accessToken
        token.refreshToken = data.refreshToken
        token.expiresAt = Math.floor(Date.now() / 1000) + (data.expiresIn ?? 3600)
        token.userId = data.user.id
        token.tenantId = data.user.tenant_id ?? null
        token.isPlatformAdmin = data.user.is_platform_admin ?? false
        token.roles = roles
        return token
      }

      // Token still valid
      if (Date.now() < token.expiresAt * 1000) {
        return token
      }

      // Token expired: refresh via Valinor API
      try {
        const res = await fetch(`${VALINOR_API_URL}/auth/token/refresh`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh_token: token.refreshToken }),
        })
        if (!res.ok) throw new Error("refresh failed")
        const data = await res.json()
        token.accessToken = data.access_token
        token.refreshToken = data.refresh_token ?? token.refreshToken
        token.expiresAt = Math.floor(Date.now() / 1000) + (data.expires_in ?? 3600)
        return token
      } catch (err) {
        console.error("Token refresh failed:", err)
        return { ...token, error: "RefreshTokenError" }
      }
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken
      session.user.id = token.userId
      session.user.tenantId = token.tenantId
      session.user.isPlatformAdmin = token.isPlatformAdmin
      session.user.roles = token.roles
      return session
    },
  },
  pages: {
    signIn: "/login",
  },
  session: {
    strategy: "jwt",
  },
}

export const { handlers, auth, signIn, signOut } = NextAuth(authConfig)
```

**Step 2: Fix the exchange response field names**

Note: The `exchangeIDToken` response uses the Go struct field names (`access_token`, `refresh_token`), but in the jwt callback we need to map them correctly:

```typescript
// In the Clerk jwt callback branch:
token.accessToken = data.accessToken   // WRONG — Go returns access_token
```

Fix to:
```typescript
token.accessToken = data.access_token
token.refreshToken = data.refresh_token
token.expiresAt = Math.floor(Date.now() / 1000) + (data.expires_in ?? 3600)
token.userId = data.user.id
token.tenantId = data.user.tenant_id ?? null
token.isPlatformAdmin = data.user.is_platform_admin ?? false
const roles = decodeJwtRoles(data.access_token)
token.roles = roles
```

**Step 3: Update .env.example**

Add Clerk env vars to `dashboard/.env.example`:

```
# Dev mode (local development)
VALINOR_DEV_MODE=true
VALINOR_API_URL=http://localhost:8080
NEXT_PUBLIC_VALINOR_API_URL=http://localhost:8080
AUTH_SECRET=dev-secret-do-not-use-in-production-32ch
AUTH_TRUST_HOST=true
AUTH_URL=http://localhost:3000

# Production OIDC via Clerk (uncomment for production)
# AUTH_CLERK_ISSUER=https://your-clerk-instance.clerk.accounts.dev
# AUTH_CLERK_ID=your_clerk_client_id
# AUTH_CLERK_SECRET=your_clerk_client_secret
```

**Step 4: Verify build**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npx tsc --noEmit`
Expected: No type errors

**Step 5: Commit**

```bash
git add dashboard/src/lib/auth.ts dashboard/.env.example
git commit -m "feat(dashboard): add Clerk as NextAuth OIDC provider alongside dev mode"
```

---

### Task 7: Update the login page for dual-provider support

**Files:**
- Modify: `dashboard/src/app/(auth)/login/page.tsx`

**Step 1: Update the login page**

Replace `dashboard/src/app/(auth)/login/page.tsx`:

```tsx
"use client"

import { signIn } from "next-auth/react"
import { useState } from "react"
import { useRouter } from "next/navigation"

const isDevMode = process.env.NEXT_PUBLIC_VALINOR_DEV_MODE === "true"
const isClerkEnabled = !!process.env.NEXT_PUBLIC_AUTH_CLERK_ENABLED

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  async function handleDevLogin(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setLoading(true)

    const result = await signIn("credentials", {
      email,
      redirect: false,
    })

    setLoading(false)

    if (result?.error) {
      setError("Invalid email or user not found.")
      return
    }

    router.push("/")
    router.refresh()
  }

  async function handleClerkLogin() {
    setLoading(true)
    await signIn("clerk", { redirectTo: "/" })
  }

  return (
    <div className="flex min-h-[100dvh] items-center justify-center bg-zinc-50">
      <div className="w-full max-w-sm space-y-6">
        <div className="text-center">
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
            Valinor Dashboard
          </h1>
          <p className="mt-2 text-sm text-zinc-500">
            Sign in to manage your AI agent infrastructure.
          </p>
        </div>

        {isClerkEnabled && (
          <>
            <button
              type="button"
              onClick={handleClerkLogin}
              disabled={loading}
              className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? "Redirecting..." : "Sign in"}
            </button>
            {isDevMode && (
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-zinc-200" />
                </div>
                <div className="relative flex justify-center text-xs">
                  <span className="bg-zinc-50 px-2 text-zinc-400">or</span>
                </div>
              </div>
            )}
          </>
        )}

        {isDevMode && (
          <>
            <form onSubmit={handleDevLogin} className="space-y-4">
              <div className="space-y-2">
                <label
                  htmlFor="email"
                  className="text-sm font-medium text-zinc-700"
                >
                  Email
                </label>
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  required
                  className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400"
                />
              </div>
              {error && (
                <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
                  <p className="text-sm text-rose-700">{error}</p>
                </div>
              )}
              <button
                type="submit"
                disabled={loading || !email}
                className="w-full rounded-lg border border-zinc-200 bg-white px-4 py-2.5 text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-50 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? "Signing in..." : "Sign in (Dev Mode)"}
              </button>
            </form>
            <p className="text-center text-xs text-zinc-400">
              Dev mode authentication. Enter any existing user email.
            </p>
          </>
        )}
      </div>
    </div>
  )
}
```

**Step 2: Add the NEXT_PUBLIC env vars to .env.example**

Add to `dashboard/.env.example`:
```
NEXT_PUBLIC_VALINOR_DEV_MODE=true
# NEXT_PUBLIC_AUTH_CLERK_ENABLED=true
```

**Step 3: Verify build**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npx tsc --noEmit`
Expected: No type errors

**Step 4: Commit**

```bash
git add dashboard/src/app/(auth)/login/page.tsx dashboard/.env.example
git commit -m "feat(dashboard): update login page for Clerk + dev mode dual-provider"
```

---

### Task 8: Add TenantResolver.ResolveFromOrigin helper

**Files:**
- Modify: `internal/auth/` (check existing TenantResolver methods)

**Step 1: Check existing TenantResolver API**

Run: `grep -n 'func.*TenantResolver' internal/auth/*.go`

Review what methods exist. The HandleCallback (handler.go:274-294) shows the current tenant resolution pattern. We need a method that takes an `Origin` header value like `https://gondolin.valinor.app` and returns a tenant ID.

**Step 2: Write failing test for ResolveFromOrigin**

If the method doesn't exist, create a test in the appropriate test file that calls `resolver.ResolveFromOrigin("https://gondolin.valinor.app")` and expects the tenant ID back.

**Step 3: Implement ResolveFromOrigin**

Parse the URL, extract the subdomain relative to the configured `baseDomain`, and call the existing tenant lookup query.

**Step 4: Run tests**

Run: `cd /Users/fred/Documents/Valinor && go test ./internal/auth/ -v`
Expected: All pass

**Step 5: Commit**

```bash
git add internal/auth/
git commit -m "feat(auth): add ResolveFromOrigin to TenantResolver"
```

---

### Task 9: Full integration verification

**Files:** None (verification only)

**Step 1: Run Go test suite**

Run: `cd /Users/fred/Documents/Valinor && go test ./... 2>&1 | tail -25`
Expected: All 16+ packages pass

**Step 2: Run dashboard build**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npx tsc --noEmit`
Expected: No type errors

**Step 3: Run existing E2E tests (dev mode still works)**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npx playwright test --reporter=list`
Expected: All 18 tests pass (dev mode login is unchanged)

**Step 4: Manual smoke test**

1. Ensure `config.yaml` has `auth.devmode: true` and `auth.oidc.enabled: false`
2. Start backend: `cd /tmp/valinor && ./valinor`
3. Start dashboard: `cd dashboard && npm run dev`
4. Visit `http://localhost:3000/login`
5. Dev mode login should work as before
6. Verify no regressions

**Step 5: Verify OIDC exchange endpoint registration**

Temporarily set `auth.oidc.enabled: true` with dummy values in `config.yaml`:
```yaml
auth:
  oidc:
    enabled: true
    issuerurl: "https://example.clerk.accounts.dev"
    clientid: "test"
    jwksurl: "https://example.clerk.accounts.dev/.well-known/jwks.json"
```

Rebuild and check logs for `"OIDC token exchange enabled"` message.

Run: `curl -s -X POST http://localhost:8080/auth/exchange -H "Content-Type: application/json" -d '{"id_token":"invalid"}' | jq .`
Expected: `{"error": "invalid id_token"}` with 401 status (proves endpoint is live)

Revert config.yaml back to `auth.oidc.enabled: false`.

**Step 6: Commit any final adjustments**

```bash
git add -A
git commit -m "test: verify production auth integration"
```
