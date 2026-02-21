# Phase 3 P1: RLS Tests + Tenant Provisioning + Platform Admin

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Prove RLS tenant isolation works at the database level, add a platform admin auth concept, and build the tenant provisioning API.

**Architecture:** Platform admin is modeled as a boolean flag on the users table. Tenant CRUD lives in `internal/tenant` (separate package from auth). RLS tests use two-tenant fixtures to verify isolation across every RLS-protected table. The existing `handleListAgents` stub is wired to `WithTenantConnection` as the reference pattern.

**Tech Stack:** Go 1.22+, pgx/v5, testcontainers-go, golang-jwt/v5

---

### Task 1: Migration — `is_platform_admin` Column

**Files:**
- Create: `migrations/000005_platform_admin.up.sql`
- Create: `migrations/000005_platform_admin.down.sql`

**Step 1: Write the up migration**

```sql
-- Platform admin flag for cross-tenant operations.
-- Revisit: once we discover what platform-level operations exist beyond
-- tenant CRUD, may need to graduate to platform_role TEXT or a table.
ALTER TABLE users ADD COLUMN is_platform_admin BOOLEAN NOT NULL DEFAULT false;
```

**Step 2: Write the down migration**

```sql
ALTER TABLE users DROP COLUMN IF EXISTS is_platform_admin;
```

**Step 3: Verify migrations compile**

Run: `go build ./...`
Expected: PASS (migrations are loaded at runtime, but build verifies no Go breakage)

**Step 4: Commit**

```bash
git add migrations/000005_platform_admin.up.sql migrations/000005_platform_admin.down.sql
git commit -m "migration: add is_platform_admin column to users"
```

---

### Task 2: Identity + JWT Claims — Platform Admin

**Files:**
- Modify: `internal/auth/auth.go:19-30` (Identity struct)
- Modify: `internal/auth/token.go:11-22` (valinorClaims struct)
- Modify: `internal/auth/token.go:49-72` (createToken)
- Modify: `internal/auth/token.go:94-105` (ValidateToken return)
- Modify: `internal/auth/token_test.go` (add test)

**Step 1: Write the failing test**

Add to `internal/auth/token_test.go`:

```go
func TestTokenService_PlatformAdminClaim(t *testing.T) {
	svc := newTestTokenService()
	identity := &auth.Identity{
		UserID:          "admin-1",
		Email:           "admin@valinor.com",
		IsPlatformAdmin: true,
	}

	token, err := svc.CreateAccessToken(identity)
	require.NoError(t, err)

	parsed, err := svc.ValidateToken(token)
	require.NoError(t, err)
	assert.True(t, parsed.IsPlatformAdmin)
}

func TestTokenService_NonPlatformAdminOmitsClaim(t *testing.T) {
	svc := newTestTokenService()
	identity := &auth.Identity{
		UserID:   "user-1",
		TenantID: "tenant-1",
	}

	token, err := svc.CreateAccessToken(identity)
	require.NoError(t, err)

	parsed, err := svc.ValidateToken(token)
	require.NoError(t, err)
	assert.False(t, parsed.IsPlatformAdmin)
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/auth/ -run TestTokenService_PlatformAdmin -count=1`
Expected: FAIL (IsPlatformAdmin field doesn't exist)

**Step 3: Add IsPlatformAdmin to Identity**

In `internal/auth/auth.go`, add to the Identity struct after `Generation`:

```go
IsPlatformAdmin bool `json:"is_platform_admin,omitempty"`
```

**Step 4: Add claim to valinorClaims**

In `internal/auth/token.go`, add to valinorClaims after `Generation`:

```go
IsPlatformAdmin bool `json:"pa,omitempty"`
```

**Step 5: Wire through createToken**

In `internal/auth/token.go:49-68`, add to the claims struct literal after `Generation`:

```go
IsPlatformAdmin: identity.IsPlatformAdmin,
```

**Step 6: Wire through ValidateToken**

In `internal/auth/token.go:94-104`, add to the returned Identity after `Generation`:

```go
IsPlatformAdmin: claims.IsPlatformAdmin,
```

**Step 7: Run tests to verify they pass**

Run: `go test ./internal/auth/ -run TestTokenService_PlatformAdmin -count=1`
Expected: PASS

Run: `go test -short ./... -count=1`
Expected: all PASS

**Step 8: Commit**

```bash
git add internal/auth/auth.go internal/auth/token.go internal/auth/token_test.go
git commit -m "feat: add IsPlatformAdmin to Identity and JWT claims"
```

---

### Task 3: RequirePlatformAdmin Middleware

**Files:**
- Modify: `internal/auth/middleware.go` (add function)
- Modify: `internal/auth/middleware_test.go` (create if needed, add tests)

**Step 1: Write the failing tests**

Create `internal/auth/middleware_test.go` (if it doesn't exist):

```go
package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valinor-ai/valinor/internal/auth"
)

func TestRequirePlatformAdmin_Allows(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	identity := &auth.Identity{
		UserID:          "admin-1",
		IsPlatformAdmin: true,
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()

	auth.RequirePlatformAdmin(inner).ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequirePlatformAdmin_DeniesNonAdmin(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	identity := &auth.Identity{
		UserID:   "user-1",
		TenantID: "tenant-1",
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()

	auth.RequirePlatformAdmin(inner).ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequirePlatformAdmin_DeniesNoIdentity(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	auth.RequirePlatformAdmin(inner).ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/auth/ -run TestRequirePlatformAdmin -count=1`
Expected: FAIL (RequirePlatformAdmin not defined)

**Step 3: Implement RequirePlatformAdmin**

Add to `internal/auth/middleware.go`:

```go
// RequirePlatformAdmin returns middleware that restricts access to platform admins.
func RequirePlatformAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := GetIdentity(r.Context())
		if identity == nil {
			writeAuthError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		if !identity.IsPlatformAdmin {
			writeAuthError(w, http.StatusForbidden, "platform admin required")
			return
		}

		next.ServeHTTP(w, r)
	})
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/auth/ -run TestRequirePlatformAdmin -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/auth/middleware.go internal/auth/middleware_test.go
git commit -m "feat: add RequirePlatformAdmin middleware"
```

---

### Task 4: Auth Store — Load IsPlatformAdmin

**Files:**
- Modify: `internal/auth/store.go:67-136` (GetIdentityWithRoles)
- Modify: `internal/auth/store_test.go` (add test)

**Step 1: Write the failing test**

Add to `internal/auth/store_test.go`:

```go
func TestStore_GetIdentityWithRoles_PlatformAdmin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := auth.NewStore(pool)

	// Create tenant and platform admin user
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id",
		"Platform", "platform",
	).Scan(&tenantID)
	require.NoError(t, err)

	var userID string
	err = pool.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, display_name, oidc_subject, oidc_issuer, is_platform_admin)
		 VALUES ($1, $2, $3, $4, $5, true) RETURNING id`,
		tenantID, "admin@valinor.com", "Admin", "google-admin", "https://accounts.google.com",
	).Scan(&userID)
	require.NoError(t, err)

	identity, err := store.GetIdentityWithRoles(ctx, userID)
	require.NoError(t, err)
	assert.True(t, identity.IsPlatformAdmin)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -run TestStore_GetIdentityWithRoles_PlatformAdmin -count=1`
Expected: FAIL (IsPlatformAdmin not loaded from DB)

**Step 3: Update GetIdentityWithRoles**

In `internal/auth/store.go:67-79`, modify the SELECT and Scan to include `is_platform_admin`:

Change the query from:
```go
"SELECT tenant_id, email, COALESCE(display_name, '') FROM users WHERE id = $1"
```
to:
```go
"SELECT tenant_id, email, COALESCE(display_name, ''), is_platform_admin FROM users WHERE id = $1"
```

Add `isPlatformAdmin bool` variable and scan it:
```go
var tenantID, email, displayName string
var isPlatformAdmin bool
err := s.pool.QueryRow(ctx,
	"SELECT tenant_id, email, COALESCE(display_name, ''), is_platform_admin FROM users WHERE id = $1",
	userID,
).Scan(&tenantID, &email, &displayName, &isPlatformAdmin)
```

Then add to the returned Identity:
```go
IsPlatformAdmin: isPlatformAdmin,
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/auth/ -run TestStore_GetIdentityWithRoles -count=1`
Expected: PASS (both existing and new test)

**Step 5: Commit**

```bash
git add internal/auth/store.go internal/auth/store_test.go
git commit -m "feat: load is_platform_admin in GetIdentityWithRoles"
```

---

### Task 5: HandleCallback — Tenantless Platform Admin Path

**Files:**
- Modify: `internal/auth/handler.go:146-159` (HandleCallback tenant resolution block)
- Modify: `internal/auth/store.go` (add LookupPlatformAdminByOIDC)
- Modify: `internal/auth/handler_test.go` (add test)

**Step 1: Write the failing test**

Add to `internal/auth/handler_test.go`:

```go
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

	// TenantResolver that always fails (simulating base domain access)
	handler := auth.NewHandler(auth.HandlerConfig{
		TokenSvc:   tokenSvc,
		Store:      store,
		OIDC:       oidcProvider,
		StateStore: stateStore,
		// No TenantResolver — simulates base domain access
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -run TestHandler_Callback_PlatformAdminNoTenant -count=1`
Expected: FAIL (handler returns 503 "tenant resolution not configured")

**Step 3: Add LookupPlatformAdminByOIDC to Store**

Add to `internal/auth/store.go`:

```go
// LookupPlatformAdminByOIDC looks up a platform admin by OIDC credentials.
// Returns nil, nil if the user exists but is not a platform admin.
// Returns nil, ErrUserNotFound if no matching user exists.
func (s *Store) LookupPlatformAdminByOIDC(ctx context.Context, issuer, subject string) (*Identity, error) {
	var userID string
	var isPlatformAdmin bool
	err := s.pool.QueryRow(ctx,
		"SELECT id, is_platform_admin FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2",
		issuer, subject,
	).Scan(&userID, &isPlatformAdmin)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("looking up platform admin: %w", err)
	}

	if !isPlatformAdmin {
		return nil, nil
	}

	return s.GetIdentityWithRoles(ctx, userID)
}
```

**Step 4: Modify HandleCallback for tenantless path**

In `internal/auth/handler.go`, replace lines 146-159 (the tenant resolution block) with:

```go
	// Resolve tenant from subdomain
	var tenantID string
	if h.tenantResolver != nil {
		tid, resolveErr := h.tenantResolver.ResolveFromRequest(r.Context(), r)
		if resolveErr != nil {
			// No tenant resolved — check if this is a platform admin on the base domain
			if h.store != nil {
				adminIdentity, adminErr := h.store.LookupPlatformAdminByOIDC(r.Context(), userInfo.Issuer, userInfo.Subject)
				if adminErr == nil && adminIdentity != nil {
					// Platform admin — issue tokens without tenant scope
					accessToken, tokenErr := h.tokenSvc.CreateAccessToken(adminIdentity)
					if tokenErr != nil {
						writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token creation failed"})
						return
					}
					refreshToken, tokenErr := h.tokenSvc.CreateRefreshToken(adminIdentity)
					if tokenErr != nil {
						writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token creation failed"})
						return
					}
					writeJSON(w, http.StatusOK, map[string]string{
						"access_token":  accessToken,
						"refresh_token": refreshToken,
						"token_type":    "Bearer",
					})
					return
				}
			}
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot resolve tenant"})
			return
		}
		tenantID = tid
	} else {
		// No TenantResolver configured — check for platform admin via OIDC exchange
		if h.store != nil {
			adminIdentity, adminErr := h.store.LookupPlatformAdminByOIDC(r.Context(), userInfo.Issuer, userInfo.Subject)
			if adminErr == nil && adminIdentity != nil {
				accessToken, tokenErr := h.tokenSvc.CreateAccessToken(adminIdentity)
				if tokenErr != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token creation failed"})
					return
				}
				refreshToken, tokenErr := h.tokenSvc.CreateRefreshToken(adminIdentity)
				if tokenErr != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token creation failed"})
					return
				}
				writeJSON(w, http.StatusOK, map[string]string{
					"access_token":  accessToken,
					"refresh_token": refreshToken,
					"token_type":    "Bearer",
				})
				return
			}
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tenant resolution not configured"})
		return
	}
```

Note: the OIDC exchange (`h.oidc.Exchange`) must happen **before** the tenant resolution block. Currently it happens after (lines 161-168). Move the exchange block to before tenant resolution. The test `TestHandler_Callback_PlatformAdminNoTenant` depends on having userInfo available when the tenant resolution branch executes.

**Step 5: Run tests to verify they pass**

Run: `go test ./internal/auth/ -run TestHandler_Callback -count=1`
Expected: PASS (all callback tests, including new platform admin one)

Run: `go test -short ./... -count=1`
Expected: all PASS

**Step 6: Commit**

```bash
git add internal/auth/store.go internal/auth/handler.go internal/auth/handler_test.go
git commit -m "feat: platform admin tenantless callback path"
```

---

### Task 6: Seed Script

**Files:**
- Create: `scripts/seed_platform_admin.sql`

**Step 1: Write the seed script**

```sql
-- Seed a platform admin user.
-- Run this once after initial deployment:
--   psql $DATABASE_URL -f scripts/seed_platform_admin.sql
--
-- Customize the VALUES below for your environment.
-- The user must already exist via OIDC login, OR you can insert directly.

-- Option A: Promote an existing user to platform admin
-- UPDATE users SET is_platform_admin = true WHERE email = 'admin@yourcompany.com';

-- Option B: Create a bootstrap tenant + platform admin user
INSERT INTO tenants (name, slug) VALUES ('Platform Operations', 'platform-ops')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO users (tenant_id, email, display_name, oidc_subject, oidc_issuer, is_platform_admin)
VALUES (
    (SELECT id FROM tenants WHERE slug = 'platform-ops'),
    'admin@example.com',       -- CHANGE THIS
    'Platform Admin',
    'replace-with-oidc-sub',   -- CHANGE THIS
    'https://accounts.google.com',
    true
)
ON CONFLICT (oidc_issuer, oidc_subject) DO UPDATE SET is_platform_admin = true;
```

**Step 2: Commit**

```bash
git add scripts/seed_platform_admin.sql
git commit -m "chore: add platform admin seed script"
```

---

### Task 7: Tenant Package — Store (TDD)

**Files:**
- Create: `internal/tenant/tenant.go`
- Create: `internal/tenant/store.go`
- Create: `internal/tenant/store_test.go`

**Step 1: Write the domain types**

Create `internal/tenant/tenant.go`:

```go
package tenant

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

var (
	ErrTenantNotFound = errors.New("tenant not found")
	ErrSlugTaken      = errors.New("tenant slug already in use")
	ErrInvalidSlug    = errors.New("invalid tenant slug")
)

// Tenant represents a tenant in the system.
type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

var slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$`)

var reservedSlugs = map[string]bool{
	"api": true, "app": true, "www": true, "admin": true,
	"platform": true, "auth": true, "static": true, "assets": true,
}

// ValidateSlug checks that a slug conforms to DNS label rules and is not reserved.
func ValidateSlug(slug string) error {
	if !slugPattern.MatchString(slug) {
		return fmt.Errorf("%w: must be 3-63 lowercase alphanumeric characters or hyphens, cannot start/end with hyphen", ErrInvalidSlug)
	}
	if reservedSlugs[slug] {
		return fmt.Errorf("%w: %q is reserved", ErrInvalidSlug, slug)
	}
	return nil
}
```

**Step 2: Write the failing store tests**

Create `internal/tenant/store_test.go`:

```go
package tenant_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/tenant"
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

func TestStore_Create(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	ctx := context.Background()

	created, err := store.Create(ctx, "Chelsea FC", "chelsea-fc")
	require.NoError(t, err)
	assert.NotEmpty(t, created.ID)
	assert.Equal(t, "Chelsea FC", created.Name)
	assert.Equal(t, "chelsea-fc", created.Slug)
	assert.Equal(t, "active", created.Status)
}

func TestStore_Create_DuplicateSlug(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	ctx := context.Background()

	_, err := store.Create(ctx, "Chelsea FC", "chelsea-fc")
	require.NoError(t, err)

	_, err = store.Create(ctx, "Chelsea FC 2", "chelsea-fc")
	assert.ErrorIs(t, err, tenant.ErrSlugTaken)
}

func TestStore_GetByID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	ctx := context.Background()

	created, err := store.Create(ctx, "Chelsea FC", "chelsea-fc")
	require.NoError(t, err)

	got, err := store.GetByID(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, "Chelsea FC", got.Name)
	assert.Equal(t, "chelsea-fc", got.Slug)
}

func TestStore_GetByID_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	ctx := context.Background()

	_, err := store.GetByID(ctx, "00000000-0000-0000-0000-000000000000")
	assert.ErrorIs(t, err, tenant.ErrTenantNotFound)
}

func TestStore_List(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	ctx := context.Background()

	_, err := store.Create(ctx, "Tenant A", "tenant-a")
	require.NoError(t, err)
	_, err = store.Create(ctx, "Tenant B", "tenant-b")
	require.NoError(t, err)

	tenants, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, tenants, 2)
}

func TestValidateSlug(t *testing.T) {
	tests := []struct {
		slug    string
		wantErr bool
	}{
		{"chelsea-fc", false},
		{"abc", false},
		{"a-b", false},
		{"ab", true},                 // too short
		{"-abc", true},               // starts with hyphen
		{"abc-", true},               // ends with hyphen
		{"ABC", true},                // uppercase
		{"a b", true},                // space
		{"api", true},                // reserved
		{"www", true},                // reserved
		{"admin", true},              // reserved
	}

	for _, tt := range tests {
		t.Run(tt.slug, func(t *testing.T) {
			err := tenant.ValidateSlug(tt.slug)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
```

**Step 3: Run tests to verify they fail**

Run: `go test ./internal/tenant/ -run TestStore -count=1`
Expected: FAIL (package doesn't exist yet / Store not defined)

**Step 4: Implement the Store**

Create `internal/tenant/store.go`:

```go
package tenant

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store handles tenant database operations.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new tenant store.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Create inserts a new tenant with the given name and slug.
func (s *Store) Create(ctx context.Context, name, slug string) (*Tenant, error) {
	if err := ValidateSlug(slug); err != nil {
		return nil, err
	}

	var t Tenant
	err := s.pool.QueryRow(ctx,
		`INSERT INTO tenants (name, slug) VALUES ($1, $2)
		 RETURNING id, name, slug, status, created_at, updated_at`,
		name, slug,
	).Scan(&t.ID, &t.Name, &t.Slug, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique constraint") {
			return nil, fmt.Errorf("%w: %s", ErrSlugTaken, slug)
		}
		return nil, fmt.Errorf("creating tenant: %w", err)
	}
	return &t, nil
}

// GetByID retrieves a tenant by its UUID.
func (s *Store) GetByID(ctx context.Context, id string) (*Tenant, error) {
	var t Tenant
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, slug, status, created_at, updated_at
		 FROM tenants WHERE id = $1`,
		id,
	).Scan(&t.ID, &t.Name, &t.Slug, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTenantNotFound
		}
		return nil, fmt.Errorf("getting tenant: %w", err)
	}
	return &t, nil
}

// List returns all tenants.
func (s *Store) List(ctx context.Context) ([]Tenant, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, slug, status, created_at, updated_at
		 FROM tenants ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("listing tenants: %w", err)
	}
	defer rows.Close()

	var tenants []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Slug, &t.Status, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning tenant: %w", err)
		}
		tenants = append(tenants, t)
	}
	return tenants, rows.Err()
}
```

**Step 5: Run tests to verify they pass**

Run: `go test ./internal/tenant/ -run "TestStore|TestValidateSlug" -count=1`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/tenant/
git commit -m "feat: add tenant package with Store and slug validation"
```

---

### Task 8: Tenant HTTP Handler

**Files:**
- Create: `internal/tenant/handler.go`
- Create: `internal/tenant/handler_test.go`

**Step 1: Write the failing handler tests**

Create `internal/tenant/handler_test.go`:

```go
package tenant_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/tenant"
)

func withPlatformAdmin(req *http.Request) *http.Request {
	identity := &auth.Identity{
		UserID:          "admin-1",
		IsPlatformAdmin: true,
	}
	return req.WithContext(auth.WithIdentity(req.Context(), identity))
}

func TestHandler_CreateTenant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	handler := tenant.NewHandler(store)

	body := `{"name": "Chelsea FC", "slug": "chelsea-fc"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withPlatformAdmin(req)
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp tenant.Tenant
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Chelsea FC", resp.Name)
	assert.Equal(t, "chelsea-fc", resp.Slug)
	assert.NotEmpty(t, resp.ID)
}

func TestHandler_CreateTenant_InvalidSlug(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	handler := tenant.NewHandler(store)

	body := `{"name": "Bad", "slug": "api"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withPlatformAdmin(req)
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_GetTenant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	handler := tenant.NewHandler(store)

	created, err := store.Create(context.Background(), "Chelsea FC", "chelsea-fc")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+created.ID, nil)
	req.SetPathValue("id", created.ID)
	req = withPlatformAdmin(req)
	w := httptest.NewRecorder()

	handler.HandleGet(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp tenant.Tenant
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Chelsea FC", resp.Name)
}

func TestHandler_ListTenants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	handler := tenant.NewHandler(store)

	_, err := store.Create(context.Background(), "Tenant A", "tenant-a")
	require.NoError(t, err)
	_, err = store.Create(context.Background(), "Tenant B", "tenant-b")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	req = withPlatformAdmin(req)
	w := httptest.NewRecorder()

	handler.HandleList(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp []tenant.Tenant
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp, 2)
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/tenant/ -run TestHandler -count=1`
Expected: FAIL (Handler not defined)

**Step 3: Implement the Handler**

Create `internal/tenant/handler.go`:

```go
package tenant

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Handler handles tenant HTTP endpoints.
type Handler struct {
	store *Store
}

// NewHandler creates a new tenant handler.
func NewHandler(store *Store) *Handler {
	return &Handler{store: store}
}

// RegisterRoutes registers tenant routes on the given mux.
// All routes require platform admin auth (applied externally via middleware).
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/tenants", h.HandleCreate)
	mux.HandleFunc("GET /api/v1/tenants/{id}", h.HandleGet)
	mux.HandleFunc("GET /api/v1/tenants", h.HandleList)
}

// HandleCreate creates a new tenant.
func (h *Handler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

	var req struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Name == "" || req.Slug == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and slug are required"})
		return
	}

	t, err := h.store.Create(r.Context(), req.Name, req.Slug)
	if err != nil {
		if errors.Is(err, ErrInvalidSlug) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if errors.Is(err, ErrSlugTaken) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tenant creation failed"})
		return
	}

	writeJSON(w, http.StatusCreated, t)
}

// HandleGet returns a tenant by ID.
func (h *Handler) HandleGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing tenant id"})
		return
	}

	t, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetching tenant failed"})
		return
	}

	writeJSON(w, http.StatusOK, t)
}

// HandleList returns all tenants.
func (h *Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	tenants, err := h.store.List(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "listing tenants failed"})
		return
	}

	if tenants == nil {
		tenants = []Tenant{}
	}

	writeJSON(w, http.StatusOK, tenants)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/tenant/ -run TestHandler -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/tenant/handler.go internal/tenant/handler_test.go
git commit -m "feat: add tenant HTTP handler (create, get, list)"
```

---

### Task 9: Wire Tenant Routes into Server

**Files:**
- Modify: `internal/platform/server/server.go:20-28` (Dependencies)
- Modify: `internal/platform/server/server.go:37-94` (New function)
- Modify: `cmd/valinor/main.go` (create tenant handler, pass to server)

**Step 1: Add TenantHandler to Dependencies**

In `internal/platform/server/server.go`, add import:
```go
"github.com/valinor-ai/valinor/internal/tenant"
```

Add to Dependencies struct:
```go
TenantHandler *tenant.Handler
```

**Step 2: Register tenant routes with platform admin guard**

In `server.go`, after the RBAC route block (line 80), add:

```go
	// Platform admin routes (tenant provisioning)
	if deps.TenantHandler != nil {
		protectedMux.Handle("POST /api/v1/tenants",
			auth.RequirePlatformAdmin(http.HandlerFunc(deps.TenantHandler.HandleCreate)),
		)
		protectedMux.Handle("GET /api/v1/tenants/{id}",
			auth.RequirePlatformAdmin(http.HandlerFunc(deps.TenantHandler.HandleGet)),
		)
		protectedMux.Handle("GET /api/v1/tenants",
			auth.RequirePlatformAdmin(http.HandlerFunc(deps.TenantHandler.HandleList)),
		)
	}
```

**Step 3: Wire in main.go**

In `cmd/valinor/main.go`, add import:
```go
"github.com/valinor-ai/valinor/internal/tenant"
```

After the `authHandler` creation, add:
```go
	var tenantHandler *tenant.Handler
	if pool != nil {
		tenantStore := tenant.NewStore(pool)
		tenantHandler = tenant.NewHandler(tenantStore)
	}
```

Add to server.Dependencies:
```go
TenantHandler: tenantHandler,
```

**Step 4: Build and run short tests**

Run: `go build ./... && go test -short ./... -count=1`
Expected: all PASS

**Step 5: Commit**

```bash
git add internal/platform/server/server.go cmd/valinor/main.go
git commit -m "feat: wire tenant provisioning routes into server"
```

---

### Task 10: RLS Integration Tests

**Files:**
- Create: `internal/platform/database/rls_test.go`

**Step 1: Write the RLS test file**

Create `internal/platform/database/rls_test.go`:

```go
package database_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

// setupRLSTestDB creates a test database with a non-superuser role.
// RLS policies are enforced for non-superuser connections.
func setupRLSTestDB(t *testing.T) (*database.Pool, func()) {
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

	// Run migrations as superuser
	err = database.RunMigrations(connStr, "file://../../migrations")
	require.NoError(t, err)

	// Create a non-superuser role that respects RLS
	superPool, err := database.Connect(ctx, connStr, 2)
	require.NoError(t, err)

	_, err = superPool.Exec(ctx, `
		CREATE ROLE rls_user LOGIN PASSWORD 'rls_pass';
		GRANT USAGE ON SCHEMA public TO rls_user;
		GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO rls_user;
	`)
	require.NoError(t, err)
	superPool.Close()

	// Connect as non-superuser (RLS now enforced)
	// Replace username/password in connection string
	rlsConnStr := replaceUserInConnStr(connStr, "rls_user", "rls_pass")
	pool, err := database.Connect(ctx, rlsConnStr, 5)
	require.NoError(t, err)

	cleanup := func() {
		pool.Close()
		_ = container.Terminate(ctx)
	}

	return pool, cleanup
}

// replaceUserInConnStr swaps the user and password in a postgres connection string.
func replaceUserInConnStr(connStr, user, password string) string {
	// connStr format: postgres://test:test@host:port/db?sslmode=disable
	// Replace test:test with user:password
	return strings.Replace(
		strings.Replace(connStr, "test:test", user+":"+password, 1),
		"", "", 0,
	)
}

// seedTwoTenants creates two tenants with data in all RLS-protected tables.
// Returns (tenantAID, tenantBID).
func seedTwoTenants(t *testing.T, superConnStr string) (string, string) {
	t.Helper()
	ctx := context.Background()

	// Connect as superuser for seeding (bypasses RLS)
	pool, err := database.Connect(ctx, superConnStr, 2)
	require.NoError(t, err)
	defer pool.Close()

	var tenantA, tenantB string
	err = pool.QueryRow(ctx, "INSERT INTO tenants (name, slug) VALUES ('Tenant A', 'tenant-a') RETURNING id").Scan(&tenantA)
	require.NoError(t, err)
	err = pool.QueryRow(ctx, "INSERT INTO tenants (name, slug) VALUES ('Tenant B', 'tenant-b') RETURNING id").Scan(&tenantB)
	require.NoError(t, err)

	// Users
	_, err = pool.Exec(ctx, "INSERT INTO users (tenant_id, email, display_name) VALUES ($1, 'a@a.com', 'User A')", tenantA)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "INSERT INTO users (tenant_id, email, display_name) VALUES ($1, 'b@b.com', 'User B')", tenantB)
	require.NoError(t, err)

	// Departments
	_, err = pool.Exec(ctx, "INSERT INTO departments (tenant_id, name) VALUES ($1, 'Dept A')", tenantA)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "INSERT INTO departments (tenant_id, name) VALUES ($1, 'Dept B')", tenantB)
	require.NoError(t, err)

	// Roles
	_, err = pool.Exec(ctx, "INSERT INTO roles (tenant_id, name, permissions) VALUES ($1, 'admin', '[\"*\"]')", tenantA)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "INSERT INTO roles (tenant_id, name, permissions) VALUES ($1, 'admin', '[\"*\"]')", tenantB)
	require.NoError(t, err)

	// Agent instances
	_, err = pool.Exec(ctx, "INSERT INTO agent_instances (tenant_id, status) VALUES ($1, 'active')", tenantA)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "INSERT INTO agent_instances (tenant_id, status) VALUES ($1, 'active')", tenantB)
	require.NoError(t, err)

	// Connectors
	_, err = pool.Exec(ctx, "INSERT INTO connectors (tenant_id, name, endpoint) VALUES ($1, 'Conn A', 'https://a.com')", tenantA)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "INSERT INTO connectors (tenant_id, name, endpoint) VALUES ($1, 'Conn B', 'https://b.com')", tenantB)
	require.NoError(t, err)

	// Resource policies
	_, err = pool.Exec(ctx,
		"INSERT INTO resource_policies (tenant_id, subject_type, subject_id, action, resource_type, effect) VALUES ($1, 'role', $1, 'read', 'agent', 'allow')", tenantA)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		"INSERT INTO resource_policies (tenant_id, subject_type, subject_id, action, resource_type, effect) VALUES ($1, 'role', $1, 'read', 'agent', 'allow')", tenantB)
	require.NoError(t, err)

	return tenantA, tenantB
}

func countRows(t *testing.T, ctx context.Context, q database.Querier, table string) int {
	t.Helper()
	var count int
	err := q.QueryRow(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count)
	require.NoError(t, err)
	return count
}

func TestRLS_TenantIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupRLSTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Seed via superuser (need the original connStr — we'll get it from container)
	// For simplicity, seed before connecting as rls_user.
	// Actually, we need to restructure: seed as superuser, then query as rls_user.
	// Let's adjust the setup to return both.

	// ... (see implementation note below)
}
```

**Implementation note:** The test setup needs both a superuser connection (for seeding) and a non-superuser connection (for RLS testing). Restructure `setupRLSTestDB` to return both the superuser connStr and the rls_user pool.

The actual test body for each table follows this pattern:

```go
t.Run("users", func(t *testing.T) {
	err := database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		count := countRows(t, ctx, q, "users")
		assert.Equal(t, 1, count)
		return nil
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantB, func(ctx context.Context, q database.Querier) error {
		count := countRows(t, ctx, q, "users")
		assert.Equal(t, 1, count)
		return nil
	})
	require.NoError(t, err)
})
```

Repeat for: departments, roles, agent_instances, connectors, resource_policies.

Add a test for no tenant set:
```go
t.Run("no tenant set returns empty", func(t *testing.T) {
	var count int
	err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
})
```

**Step 2: Run tests**

Run: `go test ./internal/platform/database/ -run TestRLS -count=1`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/platform/database/rls_test.go
git commit -m "test: add RLS tenant isolation integration tests"
```

---

### Task 11: Wire handleListAgents with WithTenantConnection

**Files:**
- Modify: `internal/platform/server/server.go:160-163` (handleListAgents)

**Step 1: Replace the stub handler**

Replace `handleListAgents` in `server.go`:

```go
func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	if s.pool == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database not available"})
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	type agentInstance struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}

	var agents []agentInstance
	err := database.WithTenantConnection(r.Context(), s.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		rows, queryErr := q.Query(ctx, "SELECT id, status FROM agent_instances")
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()

		for rows.Next() {
			var a agentInstance
			if scanErr := rows.Scan(&a.ID, &a.Status); scanErr != nil {
				return scanErr
			}
			agents = append(agents, a)
		}
		return rows.Err()
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list agents"})
		return
	}

	if agents == nil {
		agents = []agentInstance{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"agents": agents})
}
```

Add import for `database`:
```go
"github.com/valinor-ai/valinor/internal/platform/database"
```

**Step 2: Build and test**

Run: `go build ./... && go test -short ./... -count=1`
Expected: all PASS

**Step 3: Commit**

```bash
git add internal/platform/server/server.go
git commit -m "feat: wire handleListAgents with WithTenantConnection (RLS reference pattern)"
```

---

### Task 12: Final Verification

**Step 1: Run vet, build, and short tests**

```bash
go vet ./...
go build ./...
go test -short ./... -count=1
```

Expected: all PASS with no warnings.

**Step 2: Update docs/lessons.md**

Add entry about RLS pattern and platform admin revisit note.

**Step 3: Commit any remaining changes**

```bash
git add -A
git commit -m "chore: final cleanup for Phase 3 P1"
```
