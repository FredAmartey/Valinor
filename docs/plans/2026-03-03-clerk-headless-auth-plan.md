# Clerk Headless Auth Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace Clerk OIDC redirect with headless `@clerk/clerk-js` SDK for custom login/sign-up pages, plus add tenant self-service creation and invite system.

**Architecture:** Frontend uses `@clerk/clerk-js` headless to authenticate users (password + social OAuth). Clerk session tokens are exchanged for Valinor tokens via the existing `POST /auth/exchange` backend endpoint. New backend endpoints handle tenant self-service creation and invite codes. NextAuth keeps its JWT strategy — the Clerk OIDC provider is replaced with a credentials provider that accepts Clerk session tokens.

**Tech Stack:** `@clerk/clerk-js` (headless, ~40KB), NextAuth v5 (JWT strategy), Go backend (existing auth handler), PostgreSQL (new `tenant_invites` table), shadcn/ui components.

---

## Phase 1: Backend — Invite System & Tenant Self-Service

### Task 1: Migration for tenant_invites Table

**Files:**
- Create: `migrations/000016_tenant_invites.up.sql`
- Create: `migrations/000016_tenant_invites.down.sql`

**Step 1: Write the up migration**

```sql
-- migrations/000016_tenant_invites.up.sql
CREATE TABLE tenant_invites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    code        VARCHAR(32) UNIQUE NOT NULL,
    role        VARCHAR(64) NOT NULL DEFAULT 'standard_user',
    created_by  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tenant_invites_code ON tenant_invites(code) WHERE used_at IS NULL;
CREATE INDEX idx_tenant_invites_tenant ON tenant_invites(tenant_id);

ALTER TABLE tenant_invites ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_invites
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
```

**Step 2: Write the down migration**

```sql
-- migrations/000016_tenant_invites.down.sql
DROP TABLE IF EXISTS tenant_invites;
```

**Step 3: Run the migration**

Run: `cd /Users/fred/Documents/Valinor && go run cmd/valinor/main.go migrate up`
(or use the migrate tool directly if available)

If migrate command isn't built in, apply manually:
```bash
/usr/local/Cellar/postgresql@15/15.13/bin/psql postgres://valinor:valinor@localhost:5432/valinor -f migrations/000016_tenant_invites.up.sql
```

Expected: Table created successfully.

**Step 4: Commit**

```bash
git add migrations/000016_tenant_invites.up.sql migrations/000016_tenant_invites.down.sql
git commit -m "feat: add tenant_invites migration with RLS"
```

---

### Task 2: Invite Store

**Files:**
- Create: `internal/tenant/invite.go` (model + errors)
- Create: `internal/tenant/invite_store.go` (store methods)
- Create: `internal/tenant/invite_store_test.go` (tests)

**Step 1: Write the invite model**

```go
// internal/tenant/invite.go
package tenant

import (
	"errors"
	"time"
)

type Invite struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Code      string     `json:"code"`
	Role      string     `json:"role"`
	CreatedBy string     `json:"created_by"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedBy    *string    `json:"used_by,omitempty"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

var (
	ErrInviteNotFound = errors.New("invite not found")
	ErrInviteExpired  = errors.New("invite has expired")
	ErrInviteUsed     = errors.New("invite has already been used")
)
```

**Step 2: Write failing tests for the store**

```go
// internal/tenant/invite_store_test.go
package tenant_test

import (
	"context"
	"testing"
	"time"

	"github.com/FredAmartey/valinor/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInviteStore_Create(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	inviteStore := tenant.NewInviteStore(pool)
	ctx := context.Background()

	// Create a tenant and a user first
	tn, err := store.Create(ctx, "Invite Test Org", "invite-test-org")
	require.NoError(t, err)

	// Create invite
	inv, err := inviteStore.Create(ctx, tn.ID, "test-user-id", "standard_user", 24*time.Hour)
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

	inv, err := inviteStore.Create(ctx, tn.ID, "test-user-id", "standard_user", 24*time.Hour)
	require.NoError(t, err)

	found, err := inviteStore.GetByCode(ctx, inv.Code)
	require.NoError(t, err)
	assert.Equal(t, inv.ID, found.ID)

	// Not found
	_, err = inviteStore.GetByCode(ctx, "nonexistent")
	assert.ErrorIs(t, err, tenant.ErrInviteNotFound)
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

	inv, err := inviteStore.Create(ctx, tn.ID, "test-user-id", "standard_user", 24*time.Hour)
	require.NoError(t, err)

	// Redeem
	err = inviteStore.Redeem(ctx, inv.Code, "redeemer-user-id")
	require.NoError(t, err)

	// Double redeem fails
	err = inviteStore.Redeem(ctx, inv.Code, "another-user-id")
	assert.ErrorIs(t, err, tenant.ErrInviteUsed)
}
```

**Step 3: Run tests to verify they fail**

Run: `cd /Users/fred/Documents/Valinor && CGO_ENABLED=0 go test ./internal/tenant/ -run TestInviteStore -v -short`
Expected: Compilation error — `NewInviteStore` undefined.

**Step 4: Implement the invite store**

```go
// internal/tenant/invite_store.go
package tenant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type InviteStore struct {
	pool *pgxpool.Pool
}

func NewInviteStore(pool *pgxpool.Pool) *InviteStore {
	return &InviteStore{pool: pool}
}

func generateCode() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating invite code: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (s *InviteStore) Create(ctx context.Context, tenantID, createdBy, role string, ttl time.Duration) (*Invite, error) {
	code, err := generateCode()
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(ttl)

	var inv Invite
	err = s.pool.QueryRow(ctx,
		`INSERT INTO tenant_invites (tenant_id, code, role, created_by, expires_at)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, tenant_id, code, role, created_by, expires_at, used_by, used_at, created_at`,
		tenantID, code, role, createdBy, expiresAt,
	).Scan(&inv.ID, &inv.TenantID, &inv.Code, &inv.Role, &inv.CreatedBy,
		&inv.ExpiresAt, &inv.UsedBy, &inv.UsedAt, &inv.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating invite: %w", err)
	}
	return &inv, nil
}

func (s *InviteStore) GetByCode(ctx context.Context, code string) (*Invite, error) {
	var inv Invite
	err := s.pool.QueryRow(ctx,
		`SELECT id, tenant_id, code, role, created_by, expires_at, used_by, used_at, created_at
		 FROM tenant_invites WHERE code = $1`,
		code,
	).Scan(&inv.ID, &inv.TenantID, &inv.Code, &inv.Role, &inv.CreatedBy,
		&inv.ExpiresAt, &inv.UsedBy, &inv.UsedAt, &inv.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, ErrInviteNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting invite by code: %w", err)
	}
	return &inv, nil
}

func (s *InviteStore) ListByTenant(ctx context.Context, tenantID string) ([]Invite, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, tenant_id, code, role, created_by, expires_at, used_by, used_at, created_at
		 FROM tenant_invites WHERE tenant_id = $1 ORDER BY created_at DESC`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing invites: %w", err)
	}
	defer rows.Close()

	var invites []Invite
	for rows.Next() {
		var inv Invite
		if err := rows.Scan(&inv.ID, &inv.TenantID, &inv.Code, &inv.Role, &inv.CreatedBy,
			&inv.ExpiresAt, &inv.UsedBy, &inv.UsedAt, &inv.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning invite: %w", err)
		}
		invites = append(invites, inv)
	}
	return invites, nil
}

func (s *InviteStore) Redeem(ctx context.Context, code, userID string) error {
	inv, err := s.GetByCode(ctx, code)
	if err != nil {
		return err
	}
	if inv.UsedAt != nil {
		return ErrInviteUsed
	}
	if time.Now().After(inv.ExpiresAt) {
		return ErrInviteExpired
	}

	tag, err := s.pool.Exec(ctx,
		`UPDATE tenant_invites SET used_by = $1, used_at = now()
		 WHERE code = $2 AND used_at IS NULL`,
		userID, code,
	)
	if err != nil {
		return fmt.Errorf("redeeming invite: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInviteUsed
	}
	return nil
}

func (s *InviteStore) Delete(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM tenant_invites WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deleting invite: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInviteNotFound
	}
	return nil
}
```

**Step 5: Run tests**

Run: `cd /Users/fred/Documents/Valinor && CGO_ENABLED=0 go test ./internal/tenant/ -run TestInviteStore -v`
Expected: Tests may need DB setup; if using `-short` they skip. Run without `-short` if testcontainers available.

**Step 6: Commit**

```bash
git add internal/tenant/invite.go internal/tenant/invite_store.go internal/tenant/invite_store_test.go
git commit -m "feat: add invite store with create, redeem, list, delete"
```

---

### Task 3: Invite Handler & Routes

**Files:**
- Create: `internal/tenant/invite_handler.go`
- Modify: `internal/platform/server/server.go` (add routes)

**Step 1: Write the invite handler**

```go
// internal/tenant/invite_handler.go
package tenant

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/FredAmartey/valinor/internal/auth"
	"github.com/FredAmartey/valinor/internal/platform/middleware"
)

type InviteHandler struct {
	store *InviteStore
}

func NewInviteHandler(store *InviteStore) *InviteHandler {
	return &InviteHandler{store: store}
}

func (h *InviteHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Role == "" {
		req.Role = "standard_user"
	}

	inv, err := h.store.Create(r.Context(), tenantID, identity.UserID, req.Role, 7*24*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create invite"})
		return
	}
	writeJSON(w, http.StatusCreated, inv)
}

func (h *InviteHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	invites, err := h.store.ListByTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list invites"})
		return
	}
	if invites == nil {
		invites = []Invite{}
	}
	writeJSON(w, http.StatusOK, invites)
}

func (h *InviteHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invite id required"})
		return
	}

	err := h.store.Delete(r.Context(), id)
	if errors.Is(err, ErrInviteNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "invite not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete invite"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
```

**Step 2: Write the invite redeem handler on the auth handler**

This goes in `internal/auth/handler.go`. Add a new method:

```go
// Add to internal/auth/handler.go

func (h *Handler) HandleRedeemInvite(w http.ResponseWriter, r *http.Request) {
	identity := GetIdentity(r.Context())
	if identity == nil {
		writeAuthError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		writeAuthError(w, http.StatusBadRequest, "invite code required")
		return
	}

	// Delegate to invite store — needs to be injected into auth handler
	// or call via a shared interface. For now, this will be wired in server.go.
}
```

Actually, the redeem logic is better placed as a dedicated endpoint. We'll wire it in `server.go` as a protected route that:
1. Validates the invite code
2. Updates the user's `tenant_id`
3. Assigns the invite's role
4. Marks invite as used
5. Re-issues tokens

This requires careful wiring. Let me define the route in server.go:

**Step 3: Register invite routes in server.go**

Add to the protected routes section of `internal/platform/server/server.go`:

```go
// Invite routes (org_admin only for create/list/delete)
if deps.InviteHandler != nil {
    protectedMux.Handle("POST /api/v1/invites",
        rbac.RequirePermission(deps.RBAC, "invites:write", rbacOpts...)(
            http.HandlerFunc(deps.InviteHandler.HandleCreate),
        ),
    )
    protectedMux.Handle("GET /api/v1/invites",
        rbac.RequirePermission(deps.RBAC, "invites:read", rbacOpts...)(
            http.HandlerFunc(deps.InviteHandler.HandleList),
        ),
    )
    protectedMux.Handle("DELETE /api/v1/invites/{id}",
        rbac.RequirePermission(deps.RBAC, "invites:write", rbacOpts...)(
            http.HandlerFunc(deps.InviteHandler.HandleDelete),
        ),
    )
}
```

**Step 4: Add InviteHandler to server Dependencies struct**

In `internal/platform/server/server.go`, add to the `Dependencies` struct:

```go
InviteHandler *tenant.InviteHandler
```

**Step 5: Wire InviteStore and InviteHandler in main.go**

In `cmd/valinor/main.go`, after creating the tenant store:

```go
inviteStore := tenant.NewInviteStore(pool)
inviteHandler := tenant.NewInviteHandler(inviteStore)
// Add to deps: InviteHandler: inviteHandler
```

**Step 6: Commit**

```bash
git add internal/tenant/invite_handler.go internal/platform/server/server.go cmd/valinor/main.go
git commit -m "feat: add invite endpoints — create, list, delete"
```

---

### Task 4: Tenant Self-Service Creation Endpoint

**Files:**
- Modify: `internal/tenant/handler.go` (add HandleSelfServiceCreate)
- Modify: `internal/platform/server/server.go` (add route)
- Modify: `internal/auth/store.go` (add UpdateUserTenant)

**Step 1: Add UpdateUserTenant to auth store**

This method assigns a tenant to a tenantless user (post-signup):

```go
// Add to internal/auth/store.go

func (s *Store) UpdateUserTenant(ctx context.Context, userID, tenantID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE users SET tenant_id = $1 WHERE id = $2 AND tenant_id IS NULL`,
		tenantID, userID,
	)
	if err != nil {
		return fmt.Errorf("updating user tenant: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found or already has a tenant")
	}
	return nil
}
```

**Step 2: Add slug generation utility**

```go
// Add to internal/tenant/tenant.go

func GenerateSlug(name string) string {
	slug := strings.ToLower(name)
	slug = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, slug)
	// Collapse multiple hyphens
	for strings.Contains(slug, "--") {
		slug = strings.ReplaceAll(slug, "--", "-")
	}
	slug = strings.Trim(slug, "-")
	if len(slug) < 3 {
		slug = slug + "-team"
	}
	if len(slug) > 63 {
		slug = slug[:63]
	}
	return slug
}
```

**Step 3: Add HandleSelfServiceCreate to tenant handler**

```go
// Add to internal/tenant/handler.go

func (h *Handler) HandleSelfServiceCreate(w http.ResponseWriter, r *http.Request) {
	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	if identity.TenantID != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user already belongs to a tenant"})
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "team name is required"})
		return
	}

	slug := GenerateSlug(req.Name)
	t, err := h.store.Create(r.Context(), req.Name, slug)
	if err != nil {
		if errors.Is(err, ErrSlugTaken) {
			// Append random suffix
			slug = slug + "-" + fmt.Sprintf("%d", time.Now().UnixMilli()%10000)
			t, err = h.store.Create(r.Context(), req.Name, slug)
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create team"})
			return
		}
	}

	// Assign user to tenant — requires authStore to be injected
	// This will be wired via a callback or direct store reference
	// For now, the handler needs access to the auth store
	if err := h.authStore.UpdateUserTenant(r.Context(), identity.UserID, t.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to assign user to team"})
		return
	}

	// Assign org_admin role to the creating user
	// This requires inserting into user_roles with the org_admin role for this tenant
	if err := h.assignOrgAdmin(r.Context(), identity.UserID, t.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to assign admin role"})
		return
	}

	writeJSON(w, http.StatusCreated, t)
}
```

**Note:** The handler needs `authStore` injected. Update the Handler struct to accept it, or create a dedicated `OnboardingHandler` to avoid coupling.

**Step 4: Register route in server.go**

```go
// Self-service tenant creation (authenticated, tenantless users)
protectedMux.HandleFunc("POST /api/v1/tenants/self-service",
    deps.TenantHandler.HandleSelfServiceCreate,
)
```

**Step 5: Commit**

```bash
git add internal/tenant/handler.go internal/tenant/tenant.go internal/auth/store.go internal/platform/server/server.go
git commit -m "feat: add tenant self-service creation with slug generation"
```

---

## Phase 2: Frontend — Clerk SDK Setup

### Task 5: Install @clerk/clerk-js & Update Env

**Step 1: Install the package**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npm install @clerk/clerk-js`

**Step 2: Add publishable key to .env.example**

Add to `dashboard/.env.example`:

```
# Clerk Frontend SDK (required when NEXT_PUBLIC_AUTH_CLERK_ENABLED=true)
# NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_your_publishable_key
```

**Step 3: Add publishable key to .env.local**

Add to `dashboard/.env.local`:

```
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_...
```

Get this value from the Clerk Dashboard → API Keys → Publishable Key.

**Step 4: Commit**

```bash
git add dashboard/package.json dashboard/package-lock.json dashboard/.env.example
git commit -m "feat: install @clerk/clerk-js and add publishable key env"
```

---

### Task 6: Clerk SDK Initialization Hook

**Files:**
- Create: `dashboard/src/lib/clerk.ts`

**Step 1: Create the Clerk initialization module**

```typescript
// dashboard/src/lib/clerk.ts
import Clerk from "@clerk/clerk-js"

let clerkInstance: Clerk | null = null
let clerkPromise: Promise<Clerk> | null = null

const publishableKey = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY

export function getClerk(): Promise<Clerk> {
  if (!publishableKey) {
    return Promise.reject(new Error("NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY not set"))
  }

  if (clerkInstance?.loaded) {
    return Promise.resolve(clerkInstance)
  }

  if (clerkPromise) {
    return clerkPromise
  }

  clerkPromise = (async () => {
    const clerk = new Clerk(publishableKey)
    await clerk.load()
    clerkInstance = clerk
    return clerk
  })()

  return clerkPromise
}

export function getClerkSync(): Clerk | null {
  return clerkInstance
}
```

**Step 2: Commit**

```bash
git add dashboard/src/lib/clerk.ts
git commit -m "feat: add Clerk headless SDK initialization module"
```

---

### Task 7: Update NextAuth Config — Replace OIDC with Clerk Token Credentials

**Files:**
- Modify: `dashboard/src/lib/auth.ts`

**Step 1: Replace the Clerk OIDC provider**

Replace the existing Clerk OIDC provider block (lines 124-136 of `auth.ts`) with a new credentials provider that accepts a Clerk session token:

```typescript
// Replace the Clerk OIDC block with:
...(process.env.AUTH_CLERK_ISSUER
  ? [
      Credentials({
        id: "clerk-token",
        credentials: {
          token: { label: "Clerk Session Token", type: "text" },
          tenantSlug: { label: "Tenant Slug", type: "text" },
        },
        async authorize(credentials) {
          if (!credentials?.token) return null

          const data = await exchangeIDToken(
            credentials.token as string,
            (credentials.tenantSlug as string) || undefined,
          )
          if (!data) return null

          const roles = decodeJwtRoles(data.access_token)
          return {
            id: data.user.id,
            email: data.user.email,
            name: data.user.display_name ?? data.user.email,
            tenantId: data.user.tenant_id ?? null,
            isPlatformAdmin: data.user.is_platform_admin ?? false,
            accessToken: data.access_token,
            refreshToken: data.refresh_token,
            expiresIn: data.expires_in ?? 3600,
            roles,
          }
        },
      }),
    ]
  : []),
```

**Step 2: Update the JWT callback to handle `clerk-token` provider**

In the JWT callback, update the condition for Clerk sign-in (around line 158):

```typescript
// Replace: if (account?.provider === "clerk" && account.id_token) {
// With:
if (user && account?.provider === "clerk-token") {
  token.accessToken = user.accessToken
  token.refreshToken = user.refreshToken
  token.expiresAt = Math.floor(Date.now() / 1000) + (user.expiresIn ?? 3600)
  token.userId = user.id ?? ""
  token.tenantId = user.tenantId ?? null
  token.isPlatformAdmin = user.isPlatformAdmin ?? false
  token.roles = user.roles ?? []
  return token
}
```

**Step 3: Remove the `authorization: { params: { prompt: "login" } }` line**

This was added for the OIDC provider and is no longer needed since we're using credentials.

**Step 4: Verify TypeScript compiles**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npx tsc --noEmit`
Expected: No errors.

**Step 5: Commit**

```bash
git add dashboard/src/lib/auth.ts
git commit -m "feat: replace Clerk OIDC provider with headless token credentials"
```

---

## Phase 3: Frontend — Auth Pages

### Task 8: Shared Auth Components

**Files:**
- Create: `dashboard/src/components/auth/auth-card.tsx`
- Create: `dashboard/src/components/auth/social-buttons.tsx`
- Create: `dashboard/src/components/auth/auth-divider.tsx`

**Step 1: Create AuthCard wrapper**

```typescript
// dashboard/src/components/auth/auth-card.tsx
"use client"

export function AuthCard({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-[100dvh] items-center justify-center bg-gradient-to-b from-zinc-950 to-zinc-900">
      <div className="w-full max-w-sm space-y-6 rounded-2xl bg-white p-8 shadow-2xl shadow-black/20">
        <div className="text-center">
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
            Valinor
          </h1>
        </div>
        {children}
      </div>
    </div>
  )
}
```

**Step 2: Create SocialButtons**

```typescript
// dashboard/src/components/auth/social-buttons.tsx
"use client"

interface SocialButtonsProps {
  onGoogle: () => void
  onGitHub: () => void
  disabled?: boolean
}

export function SocialButtons({ onGoogle, onGitHub, disabled }: SocialButtonsProps) {
  return (
    <div className="grid grid-cols-2 gap-3">
      <button
        type="button"
        onClick={onGoogle}
        disabled={disabled}
        className="flex items-center justify-center gap-2 rounded-lg border border-zinc-200 bg-white px-4 py-2.5 text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-50 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
      >
        <GoogleIcon />
        Google
      </button>
      <button
        type="button"
        onClick={onGitHub}
        disabled={disabled}
        className="flex items-center justify-center gap-2 rounded-lg border border-zinc-200 bg-white px-4 py-2.5 text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-50 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
      >
        <GitHubIcon />
        GitHub
      </button>
    </div>
  )
}

function GoogleIcon() {
  return (
    <svg className="h-4 w-4" viewBox="0 0 24 24">
      <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" />
      <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
      <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
      <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
    </svg>
  )
}

function GitHubIcon() {
  return (
    <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 24 24">
      <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.02 10.02 0 0 0 22 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
    </svg>
  )
}
```

**Step 3: Create AuthDivider**

```typescript
// dashboard/src/components/auth/auth-divider.tsx
export function AuthDivider() {
  return (
    <div className="relative">
      <div className="absolute inset-0 flex items-center">
        <div className="w-full border-t border-zinc-200" />
      </div>
      <div className="relative flex justify-center text-xs">
        <span className="bg-white px-2 text-zinc-400">or continue with</span>
      </div>
    </div>
  )
}
```

**Step 4: Commit**

```bash
git add dashboard/src/components/auth/
git commit -m "feat: add shared auth components — AuthCard, SocialButtons, AuthDivider"
```

---

### Task 9: Rewrite Login Page

**Files:**
- Modify: `dashboard/src/app/(auth)/login/page.tsx`

**Step 1: Rewrite the login page**

```typescript
// dashboard/src/app/(auth)/login/page.tsx
"use client"

import { signIn } from "next-auth/react"
import { useState } from "react"
import { useRouter } from "next/navigation"
import { AuthCard } from "@/components/auth/auth-card"
import { SocialButtons } from "@/components/auth/social-buttons"
import { AuthDivider } from "@/components/auth/auth-divider"
import { getClerk } from "@/lib/clerk"
import Link from "next/link"

const isDevMode = process.env.NEXT_PUBLIC_VALINOR_DEV_MODE === "true"
const isClerkEnabled = !!process.env.NEXT_PUBLIC_AUTH_CLERK_ENABLED
const tenantSlug = process.env.NEXT_PUBLIC_TENANT_SLUG

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  async function handleDevLogin(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setLoading(true)

    const result = await signIn("credentials", { email, redirect: false })
    setLoading(false)

    if (result?.error) {
      setError("Invalid email or user not found.")
      return
    }
    router.push("/")
    router.refresh()
  }

  async function handleClerkLogin(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setLoading(true)

    try {
      const clerk = await getClerk()
      const signInAttempt = await clerk.client.signIn.create({
        identifier: email,
        password,
      })

      if (signInAttempt.status !== "complete") {
        setError("Sign-in could not be completed. Try again.")
        setLoading(false)
        return
      }

      // Set the active session in Clerk
      await clerk.setActive({ session: signInAttempt.createdSessionId })

      // Get session token to exchange for Valinor tokens
      const token = await clerk.session?.getToken()
      if (!token) {
        setError("Failed to get session token.")
        setLoading(false)
        return
      }

      const result = await signIn("clerk-token", {
        token,
        tenantSlug: tenantSlug ?? "",
        redirect: false,
      })

      setLoading(false)
      if (result?.error) {
        setError("Authentication failed. Please try again.")
        return
      }
      router.push("/")
      router.refresh()
    } catch (err: unknown) {
      setLoading(false)
      const message = err instanceof Error ? err.message : "Sign-in failed"
      // Map Clerk error codes to friendly messages
      if (message.includes("identifier") || message.includes("password")) {
        setError("Invalid email or password.")
      } else if (message.includes("rate")) {
        setError("Too many attempts. Try again in a few minutes.")
      } else {
        setError("Sign-in failed. Please try again.")
      }
    }
  }

  async function handleSocialLogin(strategy: "oauth_google" | "oauth_github") {
    setError("")
    setLoading(true)
    try {
      const clerk = await getClerk()
      await clerk.client.signIn.authenticateWithRedirect({
        strategy,
        redirectUrl: "/sso-callback",
        redirectUrlComplete: "/sso-callback",
      })
    } catch {
      setLoading(false)
      setError("Social sign-in failed. Please try again.")
    }
  }

  return (
    <AuthCard>
      <p className="text-center text-sm text-zinc-500">
        Sign in to manage your AI agent infrastructure.
      </p>

      {isClerkEnabled && (
        <>
          <form onSubmit={handleClerkLogin} className="space-y-4">
            <div className="space-y-2">
              <label htmlFor="email" className="text-sm font-medium text-zinc-700">
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
            <div className="space-y-2">
              <label htmlFor="password" className="text-sm font-medium text-zinc-700">
                Password
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
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
              disabled={loading || !email || !password}
              className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? "Signing in..." : "Sign in"}
            </button>
          </form>

          <AuthDivider />

          <SocialButtons
            onGoogle={() => handleSocialLogin("oauth_google")}
            onGitHub={() => handleSocialLogin("oauth_github")}
            disabled={loading}
          />

          <p className="text-center text-sm text-zinc-500">
            Don&apos;t have an account?{" "}
            <Link href="/signup" className="font-medium text-zinc-900 hover:underline">
              Sign up
            </Link>
          </p>
        </>
      )}

      {isDevMode && (
        <>
          {isClerkEnabled && <AuthDivider />}
          <form onSubmit={handleDevLogin} className="space-y-4">
            <div className="space-y-2">
              <label htmlFor="dev-email" className="text-sm font-medium text-zinc-700">
                Email {isClerkEnabled && "(Dev Mode)"}
              </label>
              <input
                id="dev-email"
                type="email"
                value={isClerkEnabled ? undefined : email}
                onChange={(e) => !isClerkEnabled && setEmail(e.target.value)}
                placeholder="you@example.com"
                required
                className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400"
              />
            </div>
            {!isClerkEnabled && error && (
              <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
                <p className="text-sm text-rose-700">{error}</p>
              </div>
            )}
            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg border border-zinc-200 bg-white px-4 py-2.5 text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-50 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? "Signing in..." : "Sign in (Dev Mode)"}
            </button>
          </form>
          <p className="text-center text-xs text-zinc-400">
            Dev mode — enter any existing user email.
          </p>
        </>
      )}
    </AuthCard>
  )
}
```

**Step 2: Verify TypeScript compiles**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npx tsc --noEmit`

**Step 3: Commit**

```bash
git add dashboard/src/app/\(auth\)/login/page.tsx
git commit -m "feat: rewrite login page with email/password + social via Clerk headless"
```

---

### Task 10: Sign-Up Page

**Files:**
- Create: `dashboard/src/app/(auth)/signup/page.tsx`

**Step 1: Create the sign-up page**

```typescript
// dashboard/src/app/(auth)/signup/page.tsx
"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { AuthCard } from "@/components/auth/auth-card"
import { SocialButtons } from "@/components/auth/social-buttons"
import { AuthDivider } from "@/components/auth/auth-divider"
import { getClerk } from "@/lib/clerk"
import Link from "next/link"

export default function SignUpPage() {
  const router = useRouter()
  const [firstName, setFirstName] = useState("")
  const [lastName, setLastName] = useState("")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  async function handleSignUp(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setLoading(true)

    try {
      const clerk = await getClerk()
      const signUpAttempt = await clerk.client.signUp.create({
        emailAddress: email,
        password,
        firstName,
        lastName,
      })

      if (signUpAttempt.status === "complete") {
        // Email already verified (unlikely for password signup)
        router.push("/signup/team")
        return
      }

      // Prepare email verification
      await signUpAttempt.prepareEmailAddressVerification({ strategy: "email_code" })

      // Store signup state for verification page
      sessionStorage.setItem("valinor_signup_pending", "true")
      router.push("/signup/verify")
    } catch (err: unknown) {
      setLoading(false)
      const message = err instanceof Error ? err.message : "Sign-up failed"
      if (message.includes("email_address") || message.includes("taken")) {
        setError("Email already in use. Sign in instead?")
      } else if (message.includes("password")) {
        setError("Password must be at least 8 characters.")
      } else {
        setError("Sign-up failed. Please try again.")
      }
    }
  }

  async function handleSocialSignUp(strategy: "oauth_google" | "oauth_github") {
    setError("")
    setLoading(true)
    try {
      const clerk = await getClerk()
      await clerk.client.signUp.authenticateWithRedirect({
        strategy,
        redirectUrl: "/sso-callback",
        redirectUrlComplete: "/sso-callback",
      })
    } catch {
      setLoading(false)
      setError("Social sign-up failed. Please try again.")
    }
  }

  return (
    <AuthCard>
      <p className="text-center text-sm text-zinc-500">
        Create your account to get started.
      </p>

      <form onSubmit={handleSignUp} className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-2">
            <label htmlFor="firstName" className="text-sm font-medium text-zinc-700">
              First name
            </label>
            <input
              id="firstName"
              type="text"
              value={firstName}
              onChange={(e) => setFirstName(e.target.value)}
              placeholder="Jane"
              required
              className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400"
            />
          </div>
          <div className="space-y-2">
            <label htmlFor="lastName" className="text-sm font-medium text-zinc-700">
              Last name
            </label>
            <input
              id="lastName"
              type="text"
              value={lastName}
              onChange={(e) => setLastName(e.target.value)}
              placeholder="Doe"
              required
              className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400"
            />
          </div>
        </div>
        <div className="space-y-2">
          <label htmlFor="email" className="text-sm font-medium text-zinc-700">
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
        <div className="space-y-2">
          <label htmlFor="password" className="text-sm font-medium text-zinc-700">
            Password
          </label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
            required
            minLength={8}
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
          disabled={loading || !email || !password || !firstName || !lastName}
          className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? "Creating account..." : "Create account"}
        </button>
      </form>

      <AuthDivider />

      <SocialButtons
        onGoogle={() => handleSocialSignUp("oauth_google")}
        onGitHub={() => handleSocialSignUp("oauth_github")}
        disabled={loading}
      />

      <p className="text-center text-sm text-zinc-500">
        Already have an account?{" "}
        <Link href="/login" className="font-medium text-zinc-900 hover:underline">
          Sign in
        </Link>
      </p>
    </AuthCard>
  )
}
```

**Step 2: Commit**

```bash
git add dashboard/src/app/\(auth\)/signup/page.tsx
git commit -m "feat: add sign-up page with email/password + social"
```

---

### Task 11: Email Verification Page

**Files:**
- Create: `dashboard/src/app/(auth)/signup/verify/page.tsx`

**Step 1: Create the verification page**

```typescript
// dashboard/src/app/(auth)/signup/verify/page.tsx
"use client"

import { signIn } from "next-auth/react"
import { useState } from "react"
import { useRouter } from "next/navigation"
import { AuthCard } from "@/components/auth/auth-card"
import { getClerk } from "@/lib/clerk"

const tenantSlug = process.env.NEXT_PUBLIC_TENANT_SLUG

export default function VerifyPage() {
  const router = useRouter()
  const [code, setCode] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  async function handleVerify(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setLoading(true)

    try {
      const clerk = await getClerk()
      const signUpAttempt = clerk.client.signUp

      const result = await signUpAttempt.attemptEmailAddressVerification({ code })

      if (result.status !== "complete") {
        setError("Verification incomplete. Try again.")
        setLoading(false)
        return
      }

      // Set active session
      await clerk.setActive({ session: result.createdSessionId })

      // Get session token and exchange for Valinor tokens
      const token = await clerk.session?.getToken()
      if (!token) {
        setError("Failed to get session token.")
        setLoading(false)
        return
      }

      const signInResult = await signIn("clerk-token", {
        token,
        tenantSlug: tenantSlug ?? "",
        redirect: false,
      })

      if (signInResult?.error) {
        setError("Authentication failed.")
        setLoading(false)
        return
      }

      // Clear signup state
      sessionStorage.removeItem("valinor_signup_pending")

      // Go to team selection
      router.push("/signup/team")
      router.refresh()
    } catch {
      setLoading(false)
      setError("Invalid verification code. Try again.")
    }
  }

  return (
    <AuthCard>
      <p className="text-center text-sm text-zinc-500">
        We sent a verification code to your email. Enter it below.
      </p>

      <form onSubmit={handleVerify} className="space-y-4">
        <div className="space-y-2">
          <label htmlFor="code" className="text-sm font-medium text-zinc-700">
            Verification code
          </label>
          <input
            id="code"
            type="text"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="Enter 6-digit code"
            required
            autoFocus
            className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400 text-center tracking-widest"
          />
        </div>
        {error && (
          <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
            <p className="text-sm text-rose-700">{error}</p>
          </div>
        )}
        <button
          type="submit"
          disabled={loading || !code}
          className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? "Verifying..." : "Verify email"}
        </button>
      </form>
    </AuthCard>
  )
}
```

**Step 2: Commit**

```bash
git add dashboard/src/app/\(auth\)/signup/verify/page.tsx
git commit -m "feat: add email verification page"
```

---

### Task 12: Team Selection Page (Create or Join)

**Files:**
- Create: `dashboard/src/app/(auth)/signup/team/page.tsx`

**Step 1: Create the team selection page**

```typescript
// dashboard/src/app/(auth)/signup/team/page.tsx
"use client"

import { useSession } from "next-auth/react"
import { useState } from "react"
import { useRouter } from "next/navigation"
import { AuthCard } from "@/components/auth/auth-card"

const API_URL = process.env.NEXT_PUBLIC_VALINOR_API_URL ?? "http://localhost:8080"

export default function TeamPage() {
  const { data: session, update } = useSession()
  const router = useRouter()
  const [mode, setMode] = useState<"create" | "join">("create")
  const [teamName, setTeamName] = useState("")
  const [inviteCode, setInviteCode] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  // If user already has a tenant, skip this step
  if (session?.user?.tenantId) {
    router.push("/")
    return null
  }

  async function handleCreateTeam(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setLoading(true)

    try {
      const res = await fetch(`${API_URL}/api/v1/tenants/self-service`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${session?.accessToken}`,
        },
        body: JSON.stringify({ name: teamName }),
      })

      if (!res.ok) {
        const data = await res.json()
        setError(data.error ?? "Failed to create team.")
        setLoading(false)
        return
      }

      // Refresh session to pick up new tenantId
      await update()
      router.push("/")
      router.refresh()
    } catch {
      setLoading(false)
      setError("Failed to create team. Please try again.")
    }
  }

  async function handleJoinTeam(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setLoading(true)

    try {
      const res = await fetch(`${API_URL}/auth/invite/redeem`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${session?.accessToken}`,
        },
        body: JSON.stringify({ code: inviteCode }),
      })

      if (!res.ok) {
        const data = await res.json()
        if (data.error?.includes("expired")) {
          setError("This invite has expired. Ask your admin for a new one.")
        } else if (data.error?.includes("used")) {
          setError("This invite has already been used.")
        } else {
          setError(data.error ?? "Invalid invite code.")
        }
        setLoading(false)
        return
      }

      await update()
      router.push("/")
      router.refresh()
    } catch {
      setLoading(false)
      setError("Failed to join team. Please try again.")
    }
  }

  return (
    <AuthCard>
      <p className="text-center text-sm text-zinc-500">
        Almost there! Create a new team or join an existing one.
      </p>

      <div className="flex rounded-lg border border-zinc-200 p-1">
        <button
          type="button"
          onClick={() => { setMode("create"); setError("") }}
          className={`flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            mode === "create"
              ? "bg-zinc-900 text-white"
              : "text-zinc-600 hover:text-zinc-900"
          }`}
        >
          Create team
        </button>
        <button
          type="button"
          onClick={() => { setMode("join"); setError("") }}
          className={`flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            mode === "join"
              ? "bg-zinc-900 text-white"
              : "text-zinc-600 hover:text-zinc-900"
          }`}
        >
          Join team
        </button>
      </div>

      {mode === "create" && (
        <form onSubmit={handleCreateTeam} className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="teamName" className="text-sm font-medium text-zinc-700">
              Team name
            </label>
            <input
              id="teamName"
              type="text"
              value={teamName}
              onChange={(e) => setTeamName(e.target.value)}
              placeholder="Acme Inc."
              required
              autoFocus
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
            disabled={loading || !teamName}
            className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? "Creating..." : "Create team"}
          </button>
        </form>
      )}

      {mode === "join" && (
        <form onSubmit={handleJoinTeam} className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="inviteCode" className="text-sm font-medium text-zinc-700">
              Invite code
            </label>
            <input
              id="inviteCode"
              type="text"
              value={inviteCode}
              onChange={(e) => setInviteCode(e.target.value)}
              placeholder="Paste your invite code"
              required
              autoFocus
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
            disabled={loading || !inviteCode}
            className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? "Joining..." : "Join team"}
          </button>
        </form>
      )}
    </AuthCard>
  )
}
```

**Step 2: Commit**

```bash
git add dashboard/src/app/\(auth\)/signup/team/page.tsx
git commit -m "feat: add team selection page — create or join via invite"
```

---

### Task 13: SSO Callback Page

**Files:**
- Create: `dashboard/src/app/(auth)/sso-callback/page.tsx`

**Step 1: Create the SSO callback page**

This page handles the return from Clerk's social OAuth redirect:

```typescript
// dashboard/src/app/(auth)/sso-callback/page.tsx
"use client"

import { signIn } from "next-auth/react"
import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { AuthCard } from "@/components/auth/auth-card"
import { getClerk } from "@/lib/clerk"

const tenantSlug = process.env.NEXT_PUBLIC_TENANT_SLUG

export default function SSOCallbackPage() {
  const router = useRouter()
  const [error, setError] = useState("")

  useEffect(() => {
    async function handleCallback() {
      try {
        const clerk = await getClerk()

        // Handle the OAuth callback — Clerk processes the URL params
        const result = await clerk.handleRedirectCallback({
          afterSignInUrl: "/",
          afterSignUpUrl: "/signup/team",
        })

        // If there's an active session, exchange for Valinor tokens
        if (clerk.session) {
          const token = await clerk.session.getToken()
          if (!token) {
            setError("Failed to get session token.")
            return
          }

          const signInResult = await signIn("clerk-token", {
            token,
            tenantSlug: tenantSlug ?? "",
            redirect: false,
          })

          if (signInResult?.error) {
            setError("Authentication failed.")
            return
          }

          // Check if this is a new user (no tenant) → go to team page
          // Otherwise go to dashboard
          const response = await fetch("/api/auth/session")
          const session = await response.json()

          if (!session?.user?.tenantId) {
            router.push("/signup/team")
          } else {
            router.push("/")
          }
          router.refresh()
        }
      } catch {
        setError("Social sign-in failed. Please try again.")
      }
    }

    handleCallback()
  }, [router])

  if (error) {
    return (
      <AuthCard>
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
          <p className="text-sm text-rose-700">{error}</p>
        </div>
        <a
          href="/login"
          className="block w-full rounded-lg border border-zinc-200 bg-white px-4 py-2.5 text-center text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-50"
        >
          Back to sign in
        </a>
      </AuthCard>
    )
  }

  return (
    <AuthCard>
      <div className="flex items-center justify-center py-8">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-zinc-300 border-t-zinc-900" />
        <span className="ml-3 text-sm text-zinc-500">Completing sign-in...</span>
      </div>
    </AuthCard>
  )
}
```

**Step 2: Commit**

```bash
git add dashboard/src/app/\(auth\)/sso-callback/page.tsx
git commit -m "feat: add SSO callback page for social OAuth return"
```

---

## Phase 4: Frontend — Sign-Out & Cleanup

### Task 14: Update User Menu Sign-Out

**Files:**
- Modify: `dashboard/src/components/nav/user-menu.tsx`

**Step 1: Update sign-out to clear both Clerk and NextAuth sessions**

```typescript
// Update the onClick handler in user-menu.tsx:
onClick={async () => {
  // Clear Clerk session if SDK is loaded
  const isClerkEnabled = !!process.env.NEXT_PUBLIC_AUTH_CLERK_ENABLED
  if (isClerkEnabled) {
    const { getClerkSync } = await import("@/lib/clerk")
    const clerk = getClerkSync()
    if (clerk) {
      await clerk.signOut()
    }
  }
  await signOut({ redirectTo: "/login" })
}}
```

**Step 2: Commit**

```bash
git add dashboard/src/components/nav/user-menu.tsx
git commit -m "feat: update sign-out to clear both Clerk and NextAuth sessions"
```

---

### Task 15: Update Middleware Matcher

**Files:**
- Modify: `dashboard/src/middleware.ts`

**Step 1: Add new auth routes to the matcher exclusion**

```typescript
export const config = {
  matcher: [
    "/((?!login|signup|sso-callback|api/auth|_next/static|_next/image|favicon.ico).*)",
  ],
}
```

**Step 2: Commit**

```bash
git add dashboard/src/middleware.ts
git commit -m "feat: update middleware to allow signup and SSO callback routes"
```

---

### Task 16: Update Environment Files

**Files:**
- Modify: `dashboard/.env.example`
- Modify: `dashboard/.env.local`

**Step 1: Update .env.example with new vars**

Add to the Clerk section:

```
# NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_your_publishable_key
```

**Step 2: Update .env.local**

Add the actual publishable key from Clerk Dashboard → API Keys:

```
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_...
```

**Step 3: Commit .env.example only**

```bash
git add dashboard/.env.example
git commit -m "docs: add NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY to env example"
```

---

## Phase 5: Backend — Invite Redemption Endpoint

### Task 17: Invite Redeem Endpoint

**Files:**
- Create: `internal/auth/invite_handler.go` (or add to handler.go)
- Modify: `internal/platform/server/server.go`

**Step 1: Implement the redeem handler**

This is a protected endpoint (requires auth) that:
1. Validates invite code
2. Updates user's tenant_id
3. Assigns the invite's role
4. Marks invite used
5. Re-issues tokens

```go
// internal/auth/invite_handler.go
package auth

import (
	"encoding/json"
	"net/http"

	"github.com/FredAmartey/valinor/internal/tenant"
)

type InviteRedeemHandler struct {
	authStore   *Store
	inviteStore *tenant.InviteStore
	tokenSvc    *TokenService
}

func NewInviteRedeemHandler(authStore *Store, inviteStore *tenant.InviteStore, tokenSvc *TokenService) *InviteRedeemHandler {
	return &InviteRedeemHandler{
		authStore:   authStore,
		inviteStore: inviteStore,
		tokenSvc:    tokenSvc,
	}
}

func (h *InviteRedeemHandler) HandleRedeem(w http.ResponseWriter, r *http.Request) {
	identity := GetIdentity(r.Context())
	if identity == nil {
		writeAuthError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		writeAuthError(w, http.StatusBadRequest, "invite code required")
		return
	}

	// Get invite
	inv, err := h.inviteStore.GetByCode(r.Context(), req.Code)
	if err != nil {
		writeAuthError(w, http.StatusNotFound, err.Error())
		return
	}

	// Redeem (validates expiry, used status)
	if err := h.inviteStore.Redeem(r.Context(), req.Code, identity.UserID); err != nil {
		writeAuthError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Assign user to tenant
	if err := h.authStore.UpdateUserTenant(r.Context(), identity.UserID, inv.TenantID); err != nil {
		writeAuthError(w, http.StatusInternalServerError, "failed to assign user to tenant")
		return
	}

	// Assign the invite's role
	// This needs a method to insert into user_roles
	// For now, write a simple SQL insert via the pool
	if err := h.authStore.AssignRole(r.Context(), identity.UserID, inv.TenantID, inv.Role); err != nil {
		writeAuthError(w, http.StatusInternalServerError, "failed to assign role")
		return
	}

	// Re-issue tokens with updated tenant
	updatedIdentity, err := h.authStore.GetIdentityWithRoles(r.Context(), identity.UserID)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "failed to load updated identity")
		return
	}

	accessToken, err := h.tokenSvc.CreateAccessToken(updatedIdentity)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "failed to create access token")
		return
	}

	refreshToken, err := h.tokenSvc.CreateRefreshToken(updatedIdentity)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "failed to create refresh token")
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    86400,
		"user": map[string]interface{}{
			"id":                updatedIdentity.UserID,
			"email":            updatedIdentity.Email,
			"display_name":     updatedIdentity.DisplayName,
			"tenant_id":        updatedIdentity.TenantID,
			"is_platform_admin": updatedIdentity.IsPlatformAdmin,
		},
	})
}
```

**Step 2: Add AssignRole to auth store**

```go
// Add to internal/auth/store.go

func (s *Store) AssignRole(ctx context.Context, userID, tenantID, roleName string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id, scope_type, scope_id)
		 SELECT $1, r.id, 'org', $2
		 FROM roles r WHERE r.tenant_id = $2 AND r.name = $3
		 ON CONFLICT DO NOTHING`,
		userID, tenantID, roleName,
	)
	if err != nil {
		return fmt.Errorf("assigning role: %w", err)
	}
	return nil
}
```

**Step 3: Register route in server.go**

```go
// Protected route — authenticated users only
if deps.InviteRedeemHandler != nil {
    protectedMux.HandleFunc("POST /auth/invite/redeem",
        deps.InviteRedeemHandler.HandleRedeem,
    )
}
```

**Step 4: Wire in main.go**

```go
inviteRedeemHandler := auth.NewInviteRedeemHandler(authStore, inviteStore, tokenService)
// Add to deps: InviteRedeemHandler: inviteRedeemHandler
```

**Step 5: Commit**

```bash
git add internal/auth/invite_handler.go internal/auth/store.go internal/platform/server/server.go cmd/valinor/main.go
git commit -m "feat: add invite redemption endpoint with role assignment"
```

---

## Phase 6: Integration Testing

### Task 18: End-to-End Smoke Test

**Step 1: Start backend**

```bash
cd /Users/fred/Documents/Valinor && go run cmd/valinor/main.go
```

**Step 2: Start dashboard**

```bash
cd /Users/fred/Documents/Valinor/dashboard && npm run dev
```

**Step 3: Test dev mode login**

1. Go to http://localhost:3000/login
2. Verify the dark background + floating card UI renders
3. Sign in with `turgon@gondolin.fc` (dev mode form)
4. Verify redirect to dashboard
5. Sign out → verify return to /login

**Step 4: Test Clerk login (if publishable key configured)**

1. Enable Clerk in `.env.local`
2. Restart dashboard
3. Go to /login → enter email + password
4. Verify Clerk authenticates and session is created
5. Sign out → verify both Clerk and NextAuth sessions cleared

**Step 5: Test sign-up flow**

1. Go to /signup → create account
2. Verify email code page appears
3. After verification → team page appears
4. Create a new team → verify redirect to dashboard with tenant context

**Step 6: Commit any fixes**

---

### Task 19: TypeScript & Lint Check

**Step 1: Run TypeScript check**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npx tsc --noEmit`

**Step 2: Run Go checks**

Run: `cd /Users/fred/Documents/Valinor && CGO_ENABLED=0 go vet ./...`

**Step 3: Fix any issues and commit**
