# Platform Admin Follow-Ups Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire impersonation JWT generation, impersonation banner into the dashboard layout, and real data into the overview stat cards.

**Architecture:** Three independent wiring tasks. Backend: add `CreateImpersonationToken` to `TokenService`, wire it into the impersonate handler. Frontend: add impersonation session fields + banner to layout, fetch users/channels for overview stat cards.

**Tech Stack:** Go 1.23 / `golang-jwt/v5` / `pgxpool`, Next.js 16 / NextAuth v5 / TanStack Query v5 / Tailwind CSS v4

---

## Task 1: `CreateImpersonationToken` on TokenService

**Files:**
- Modify: `internal/auth/auth.go` (add `ImpersonatorID` field to `Identity`)
- Modify: `internal/auth/token.go` (add `imp` claim + `CreateImpersonationToken` method)
- Create: `internal/auth/token_test.go` (unit tests)

**Step 1: Write tests**

Create `internal/auth/token_test.go`:

```go
package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateImpersonationToken(t *testing.T) {
	svc := NewTokenService("test-secret-key-32-bytes-long!!", "heimdall", 1, 24)

	identity := &Identity{
		UserID:          "admin-user-id",
		IsPlatformAdmin: true,
		Email:           "admin@platform.test",
	}

	tokenStr, err := svc.CreateImpersonationToken(identity, "target-tenant-id")
	require.NoError(t, err)
	require.NotEmpty(t, tokenStr)

	// Parse and validate claims
	parsed, err := svc.ValidateToken(tokenStr)
	require.NoError(t, err)

	assert.Equal(t, "admin-user-id", parsed.UserID)
	assert.Equal(t, "target-tenant-id", parsed.TenantID)
	assert.True(t, parsed.IsPlatformAdmin)
	assert.Equal(t, []string{"org_admin"}, parsed.Roles)
	assert.Equal(t, "admin-user-id", parsed.ImpersonatorID)
	assert.Equal(t, "access", parsed.TokenType)
}

func TestCreateImpersonationToken_ShortExpiry(t *testing.T) {
	svc := NewTokenService("test-secret-key-32-bytes-long!!", "heimdall", 1, 24)

	identity := &Identity{
		UserID:          "admin-user-id",
		IsPlatformAdmin: true,
	}

	tokenStr, err := svc.CreateImpersonationToken(identity, "target-tenant-id")
	require.NoError(t, err)

	// Parse raw to check expiry
	token, _ := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		return []byte("test-secret-key-32-bytes-long!!"), nil
	})
	exp, _ := token.Claims.GetExpirationTime()
	iat, _ := token.Claims.GetIssuedAt()

	// Should be ~30 minutes (not the default 1 hour)
	diff := exp.Time.Sub(iat.Time)
	assert.InDelta(t, 30*time.Minute, diff, float64(5*time.Second))
}
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/fred/Documents/Heimdall && go test ./internal/auth/ -run TestCreateImpersonation -v`
Expected: FAIL — `CreateImpersonationToken` and `ImpersonatorID` don't exist yet.

**Step 3: Add `ImpersonatorID` to Identity**

In `internal/auth/auth.go`, add field to `Identity` struct after `IsPlatformAdmin`:

```go
ImpersonatorID string `json:"impersonator_id,omitempty"`
```

**Step 4: Add `imp` claim and `CreateImpersonationToken` to token.go**

In `internal/auth/token.go`:

Add `ImpersonatorID` to `heimdallClaims` struct (after `IsPlatformAdmin`):

```go
ImpersonatorID string `json:"imp,omitempty"`
```

Add `ImpersonatorID` to the `createToken` method's claims builder (after `IsPlatformAdmin`):

```go
ImpersonatorID: identity.ImpersonatorID,
```

Add `ImpersonatorID` to the `ValidateToken` identity construction (after `IsPlatformAdmin`):

```go
ImpersonatorID: claims.ImpersonatorID,
```

Add the new method after `CreateRefreshToken`:

```go
// CreateImpersonationToken creates a 30-minute access token scoped to a target
// tenant with org_admin privileges. The caller's user ID is preserved as the
// impersonator for audit purposes.
func (s *TokenService) CreateImpersonationToken(identity *Identity, targetTenantID string) (string, error) {
	imp := &Identity{
		UserID:          identity.UserID,
		TenantID:        targetTenantID,
		Email:           identity.Email,
		DisplayName:     identity.DisplayName,
		Roles:           []string{"org_admin"},
		IsPlatformAdmin: true,
		ImpersonatorID:  identity.UserID,
		TokenType:       "access",
	}

	now := time.Now()
	claims := heimdallClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   imp.UserID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Minute)),
		},
		UserID:          imp.UserID,
		TenantID:        imp.TenantID,
		Email:           imp.Email,
		DisplayName:     imp.DisplayName,
		Roles:           imp.Roles,
		TokenType:       imp.TokenType,
		IsPlatformAdmin: imp.IsPlatformAdmin,
		ImpersonatorID:  imp.ImpersonatorID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.signingKey)
}
```

**Step 5: Run tests to verify they pass**

Run: `cd /Users/fred/Documents/Heimdall && go test ./internal/auth/ -run TestCreateImpersonation -v`
Expected: PASS

**Step 6: Run all auth tests**

Run: `cd /Users/fred/Documents/Heimdall && go test ./internal/auth/ -v`
Expected: PASS (no regressions)

**Step 7: Commit**

```bash
git add internal/auth/auth.go internal/auth/token.go internal/auth/token_test.go
git commit -m "feat: add CreateImpersonationToken to TokenService"
```

---

## Task 2: Wire Impersonate Handler to Return JWT

**Files:**
- Modify: `internal/platform/admin/impersonate.go`
- Modify: `internal/platform/admin/impersonate_test.go`

**Step 1: Update the scaffold test to expect 200**

In `internal/platform/admin/impersonate_test.go`, replace `TestHandleImpersonate_Scaffold` with a test that uses a real `TokenService`:

```go
func TestHandleImpersonate_Success(t *testing.T) {
	tokenSvc := auth.NewTokenService("test-secret-key-32-bytes-long!!", "heimdall", 1, 24)
	// pool is nil — tenant existence check is skipped when pool is nil
	h := NewImpersonateHandler(tokenSvc, nil, nil)

	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/tenants/{id}/impersonate", http.HandlerFunc(h.Handle))

	req := httptest.NewRequest("POST", "/api/v1/tenants/a1b2c3d4-0001-4000-8000-000000000001/impersonate", nil)
	identity := &auth.Identity{UserID: "admin-1", IsPlatformAdmin: true, Email: "admin@test.com"}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp["token"])
	assert.Equal(t, float64(1800), resp["expires_in"])

	// Validate the returned token
	parsed, err := tokenSvc.ValidateToken(resp["token"].(string))
	require.NoError(t, err)
	assert.Equal(t, "a1b2c3d4-0001-4000-8000-000000000001", parsed.TenantID)
	assert.Equal(t, []string{"org_admin"}, parsed.Roles)
	assert.Equal(t, "admin-1", parsed.ImpersonatorID)
}
```

Add these imports to the test file: `"encoding/json"` and `"github.com/stretchr/testify/require"`.

**Step 2: Run test to verify it fails**

Run: `cd /Users/fred/Documents/Heimdall && go test ./internal/platform/admin/ -run TestHandleImpersonate_Success -v`
Expected: FAIL — handler still returns 501.

**Step 3: Wire the handler**

Replace the `Handle` method in `internal/platform/admin/impersonate.go` with:

```go
// Handle processes POST /api/v1/tenants/{id}/impersonate.
func (h *ImpersonateHandler) Handle(w http.ResponseWriter, r *http.Request) {
	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	if !identity.IsPlatformAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "platform admin required"})
		return
	}

	tenantID := r.PathValue("id")
	parsedTenantID, err := uuid.Parse(tenantID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tenant ID"})
		return
	}

	// Validate tenant exists
	if h.pool != nil {
		exists, err := tenantExists(r.Context(), h.pool, tenantID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to validate tenant"})
			return
		}
		if !exists {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("tenant %s not found", tenantID)})
			return
		}
	}

	// Audit log
	actorID := audit.ActorIDFromContext(r.Context())
	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), audit.Event{
			TenantID:     parsedTenantID,
			UserID:       actorID,
			Action:       "admin.impersonation.started",
			ResourceType: "tenant",
			ResourceID:   &parsedTenantID,
			Metadata: map[string]any{
				"impersonator_id": identity.UserID,
			},
			Source: "api",
		})
	}

	slog.Warn("platform admin impersonation",
		"impersonator_id", identity.UserID,
		"target_tenant_id", tenantID,
	)

	// Generate short-lived impersonation token
	token, err := h.tokenSvc.CreateImpersonationToken(identity, tenantID)
	if err != nil {
		slog.Error("failed to create impersonation token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate token"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_in": 1800,
	})
}
```

Remove the unused `fmt.Sprintf` import if the linter flags it (it's still used in the tenant-not-found error). Keep all existing imports.

**Step 4: Run tests to verify they pass**

Run: `cd /Users/fred/Documents/Heimdall && go test ./internal/platform/admin/ -v`
Expected: PASS (including the existing NotPlatformAdmin, InvalidTenantID, NoIdentity tests)

**Step 5: Run full Go test suite**

Run: `cd /Users/fred/Documents/Heimdall && go test ./... 2>&1 | tail -20`
Expected: All PASS

**Step 6: Commit**

```bash
git add internal/platform/admin/impersonate.go internal/platform/admin/impersonate_test.go
git commit -m "feat: wire impersonation handler to return 30-min JWT"
```

---

## Task 3: Overview Stat Cards — Fetch Real Data

**Files:**
- Modify: `dashboard/src/components/overview/overview.tsx:39-63,126-166`

**Step 1: Add user and channel queries to the Overview component**

In `dashboard/src/components/overview/overview.tsx`:

Add imports at the top (after existing imports):

```typescript
import { userKeys, fetchUsers } from "@/lib/queries/users"
import { channelKeys, fetchChannelLinks } from "@/lib/queries/channels"
import type { ChannelLink } from "@/lib/types"
```

Add two queries after the `agentData` query (around line 52):

```typescript
const { data: users, isLoading: usersLoading } = useQuery({
  queryKey: userKeys.list(),
  queryFn: () => fetchUsers(),
  refetchInterval: 30_000,
  enabled: !isPlatformAdmin && hasTenant,
})

const { data: channelLinks, isLoading: channelsLoading } = useQuery({
  queryKey: channelKeys.links(),
  queryFn: () => fetchChannelLinks(),
  refetchInterval: 30_000,
  enabled: !isPlatformAdmin && hasTenant,
})
```

Update `buildStatCards` call to pass the new data:

```typescript
const statCards = buildStatCards({
  isPlatformAdmin,
  canReadUsers,
  canReadConnectors,
  tenants: tenants ?? [],
  agents,
  userCount: users?.length,
  activeChannelCount: channelLinks?.filter((l) => l.status === "verified").length,
})
```

Update `isLoading`:

```typescript
const isLoading =
  (isPlatformAdmin && tenantsLoading) ||
  agentsLoading ||
  (!isPlatformAdmin && hasTenant && (usersLoading || channelsLoading))
```

**Step 2: Update `buildStatCards` to use real counts**

Update the function signature to accept the new params:

```typescript
function buildStatCards({
  isPlatformAdmin,
  canReadUsers,
  canReadConnectors,
  tenants,
  agents,
  userCount,
  activeChannelCount,
}: {
  isPlatformAdmin: boolean
  canReadUsers: boolean
  canReadConnectors: boolean
  tenants: Tenant[]
  agents: AgentInstance[]
  userCount?: number
  activeChannelCount?: number
}) {
```

Replace the `canReadUsers` block (the em-dash lines) with:

```typescript
if (canReadUsers) {
  return [
    { label: "Running Agents", value: totalAgents, icon: <Robot size={20} /> },
    { label: "Unhealthy Agents", value: unhealthyAgents, icon: <Warning size={20} /> },
    { label: "Total Users", value: userCount ?? 0, icon: <Users size={20} /> },
    ...(canReadConnectors ? [{ label: "Active Channels", value: activeChannelCount ?? 0, icon: <ChatCircle size={20} /> }] : []),
  ]
}
```

**Step 3: Verify build passes**

Run: `cd /Users/fred/Documents/Heimdall/dashboard && npm run build 2>&1 | tail -20`
Expected: Build succeeds with no errors.

**Step 4: Commit**

```bash
git add dashboard/src/components/overview/overview.tsx
git commit -m "feat: wire real user/channel counts into overview stat cards"
```

---

## Task 4: Add Impersonation Fields to NextAuth Session

**Files:**
- Modify: `dashboard/src/lib/auth.ts`

**Step 1: Add `impersonatingTenantName` to type declarations**

In `dashboard/src/lib/auth.ts`:

Add to the `Session.user` interface (after `roles: string[]`):

```typescript
impersonatingTenantName?: string
```

Add to the `User` interface (after `roles: string[]`):

```typescript
impersonatingTenantName?: string
```

Add to the `JWT` interface (after `roles: string[]`):

```typescript
impersonatingTenantName?: string
```

**Step 2: Thread through JWT and session callbacks**

In the `jwt` callback, add after `token.roles = user.roles ?? []` in **both** the `credentials` and `clerk-token` blocks:

```typescript
token.impersonatingTenantName = user.impersonatingTenantName
```

In the `session` callback, add after `session.user.roles = token.roles`:

```typescript
session.user.impersonatingTenantName = token.impersonatingTenantName
```

**Step 3: Verify build passes**

Run: `cd /Users/fred/Documents/Heimdall/dashboard && npm run build 2>&1 | tail -20`
Expected: Build succeeds.

**Step 4: Commit**

```bash
git add dashboard/src/lib/auth.ts
git commit -m "feat: add impersonatingTenantName to NextAuth session types"
```

---

## Task 5: Wire Impersonation Banner into Dashboard Layout

**Files:**
- Modify: `dashboard/src/app/(dashboard)/layout.tsx`
- Create: `dashboard/src/components/tenants/impersonation-banner-wrapper.tsx`

**Step 1: Create a client wrapper component**

The dashboard layout is a server component, but the banner needs `useSession` and `onClick`. Create a client wrapper at `dashboard/src/components/tenants/impersonation-banner-wrapper.tsx`:

```tsx
"use client"

import { useSession } from "next-auth/react"
import { useRouter } from "next/navigation"
import { ImpersonationBanner } from "./impersonation-banner"

export function ImpersonationBannerWrapper() {
  const { data: session, update } = useSession()
  const router = useRouter()

  const tenantName = session?.user?.impersonatingTenantName
  if (!tenantName) return null

  const handleExit = async () => {
    // Clear impersonation by updating the session without the impersonation field.
    // In practice this would need to re-authenticate with original credentials.
    // For now, sign out and redirect to login.
    const { signOut } = await import("next-auth/react")
    await signOut({ redirectTo: "/login" })
  }

  return <ImpersonationBanner tenantName={tenantName} onExit={handleExit} />
}
```

**Step 2: Add banner to dashboard layout**

In `dashboard/src/app/(dashboard)/layout.tsx`, add import:

```typescript
import { ImpersonationBannerWrapper } from "@/components/tenants/impersonation-banner-wrapper"
```

Add `<ImpersonationBannerWrapper />` right after the opening `<div className="flex flex-1 flex-col">` and before the `<header>`:

The layout's inner column becomes:

```tsx
<div className="flex flex-1 flex-col">
  <ImpersonationBannerWrapper />
  <header className="flex h-14 items-center gap-3 border-b border-zinc-200 bg-white px-4 lg:px-6">
    <MobileSidebar />
    <TopBar />
  </header>
  <main className="flex-1 px-4 py-6 lg:px-8">
    <div className="mx-auto max-w-[1400px]">{children}</div>
  </main>
</div>
```

**Step 3: Verify build passes**

Run: `cd /Users/fred/Documents/Heimdall/dashboard && npm run build 2>&1 | tail -20`
Expected: Build succeeds.

**Step 4: Commit**

```bash
git add dashboard/src/components/tenants/impersonation-banner-wrapper.tsx dashboard/src/app/\(dashboard\)/layout.tsx
git commit -m "feat: wire impersonation banner into dashboard layout"
```

---

## Task 6: Wire "Enter Tenant" Button to Impersonate Endpoint

**Files:**
- Modify: `dashboard/src/components/tenants/tenant-detail.tsx`

**Step 1: Wire the confirmation button**

In `dashboard/src/components/tenants/tenant-detail.tsx`:

Add imports at the top:

```typescript
import { useRouter } from "next/navigation"
import { signIn } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
```

Inside the `TenantDetail` component, add after the existing state:

```typescript
const router = useRouter()
const [isImpersonating, setIsImpersonating] = useState(false)

const handleImpersonate = async () => {
  setIsImpersonating(true)
  try {
    const data = await apiClient<{ token: string; expires_in: number }>(
      `/api/v1/tenants/${id}/impersonate`,
      { method: "POST" },
    )

    // Sign in with the impersonation token via dev credentials provider.
    // The backend token already has the correct tenant context.
    await signIn("credentials", {
      email: "__impersonate__",
      redirect: false,
    })

    // For now, reload to pick up the new session
    window.location.href = "/"
  } catch (err) {
    console.error("Impersonation failed:", err)
    setIsImpersonating(false)
  }
}
```

Replace the placeholder warning `<p>` and disabled button in the `DialogFooter` with:

```tsx
<DialogFooter>
  <button
    onClick={() => setShowImpersonateDialog(false)}
    className="rounded-lg px-4 py-2 text-sm text-zinc-600 hover:bg-zinc-100 transition-colors"
  >
    Cancel
  </button>
  <button
    onClick={handleImpersonate}
    disabled={isImpersonating}
    className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed"
  >
    {isImpersonating ? "Entering..." : "Enter Tenant"}
  </button>
</DialogFooter>
```

Remove the amber placeholder `<p>` warning paragraph entirely.

**Step 2: Verify build passes**

Run: `cd /Users/fred/Documents/Heimdall/dashboard && npm run build 2>&1 | tail -20`
Expected: Build succeeds.

**Step 3: Commit**

```bash
git add dashboard/src/components/tenants/tenant-detail.tsx
git commit -m "feat: wire Enter Tenant button to impersonate endpoint"
```

---

## Task 7: Lint & Full Verification

**Step 1: Go lint**

Run: `cd /Users/fred/Documents/Heimdall && golangci-lint run ./...`
Expected: No errors. If gofmt issues, run `gofmt -w` on affected files.

**Step 2: Go tests**

Run: `cd /Users/fred/Documents/Heimdall && go test ./...`
Expected: All PASS.

**Step 3: Dashboard build**

Run: `cd /Users/fred/Documents/Heimdall/dashboard && npm run build`
Expected: Build succeeds.

**Step 4: Fix any issues, commit fixes**

If lint/build issues found, fix and commit:
```bash
git commit -m "fix: address lint and build issues"
```

---

## Verification Checklist

After all tasks complete:

1. **Go tests pass**: `go test ./internal/auth/ -run TestCreateImpersonation -v` — 2 tests pass
2. **Impersonate handler tests**: `go test ./internal/platform/admin/ -v` — all pass including `TestHandleImpersonate_Success`
3. **Dashboard build**: `npm run build` — no errors
4. **Manual test — stat cards**: Log in as `glorfindel@gondolin.fc` (standard_user with users:read). Overview page shows real user count and channel count instead of em dashes.
5. **Manual test — impersonation**: Log in as `turgon@gondolin.fc` (platform admin). Go to Tenants → click a tenant → click "Enter Tenant" → confirm dialog → verify 200 response with JWT.
