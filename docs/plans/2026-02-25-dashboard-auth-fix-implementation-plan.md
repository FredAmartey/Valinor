# Dashboard Auth Fix — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix dashboard authentication by adding a `POST /auth/dev/login` Go endpoint and replacing the broken NextAuth OIDC provider with a credentials provider.

**Architecture:** Go API gets a new dev-only login endpoint that accepts an email and returns real JWTs. Dashboard's NextAuth config switches from a broken OIDC provider to a credentials provider that calls this endpoint. All downstream code (API clients, middleware, components) stays unchanged.

**Tech Stack:** Go (auth handler, store), Next.js (NextAuth credentials provider, login page)

**Design doc:** `docs/plans/2026-02-25-dashboard-auth-fix-design.md`

---

## Task 1: Add `FindByEmail` to Auth Store

**Files:**
- Modify: `internal/auth/store.go`
- Test: `internal/auth/store_test.go` (if exists, otherwise integration test covers it)

**Step 1: Write the failing test**

Add to `internal/auth/handler_test.go` (we'll test through the handler in Task 2, but first add the store method):

The store method is simple enough to test through the handler. Skip standalone store test — the handler test in Task 2 will cover it.

**Step 2: Add FindByEmail method to Store**

Add to `internal/auth/store.go` after `GetIdentityWithRoles`:

```go
// FindUserIDByEmail looks up a user by email address.
// Returns the user ID or ErrUserNotFound if no user matches.
func (s *Store) FindUserIDByEmail(ctx context.Context, email string) (string, error) {
	var userID string
	err := s.pool.QueryRow(ctx,
		"SELECT id FROM users WHERE email = $1",
		email,
	).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrUserNotFound
		}
		return "", fmt.Errorf("querying user by email: %w", err)
	}
	return userID, nil
}
```

Note: This query is NOT tenant-scoped (no RLS filter) because the dev login endpoint needs to find users across tenants — platform admins may not have a tenant. This is acceptable because the endpoint only exists in dev mode.

**Step 3: Verify it compiles**

```bash
go build ./internal/auth/...
```

Expected: Build succeeds.

**Step 4: Commit**

```bash
git add internal/auth/store.go
git commit -m "feat(auth): add FindUserIDByEmail store method for dev login"
```

---

## Task 2: Add `POST /auth/dev/login` Handler

**Files:**
- Modify: `internal/auth/handler.go`
- Modify: `internal/auth/handler_test.go`

**Step 1: Write the failing test**

Add to `internal/auth/handler_test.go`:

```go
func TestHandleDevLogin_ValidEmail(t *testing.T) {
	store := &Store{pool: testPool}
	tokenSvc := newTestTokenService(t)
	handler := NewHandler(HandlerConfig{
		TokenSvc: tokenSvc,
		Store:    store,
	})

	// Create a test user first
	ctx := context.Background()
	_, err := testPool.Exec(ctx, `
		INSERT INTO tenants (id, name, slug) VALUES ('t-dev', 'Dev Tenant', 'dev-tenant')
		ON CONFLICT DO NOTHING`)
	require.NoError(t, err)
	_, err = testPool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, display_name)
		VALUES ('u-dev', 't-dev', 'dev@example.com', 'Dev User')
		ON CONFLICT DO NOTHING`)
	require.NoError(t, err)

	body := `{"email": "dev@example.com"}`
	req := httptest.NewRequest("POST", "/auth/dev/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleDevLogin(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp["access_token"])
	assert.NotEmpty(t, resp["refresh_token"])
	assert.Equal(t, "Bearer", resp["token_type"])
	assert.NotNil(t, resp["user"])
}

func TestHandleDevLogin_UnknownEmail(t *testing.T) {
	store := &Store{pool: testPool}
	tokenSvc := newTestTokenService(t)
	handler := NewHandler(HandlerConfig{
		TokenSvc: tokenSvc,
		Store:    store,
	})

	body := `{"email": "nobody@example.com"}`
	req := httptest.NewRequest("POST", "/auth/dev/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleDevLogin(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleDevLogin_EmptyEmail(t *testing.T) {
	store := &Store{pool: testPool}
	tokenSvc := newTestTokenService(t)
	handler := NewHandler(HandlerConfig{
		TokenSvc: tokenSvc,
		Store:    store,
	})

	body := `{"email": ""}`
	req := httptest.NewRequest("POST", "/auth/dev/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleDevLogin(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
```

Note: These tests use the existing test infrastructure in the auth package (testPool, newTestTokenService). Check the existing test file to match the exact helpers available. Adapt as needed — the test shapes above show the intent.

**Step 2: Run tests to verify they fail**

```bash
go test ./internal/auth/... -run TestHandleDevLogin -v
```

Expected: FAIL — `HandleDevLogin` not defined.

**Step 3: Implement HandleDevLogin**

Add to `internal/auth/handler.go`:

```go
// RegisterDevRoutes registers dev-only auth routes.
// Call this only when devmode is enabled.
func (h *Handler) RegisterDevRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/dev/login", h.HandleDevLogin)
}

// HandleDevLogin authenticates by email in dev mode.
// Looks up the user, issues real access + refresh tokens.
func (h *Handler) HandleDevLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	if req.Email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "email is required",
		})
		return
	}

	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "user store not configured",
		})
		return
	}

	// Find user by email
	userID, err := h.store.FindUserIDByEmail(r.Context(), req.Email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{
				"error": "user not found",
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "user lookup failed",
		})
		return
	}

	// Load full identity with roles
	identity, err := h.store.GetIdentityWithRoles(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "identity loading failed",
		})
		return
	}

	// Issue access token
	accessToken, err := h.tokenSvc.CreateAccessToken(identity)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "token creation failed",
		})
		return
	}

	// Issue refresh token
	refreshToken, err := h.tokenSvc.CreateRefreshToken(identity)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "token creation failed",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"user": map[string]interface{}{
			"id":                identity.UserID,
			"email":             identity.Email,
			"display_name":      identity.DisplayName,
			"tenant_id":         identity.TenantID,
			"is_platform_admin": identity.IsPlatformAdmin,
		},
	})
}
```

**Step 4: Run tests to verify they pass**

```bash
go test ./internal/auth/... -run TestHandleDevLogin -v
```

Expected: PASS.

**Step 5: Commit**

```bash
git add internal/auth/handler.go internal/auth/handler_test.go
git commit -m "feat(auth): add POST /auth/dev/login endpoint for dashboard dev mode"
```

---

## Task 3: Wire Dev Login Route in Server

**Files:**
- Modify: `internal/platform/server/server.go`
- Modify: `cmd/valinor/main.go`

**Step 1: Add dev route registration to server.go**

In `internal/platform/server/server.go`, in the `New` function, after the auth handler route registration block (`if deps.AuthHandler != nil`), add:

```go
// Dev-only login route (no auth required)
if deps.DevMode && deps.AuthHandler != nil {
	deps.AuthHandler.RegisterDevRoutes(topMux)
}
```

This registers `POST /auth/dev/login` on the public mux (no auth middleware), but only when dev mode is enabled.

**Step 2: Verify Go builds and tests pass**

```bash
go build ./cmd/valinor && go test ./internal/platform/server/... && go test ./internal/auth/...
```

Expected: Build succeeds, all tests pass.

**Step 3: Commit**

```bash
git add internal/platform/server/server.go
git commit -m "feat(server): wire dev login route when devmode enabled"
```

---

## Task 4: Replace NextAuth OIDC Provider with Credentials Provider

**Files:**
- Modify: `dashboard/src/lib/auth.ts`

**Step 1: Rewrite auth.ts**

Replace the entire contents of `dashboard/src/lib/auth.ts` with:

```typescript
import NextAuth from "next-auth"
import Credentials from "next-auth/providers/credentials"
import type { NextAuthConfig } from "next-auth"

// Extend the built-in types
declare module "next-auth" {
  interface Session {
    accessToken: string
    user: {
      id: string
      email: string
      name: string
      tenantId: string | null
      isPlatformAdmin: boolean
    }
  }

  interface User {
    id: string
    email: string
    name: string
    tenantId: string | null
    isPlatformAdmin: boolean
    accessToken: string
    refreshToken: string
  }
}

declare module "@auth/core/jwt" {
  interface JWT {
    accessToken: string
    refreshToken: string
    expiresAt: number
    userId: string
    tenantId: string | null
    isPlatformAdmin: boolean
  }
}

const VALINOR_API_URL = process.env.VALINOR_API_URL ?? "http://localhost:8080"

export const authConfig: NextAuthConfig = {
  providers: [
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

        if (!res.ok) return null

        const data = await res.json()
        return {
          id: data.user.id,
          email: data.user.email,
          name: data.user.display_name ?? data.user.email,
          tenantId: data.user.tenant_id ?? null,
          isPlatformAdmin: data.user.is_platform_admin ?? false,
          accessToken: data.access_token,
          refreshToken: data.refresh_token,
        }
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      // Initial sign-in: persist tokens from authorize response
      if (user) {
        token.accessToken = user.accessToken
        token.refreshToken = user.refreshToken
        token.expiresAt = Math.floor(Date.now() / 1000) + 24 * 60 * 60 // 24h
        token.userId = user.id ?? ""
        token.tenantId = user.tenantId ?? null
        token.isPlatformAdmin = user.isPlatformAdmin ?? false
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
        token.expiresAt = Math.floor(Date.now() / 1000) + 24 * 60 * 60
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

Key changes from the broken OIDC version:
- `Credentials` provider instead of custom OIDC
- `authorize()` calls `POST /auth/dev/login` on the Go API
- `jwt` callback reads from `user` (authorize response) instead of `account` (OIDC response)
- `session: { strategy: "jwt" }` explicitly set (required for credentials provider)
- Token refresh unchanged

**Step 2: Verify dashboard builds**

```bash
cd dashboard && npm run build
```

Expected: Build succeeds.

**Step 3: Commit**

```bash
git add src/lib/auth.ts
git commit -m "feat(dashboard): replace broken OIDC provider with credentials provider for dev login"
```

---

## Task 5: Update Login Page

**Files:**
- Modify: `dashboard/src/app/(auth)/login/page.tsx`

**Step 1: Rewrite the login page**

Replace `dashboard/src/app/(auth)/login/page.tsx` with:

```tsx
"use client"

import { signIn } from "next-auth/react"
import { useState } from "react"
import { useRouter } from "next/navigation"

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
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
        <form onSubmit={handleSubmit} className="space-y-4">
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
          {error && (
            <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
              <p className="text-sm text-rose-700">{error}</p>
            </div>
          )}
          <button
            type="submit"
            disabled={loading || !email}
            className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? "Signing in..." : "Sign in (Dev Mode)"}
          </button>
        </form>
        <p className="text-center text-xs text-zinc-400">
          Dev mode authentication. Enter any existing user email.
        </p>
      </div>
    </div>
  )
}
```

Key changes:
- Now a `"use client"` component (needs `useState`, `signIn` from `next-auth/react`)
- Email input field instead of SSO button
- Calls `signIn("credentials", { email, redirect: false })` for client-side error handling
- Shows error on invalid email / user not found
- Shows "Dev Mode" label so it's clear this isn't production auth

**Step 2: Verify dashboard builds**

```bash
cd dashboard && npm run build
```

Expected: Build succeeds.

**Step 3: Commit**

```bash
git add src/app/\(auth\)/login/page.tsx
git commit -m "feat(dashboard): update login page with email input for dev mode credentials"
```

---

## Task 6: Update Playwright Smoke Tests

**Files:**
- Modify: `dashboard/tests/e2e/smoke.spec.ts`

**Step 1: Update smoke test**

Update `dashboard/tests/e2e/smoke.spec.ts` to match the new login page:

```typescript
import { test, expect } from "@playwright/test"

test.describe("Dashboard smoke tests", () => {
  test("login page renders with email input", async ({ page }) => {
    await page.goto("/login")
    await expect(page.getByText("Valinor Dashboard")).toBeVisible()
    await expect(page.getByLabel("Email")).toBeVisible()
    await expect(page.getByText("Sign in (Dev Mode)")).toBeVisible()
  })

  test("unauthenticated user is redirected to login", async ({ page }) => {
    await page.goto("/")
    await expect(page).toHaveURL(/login/)
  })
})
```

**Step 2: Verify build**

```bash
cd dashboard && npm run build
```

**Step 3: Commit**

```bash
git add tests/e2e/smoke.spec.ts
git commit -m "test(dashboard): update smoke tests for credentials login page"
```

---

## Task 7: Final Verification

**Step 1: Run all Go tests**

```bash
go test ./internal/auth/... -v
```

Expected: All tests pass including new dev login tests.

**Step 2: Run all dashboard tests**

```bash
cd dashboard && npx vitest run
```

Expected: All tests pass.

**Step 3: Run dashboard build**

```bash
cd dashboard && npm run build
```

Expected: Zero TypeScript errors.

**Step 4: Run Go lint**

```bash
cd /path/to/worktree && gofmt -l ./internal/auth/
```

Expected: No formatting issues.

**Step 5: Commit if any cleanup needed**

```bash
git add -A
git commit -m "chore: auth fix final verification pass"
```

---

## Summary

| Task | What | Side | Tests |
|------|------|------|-------|
| 1 | `FindUserIDByEmail` store method | Go | Through handler test |
| 2 | `POST /auth/dev/login` handler | Go | 3 handler tests |
| 3 | Wire dev route in server | Go | Build check |
| 4 | Replace OIDC with credentials provider | Dashboard | Build check |
| 5 | Update login page with email input | Dashboard | Build check |
| 6 | Update Playwright smoke tests | Dashboard | Smoke tests |
| 7 | Final verification | Both | Full suite |
