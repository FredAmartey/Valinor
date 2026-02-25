# Dashboard Auth Integration Fix — Design Document

## Problem

The dashboard's NextAuth configuration treats Valinor as an OIDC server (`type: "oidc"`, `issuer: VALINOR_API_URL`), but Valinor is an OIDC client (relying party). NextAuth expects a discovery document at `/.well-known/openid-configuration` which Valinor does not serve. The dashboard cannot authenticate.

## Solution

### Ship Now: Dev Mode Credentials Provider

Add a `POST /auth/dev/login` endpoint to the Go API (dev mode only) and replace the broken NextAuth OIDC provider with a `credentials` provider.

### Design Only (Deferred): Production OIDC via Clerk

Dashboard connects to Clerk directly for OIDC auth. On successful login, exchanges the Clerk id_token with Valinor for platform JWTs via a new `POST /auth/exchange` endpoint.

---

## Dev Mode Auth Flow

### New Go Endpoint: `POST /auth/dev/login`

- **Condition:** Only registered when `config.Auth.DevMode == true`
- **Request body:** `{ "email": "user@example.com" }`
- **Behavior:**
  1. Look up user by email in the database
  2. Load full identity with roles (`GetIdentityWithRoles`)
  3. Issue real access + refresh tokens (same code path as OIDC callback)
  4. Return tokens + user info
- **Response (200):**
  ```json
  {
    "access_token": "eyJ...",
    "refresh_token": "eyJ...",
    "token_type": "Bearer",
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "display_name": "User Name",
      "tenant_id": "uuid",
      "is_platform_admin": false
    }
  }
  ```
- **Error responses:**
  - 404: User not found
  - 400: Missing/invalid email
  - 404 (or not registered): When `devmode: false`

### Dashboard NextAuth Changes

Replace the `oidc` provider in `dashboard/src/lib/auth.ts` with a `credentials` provider:

```typescript
providers: [
  Credentials({
    credentials: {
      email: { label: "Email", type: "email" },
    },
    async authorize(credentials) {
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
        name: data.user.display_name,
        tenantId: data.user.tenant_id,
        isPlatformAdmin: data.user.is_platform_admin,
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
      }
    },
  }),
]
```

**JWT callback:** Stores accessToken, refreshToken, and user claims from the authorize response. Token refresh still calls `POST /auth/token/refresh` (unchanged).

**Session callback:** Exposes accessToken and user claims to client components (unchanged).

### Login Page

Update `dashboard/src/app/(auth)/login/page.tsx`:
- Email input field
- "Sign in (Dev Mode)" submit button
- Calls `signIn("credentials", { email, redirectTo: "/" })`
- Error message on invalid email

### Unchanged

- `dashboard/src/middleware.ts` — still protects routes
- `dashboard/src/lib/api.ts` / `api-client.ts` — still sends `Bearer <token>`
- All existing dashboard components — no changes

---

## Production OIDC via Clerk (Deferred)

### Architecture

```
User → Dashboard → Clerk OIDC login → Clerk callback → Dashboard
  → POST /auth/exchange (Clerk id_token) → Valinor validates → Valinor JWT
  → Dashboard stores Valinor JWT in session
```

### New Go Endpoint: `POST /auth/exchange` (future)

- Accepts `{ "id_token": "clerk-issued-jwt" }`
- Validates the Clerk id_token against Clerk's JWKS
- Resolves user by OIDC subject + issuer (existing `FindOrCreateByOIDC`)
- Issues Valinor access + refresh tokens
- Returns same shape as `/auth/dev/login` response

### Dashboard Changes (future)

- Add Clerk as NextAuth provider (or use `@clerk/nextjs` directly)
- On sign-in callback, call `POST /auth/exchange` with the Clerk id_token
- Store Valinor JWTs in session (same as dev mode path)

### Why Clerk

- Full auth platform: user management UI, MFA, org/team support
- First-class NextAuth adapter
- Handles auth UX (sign-up, password reset, MFA) that Valinor shouldn't own
- $25/mo for 1K MAU

---

## Testing

### Go

- `POST /auth/dev/login` with valid email → 200 + tokens
- `POST /auth/dev/login` with unknown email → 404
- `POST /auth/dev/login` with empty email → 400
- Endpoint NOT registered when `devmode: false`

### Dashboard

- NextAuth credentials provider authorize function — mock API call
- Login page renders email input and submit button
- Login flow end-to-end with dev API running

---

## Acceptance Criteria

1. Dashboard login page shows email input
2. Entering a valid email signs in and shows the dashboard with real data
3. Session includes real Valinor JWT — API calls work with real auth
4. Token refresh works transparently via `POST /auth/token/refresh`
5. Invalid email shows error message
6. `POST /auth/dev/login` returns 404 when `devmode: false`
7. No changes to existing dashboard components or API clients

---

## Files Changed

### Go (new/modified)
- `internal/auth/handler.go` — add `HandleDevLogin` method
- `internal/auth/handler.go` — add `RegisterDevRoutes` method
- `internal/auth/handler_test.go` — tests for dev login
- `cmd/valinor/main.go` — register dev routes when `devmode: true`
- `internal/platform/server/server.go` — wire dev login route

### Dashboard (modified)
- `dashboard/src/lib/auth.ts` — replace OIDC provider with credentials
- `dashboard/src/app/(auth)/login/page.tsx` — email input form

---

## Risks & Rollback

| Risk | Mitigation |
|------|------------|
| Dev login endpoint exposed in production | Only registered when `devmode: true`. Config default is `false` |
| Credentials provider session differs from future OIDC | Both paths store the same shape: Valinor JWT + user claims |

Rollback: Revert the two files on each side. Dashboard falls back to broken OIDC (status quo).
