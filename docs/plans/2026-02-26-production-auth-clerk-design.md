# Production Auth via Clerk — Design Document

## Problem

The dashboard only supports dev-mode credentials login (email-only, no password). Production deployments need real authentication with a proper identity provider.

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Identity provider | Clerk | Full auth platform: hosted login, MFA, user management. $25/mo for 1K MAU |
| Dashboard integration | Clerk as NextAuth OIDC provider | Keeps existing NextAuth session/JWT infrastructure. Minimal rewrite. Easy to swap IdP later |
| Dev mode | Keep alongside Clerk | Local development stays frictionless. Clerk activates via config |
| Tenant resolution | Subdomain-based | `gondolin.valinor.app` → tenant `gondolin-fc`. Reuses existing `TenantResolver` |

## Architecture

```
User → Dashboard (gondolin.valinor.app)
  → NextAuth sign-in → Clerk OIDC redirect → Clerk hosted login
  → Clerk callback → NextAuth signIn callback
  → POST /auth/exchange { id_token: "clerk-jwt" }
  → Valinor validates Clerk token via JWKS
  → Resolves tenant from subdomain (TenantResolver)
  → FindOrCreateByOIDC (oidc_subject + oidc_issuer)
  → Issues Valinor access + refresh tokens
  → NextAuth stores Valinor JWTs in session (same as dev mode)
```

## Backend Changes

### New Endpoint: `POST /auth/exchange`

Accepts an external OIDC id_token and returns Valinor tokens.

**Request:**
```json
{
  "id_token": "<clerk-issued-jwt>"
}
```

**Validation:**
1. Fetch Clerk's JWKS from configured `jwks_url` (cached in memory with TTL)
2. Validate JWT signature against JWKS
3. Validate `iss` matches configured issuer
4. Validate `aud` matches configured client_id
5. Validate `exp` is in the future
6. Extract `sub`, `email`, `name` from verified claims

**User Resolution:**
1. Resolve tenant from `Origin` header via existing `TenantResolver`
2. Call existing `FindOrCreateByOIDC(ctx, OIDCUserInfo{Issuer, Subject, Email, Name}, tenantID)`
3. Call existing `GetIdentityWithRoles(ctx, userID)`

**Token Issuance:**
1. Create access token via `tokenSvc.CreateAccessToken(identity)`
2. Create refresh token via `tokenSvc.CreateRefreshToken(identity)` with family tracking
3. Return same response shape as `/auth/dev/login`

**Response (200):**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "display_name": "User Name",
    "tenant_id": "uuid",
    "is_platform_admin": false
  }
}
```

**Errors:**
- 400: Missing or malformed id_token
- 401: Invalid signature, expired token, wrong issuer/audience
- 404: Tenant not found (subdomain doesn't match)
- 503: OIDC not configured

### New: JWKS Client

Lightweight JWKS fetcher with in-memory cache:
- Fetches `/.well-known/jwks.json` from configured URL
- Caches keys with configurable TTL (default 1 hour)
- Refreshes on cache miss (handles key rotation)
- Uses `crypto/rsa` + `encoding/json` — no external OIDC library needed

### Config Extension

```yaml
auth:
  devmode: true                    # existing — enables POST /auth/dev/login
  signing_key: "..."               # existing — Valinor JWT signing key
  oidc:
    enabled: false                 # toggle for production
    issuer: "https://clerk.example.com"
    client_id: "clerk_..."
    jwks_url: "https://clerk.example.com/.well-known/jwks.json"
```

Note: `client_secret` is not needed for the exchange endpoint — we only validate id_tokens via JWKS, we don't do the OAuth2 code exchange on the backend. NextAuth handles the code exchange directly with Clerk.

### Registration

- `POST /auth/exchange` registers when `auth.oidc.enabled: true`
- `POST /auth/dev/login` registers when `auth.devmode: true` (unchanged)
- Both can coexist

## Dashboard Changes

### NextAuth Provider Config (`auth.ts`)

Add Clerk as a second provider alongside the existing credentials provider:

```typescript
providers: [
  // Dev mode (when env var is set)
  ...(process.env.VALINOR_DEV_MODE ? [Credentials({...})] : []),

  // Production OIDC via Clerk (when env vars are set)
  ...(process.env.AUTH_CLERK_ISSUER ? [{
    id: "clerk",
    name: "Clerk",
    type: "oidc",
    issuer: process.env.AUTH_CLERK_ISSUER,
    clientId: process.env.AUTH_CLERK_ID!,
    clientSecret: process.env.AUTH_CLERK_SECRET!,
  }] : []),
]
```

### Token Exchange in signIn Callback

After Clerk authenticates, the NextAuth `signIn` callback intercepts the OIDC response:

1. Extract `id_token` from the account object (`account.id_token`)
2. Call `POST ${VALINOR_API_URL}/auth/exchange` with the id_token
3. Attach the returned Valinor tokens to the user object
4. The existing `jwt` callback stores them in the session token

This mirrors how the dev credentials provider works — both paths produce the same user object shape with `accessToken`, `refreshToken`, and user claims.

### Login Page

- **Dev mode only** (`VALINOR_DEV_MODE` set): Email input + "Sign in (Dev Mode)" button (current)
- **Clerk only** (`AUTH_CLERK_ISSUER` set): "Sign in" button → `signIn("clerk")`
- **Both**: Show both options (useful for local testing of the Clerk flow)

### What Stays Unchanged

- JWT callback (stores Valinor tokens — same shape from both providers)
- Session callback (exposes accessToken, user roles, tenantId)
- Token refresh flow (`POST /auth/token/refresh`)
- Middleware route protection
- All dashboard components and API calls
- `useSession()` usage throughout the app
- Refresh token family rotation

## Tenant Resolution

The exchange endpoint resolves tenant from the request's `Origin` header:

```
Origin: https://gondolin.valinor.app
  → subdomain: gondolin
  → TenantResolver.Resolve("gondolin")
  → tenant_id: a1b2c3d4-0001-4000-8000-000000000001
```

Platform admins (matched by `oidc_issuer` + `oidc_subject` in the users table with `is_platform_admin = true`) bypass tenant resolution and get a tenantless token — same as the existing OIDC callback flow.

## Security

- Id_tokens validated via JWKS (RSA signature verification) — not just decoded
- JWKS keys cached but refreshable on unknown `kid` (handles rotation)
- `aud` claim must match configured `client_id` — prevents token confusion
- `iss` claim must match configured issuer — prevents cross-IdP attacks
- Exchange endpoint rate-limited by existing middleware
- No `client_secret` stored on backend — only NextAuth needs it for code exchange

## Testing

### Go

- `POST /auth/exchange` with valid mock id_token → 200 + Valinor tokens
- `POST /auth/exchange` with expired token → 401
- `POST /auth/exchange` with wrong audience → 401
- `POST /auth/exchange` with wrong issuer → 401
- `POST /auth/exchange` with unknown tenant subdomain → 404
- `POST /auth/exchange` not registered when `oidc.enabled: false`
- JWKS client: cache hit, cache miss + fetch, key rotation
- Platform admin bypass: tenantless token when admin matched by OIDC subject

### Dashboard

- Login page renders Clerk button when `AUTH_CLERK_ISSUER` is set
- Login page renders dev mode when `VALINOR_DEV_MODE` is set
- signIn callback exchanges id_token for Valinor tokens (mock API)
- Session contains Valinor JWT after Clerk sign-in

## Risks

| Risk | Mitigation |
|------|------------|
| Clerk outage blocks login | Dev mode available as fallback. Existing sessions remain valid (JWT-based) |
| JWKS fetch fails | Cached keys serve requests. Log error. Return 503 only if cache is empty |
| User exists in Clerk but not Valinor | `FindOrCreateByOIDC` auto-creates with default role (no permissions until assigned) |
| Subdomain spoofing via Origin header | Origin validated against configured `base_domain`. Mismatches rejected |
