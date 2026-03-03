# Clerk Headless Auth — Login, Sign-Up & Invites

## Problem

The current Clerk OIDC integration redirects users to Clerk's hosted login page. This prevents custom UI/UX, causes sign-out issues (Clerk maintains a separate persistent session), and blocks multi-account testing. We need our own login/sign-up pages with Clerk handling identity behind the scenes.

## Approach

Use `@clerk/clerk-js` (headless SDK, ~40KB) for password verification and social OAuth. Clerk never shows its own UI. Our forms call Clerk's JS API directly, get a session token, and exchange it for Valinor tokens via the existing `POST /auth/exchange` endpoint.

## Auth Flows

### Sign-In (Email + Password)

```
Our login form → clerk.client.signIn.create({ identifier, password })
  → Clerk returns SignIn with status "complete"
  → Extract session token from active session
  → POST /auth/exchange { id_token: sessionToken, tenant_slug }
  → Backend validates via JWKS → returns Valinor access + refresh tokens
  → NextAuth stores in JWT session → redirect to dashboard
```

### Sign-In (Social OAuth — Google/GitHub)

```
User clicks "Continue with Google"
  → clerk.client.signIn.create({ strategy: "oauth_google", redirectUrl: "/sso-callback" })
  → Redirect to Google → authorize → return to /sso-callback
  → Callback page extracts Clerk session token
  → Same /auth/exchange flow as above
```

### Sign-Up

```
Our signup form → clerk.client.signUp.create({ emailAddress, password, firstName, lastName })
  → Clerk sends verification email
  → User enters code → signUp.attemptEmailAddressVerification({ code })
  → On success: exchange token → backend calls FindOrCreateByOIDC() (user created with tenant_id = NULL)
  → Team step: create new team OR redeem invite code
  → Re-exchange tokens to get fresh JWT with tenant_id
```

### Sign-Out

```
clerk.signOut() → clears Clerk session cookie
signOut({ redirectTo: "/login" }) → clears NextAuth JWT
Both cleared → clean slate, no auto-login
```

## Pages

| Route | Purpose |
|-------|---------|
| `/login` | Email/password form + social buttons (Google, GitHub) |
| `/signup` | Name, email, password form + social buttons |
| `/signup/verify` | Email verification code entry |
| `/signup/team` | Create new team OR enter invite code |
| `/sso-callback` | Hidden — handles social OAuth return from Clerk |

## UI

Full-page layout: subtle gradient background (zinc-950 → zinc-900) with centered floating card. Shared `AuthCard` wrapper, `SocialButtons` (Google + GitHub), `AuthDivider` ("or continue with" separator).

Dev mode coexistence: when `NEXT_PUBLIC_VALINOR_DEV_MODE=true`, login shows email-only form without Clerk SDK.

## Backend Changes

### New: Tenant Self-Service Creation

`POST /api/v1/tenants/self-service` (authenticated, tenantless users only):
- Accepts `{ name: string }`
- Auto-generates slug from name
- Creates tenant
- Assigns user to tenant with `org_admin` role
- Re-issues tokens with `tenant_id`

### New: Invite System

```sql
CREATE TABLE tenant_invites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id),
    code        VARCHAR(32) UNIQUE NOT NULL,
    role        VARCHAR(64) NOT NULL DEFAULT 'standard_user',
    created_by  UUID NOT NULL REFERENCES users(id),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_by     UUID REFERENCES users(id),
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Endpoints:
- `POST /api/v1/invites` — create invite (org_admin only)
- `GET /api/v1/invites` — list active invites
- `DELETE /api/v1/invites/{id}` — revoke invite
- `POST /auth/invite/redeem` — redeem invite code (assigns user to tenant)

### Changes to NextAuth Config

Replace the OIDC Clerk provider with a credentials-style provider that accepts the Clerk session token directly (no redirect).

### No Changes Needed

- Token service, ID token validator, refresh flow, middleware — all unchanged.

## Error Handling

| Scenario | Message |
|----------|---------|
| Wrong password | "Invalid email or password" |
| Account not found | "No account found. Sign up instead?" |
| Email taken (signup) | "Email already in use. Sign in instead?" |
| OAuth cancelled | "Sign-in cancelled" |
| Wrong verification code | "Invalid code. Try again." |
| Rate limited | "Too many attempts. Try again in a few minutes." |
| Expired invite | "This invite has expired. Ask your admin for a new one." |
| Used invite | "This invite has already been used." |
| Invalid invite code | "Invalid invite code." |

## Environment Variables

New:
- `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` — required for `@clerk/clerk-js`

Removed:
- `NEXT_PUBLIC_CLERK_SIGN_OUT_URL` — no longer needed

Retained:
- `AUTH_CLERK_ISSUER`, `AUTH_CLERK_ID`, `AUTH_CLERK_SECRET` — still used by backend for JWKS validation
- `NEXT_PUBLIC_AUTH_CLERK_ENABLED` — gates Clerk vs dev mode on frontend
