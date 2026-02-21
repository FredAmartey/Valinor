# Phase 3: Multi-Tenant Hardening — Backlog

**Goal:** Address remaining security and scalability gaps before onboarding real tenants. Each item was identified during Phase 2 code review but deferred because it requires design decisions or infrastructure changes beyond the immediate hardening scope.

**Builds on:** Phase 2 Auth + RBAC (PR #2) and Phase 2 Hardening (PR #3)

---

## P0 — Required Before Production Tenants

### 1. HMAC-Signed OIDC State Tokens (Replace In-Memory Store)

**Problem:** `StateStore` keeps OIDC state in a per-process map. In multi-replica deployments, login and callback may hit different instances, breaking state validation.

**Solution:** Replace the in-memory store with HMAC-signed state tokens. The state value becomes `base64(nonce + timestamp + HMAC(nonce + timestamp, signing_key))`. Validation checks the signature and TTL — no shared storage needed. The cookie binding still provides CSRF protection.

**Files:**
- Modify: `internal/auth/state.go` — Replace map-based store with sign/verify functions
- Modify: `internal/auth/state_test.go` — Test signing, verification, expiry, tampering
- Modify: `internal/auth/handler.go` — Update Generate/Validate call sites
- Delete background cleanup goroutine (no longer needed)

**Complexity:** Small. Reuses existing HMAC signing key from `TokenService`.

---

### 2. Refresh Token Family Rotation (Revocation Support)

**Problem:** Refresh tokens are stateless JWTs with no revocation. A compromised token remains valid until expiry (up to 7 days). Documented in `docs/lessons.md`.

**Solution:** Implement token family rotation per RFC 6819 §5.2.2.3:
- Store a `token_family_id` per refresh token chain in a new `refresh_tokens` table
- On each refresh, issue a new token in the same family and invalidate the old one
- If a previously-used token is presented (reuse detection), revoke the entire family
- Converts refresh tokens from purely stateless to DB-backed

**Files:**
- Create: `migrations/000003_refresh_tokens.up.sql` — `refresh_tokens` table (family_id, token_hash, used_at, revoked_at)
- Create: `migrations/000003_refresh_tokens.down.sql`
- Create: `internal/auth/refresh_store.go` — Token family CRUD
- Modify: `internal/auth/handler.go` — `HandleRefresh` checks family, rotates, detects reuse
- Modify: `internal/auth/handler_test.go` — Rotation happy path, reuse detection, family revocation

**Complexity:** Medium. New table, new store, handler changes.

---

## P1 — Required Before Multi-Replica Deployment

### 3. RLS Policy Enforcement Tests

**Problem:** `WithTenantConnection` sets the session variable, but there are no integration tests proving that RLS policies actually block cross-tenant reads/writes.

**Solution:** Add integration tests that:
- Create two tenants with separate data
- Query as tenant A, verify only tenant A's data is returned
- Attempt to read tenant B's data as tenant A, verify empty result

**Files:**
- Modify: `internal/platform/database/tenant_test.go` — Add RLS isolation integration tests
- May need: test fixtures / seed data helpers

**Complexity:** Small, but requires test database with RLS policies enabled.

---

### 4. Tenant Provisioning API

**Problem:** Tenants are assumed to exist in the `tenants` table (by slug), but there's no API to create them. Currently requires manual DB inserts.

**Solution:** Add tenant CRUD endpoints:
- `POST /api/v1/tenants` (org_admin only) — Create tenant with slug, name
- `GET /api/v1/tenants/:id` — Read tenant details
- Slug validation (lowercase alphanumeric + hyphens, no reserved words)

**Complexity:** Medium. New domain package, handlers, migration for any missing columns.

---

## P2 — Nice-to-Have Improvements

### 5. Rate Limiting on Auth Endpoints

**Problem:** No rate limiting on `/auth/login`, `/auth/callback`, `/auth/token/refresh`. Brute-force and credential stuffing attacks are unmitigated.

**Solution:** Add rate limiting middleware (per-IP or per-tenant) using a token bucket. Consider `golang.org/x/time/rate` for single-instance or Redis-based for multi-replica.

---

### 6. Audit Logging for Auth Events

**Problem:** No structured logging for security-relevant events (login, token refresh, permission denied, tenant resolution failure).

**Solution:** Add audit log entries at each auth decision point. Use structured slog fields for tenant_id, user_id, event_type, outcome.

---
