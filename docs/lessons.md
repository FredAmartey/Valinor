# Lessons Learned

Patterns and corrections captured during development. Review at session start.

---

## 2026-02-21: Fix ALL identified issues, not just code issues

**Mistake:** When investigating CI failures, I identified the `id-token: write` permission missing from `.github/workflows/claude-review.yml` but dismissed it as "not our code — CI config issue" and only fixed the Go lint errors. The workflow file is in the repo and the fix was a single line.

**Rule:** When diagnosing CI failures, fix everything that's in the repo — workflow files, config, and code. Don't draw an artificial boundary between "code" and "CI config" when both live in the same repository. If the fix is in a file you can edit, it's your job to fix it.

---

## 2026-02-21: Refresh token revocation is a security requirement

**Context:** Stateless JWT refresh tokens cannot be revoked. If a token is compromised, it remains valid until expiry (up to 7 days).

**Deferred fix:** Implement token family rotation — store a family ID per refresh token chain in the database. On each refresh, issue a new token in the same family and invalidate the old one. If a previously-used token is presented (reuse detection), revoke the entire family. This converts refresh tokens from purely stateless to DB-backed, which is the industry standard (RFC 6819 §5.2.2.3).

---

## 2026-02-21: RLS requires non-superuser connections for enforcement

**Context:** PostgreSQL Row Level Security policies are bypassed by superusers and table owners. Tests must create a dedicated non-superuser role (e.g. `rls_user`) and connect as that role to verify RLS policies actually filter data.

**Pattern:** The `WithTenantConnection` function sets `app.current_tenant_id` as a session variable. When that variable is empty/unset, the `::UUID` cast in the RLS policy causes an error rather than silently returning all rows — this is correct security behavior (fail-closed).

---

## 2026-02-21: Platform admin is a boolean flag — revisit when scope grows

**Context:** `is_platform_admin` on the users table is the simplest model that supports tenant provisioning. If platform-level operations grow beyond tenant CRUD (e.g. billing, analytics, support), consider graduating to `platform_role TEXT` or a dedicated `platform_roles` table.

**Rule:** Always run commands from the worktree directory when using git worktrees, not the main repo. The `go test` runner operates on the current working directory's module.

---

## 2026-02-26: Follow the operating loop literally — trigger external review + watch CI at step 6

**Mistake:** When PR #59 opened, I ran my own code review first and only triggered external review after fixing findings. CI lint failed on a `gofmt` issue that sat unnoticed for ~20 minutes.

**Rule:** The moment a PR opens, immediately (1) trigger `@claude` external review on the PR and (2) check CI status. Do your own review in parallel. Steps 6-10 of the operating loop exist to catch issues from multiple sources simultaneously.

---

## 2026-02-26: gofmt alignment only works within contiguous const blocks

**Mistake:** Manually aligned `=` signs across blank-line-separated const groups. `gofmt` only aligns within contiguous blocks, so it reformatted them and CI failed.

**Rule:** Don't manually align constants across groups separated by blank lines. Run `gofmt -d` locally before pushing.

---

## 2026-02-26: Wait for ALL review sources before fixing — don't fix in rounds

**Mistake:** On PR #60, I started fixing my own review findings immediately, pushed them, then Claude's external review came back with additional findings, requiring a second round of fixes. Two push cycles instead of one.

**Rule:** After triggering external review + CI (step 6), do your own review in parallel but **hold all fixes** until both CI and external review results are in (step 7). Triage everything together (step 8), then fix once. One round of fixes, one push, one re-verification.

---

## 2026-02-26: Server-side fetches lack browser headers — pass context explicitly

**Bug:** The dashboard's `exchangeIDToken` function calls `POST /auth/exchange` server-side in a NextAuth callback. The backend resolved the tenant from the `Origin` header, but server-side fetches (Node.js) don't send a browser `Origin`. Tenant resolution always failed for OIDC sign-ins.

**Fix:** Accept an explicit `tenant_slug` field in the exchange request body. The backend tries `tenant_slug` first, then falls back to `Origin` header. The dashboard passes `NEXT_PUBLIC_TENANT_SLUG` env var.

**Rule:** Never rely on browser-only headers (`Origin`, `Referer`, cookies) for server-to-server calls. When a frontend calls a backend on behalf of a user from a server-side context (SSR, middleware, callbacks), pass context like tenant identity explicitly in the request body or as a query parameter.
