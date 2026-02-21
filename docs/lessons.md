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
