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
