# Lessons Learned

Patterns and corrections captured during development. Review at session start.

---

## 2026-02-21: Fix ALL identified issues, not just code issues

**Mistake:** When investigating CI failures, I identified the `id-token: write` permission missing from `.github/workflows/claude-review.yml` but dismissed it as "not our code — CI config issue" and only fixed the Go lint errors. The workflow file is in the repo and the fix was a single line.

**Rule:** When diagnosing CI failures, fix everything that's in the repo — workflow files, config, and code. Don't draw an artificial boundary between "code" and "CI config" when both live in the same repository. If the fix is in a file you can edit, it's your job to fix it.

## 2026-02-21: Run code review BEFORE merging, not after

**Mistake:** Implemented all 10 tasks of Phase 2 Auth + RBAC, pushed a PR, fixed lint, merged — and only then ran a thorough code review. The review found 4 critical security issues (OIDC state not validated, empty tenant ID on callback, no JWT issuer validation, missing `rows.Err()` checks) and 8 important issues (RBAC engine never wired to routes, RLS session variable never set, no refresh token revocation, TOCTOU race, etc.).

**Root cause:** Treated code review as a post-merge quality check instead of a pre-merge gate. The finishing-a-development-branch skill presents options (merge, PR, keep, discard) but doesn't enforce a review step before any of them.

**Rules:**
1. **Review before merge, always.** After all tasks pass and before presenting finish options, run the code-reviewer agent. Fix Critical and Important issues before the PR is created.
2. **Security checklist for auth code.** Any code handling tokens, OIDC, sessions, or authorization must be reviewed for: state/nonce validation, token claim validation (iss, aud, exp), error propagation from iterators (`rows.Err()`), race conditions on create-or-find patterns, and whether authorization is actually enforced (not just built).
3. **"It compiles and tests pass" is not "it's correct."** Tests only catch what they test for. The integration test exercised the happy path but never tested the OIDC callback with a new user (which would have caught the empty tenant ID). Write tests for realistic scenarios, not just the wiring.
4. **Dead code is a red flag.** If an interface (`Service`) or a dependency (`RBAC` in `Dependencies`) is defined but never referenced in actual request handling, that's a sign something was skipped. Grep for unused exports before declaring a task complete.
