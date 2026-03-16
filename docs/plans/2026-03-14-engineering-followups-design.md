# Engineering Follow-ups Design

## Scope

This slice addresses the four deferred engineering follow-ups from the trust-platform merge:

1. Reduce risky duplication between `HandleMessage` and `HandleStream` in the proxy handler.
2. Split approval resolution failures into distinct cases instead of collapsing all `pgx.ErrNoRows` outcomes into `ErrApprovalNotPending`.
3. Consolidate duplicated JSON response writing for the trust-platform handlers touched by this slice.
4. Reduce noisy outbound phone-number review findings while preserving secret and email detection.

## Goals

- Keep the changes small enough to review as one focused follow-up.
- Preserve the behavior and security posture shipped in the trust-platform merge.
- Improve operator correctness and maintainability without broad handler/framework churn.

## Non-goals

- Rewriting all handler packages to use one shared HTTP helper in a single pass.
- Reworking the broader outbound-scanning model beyond the noisy phone-number rule.
- Redesigning approval UX or proxy transport semantics.

## Approach

### 1. Proxy preflight extraction

`internal/proxy/handler.go` currently duplicates a large amount of request setup logic across `HandleMessage` and `HandleStream`. The duplication is most risky around:

- agent lookup
- tenant verification
- request body limits and decoding
- sentinel scan behavior
- prompt-received activity and audit logging

The fix will extract a shared preflight helper that returns a normalized request context containing:

- resolved agent instance
- canonical tenant attribution
- decoded and context-injected message body
- prepared connection/request frame inputs

The two handlers will still diverge where they should:

- HTTP JSON response aggregation for `HandleMessage`
- SSE framing/streaming for `HandleStream`

This keeps the hot-path differences explicit while moving the security-sensitive shared logic to one place.

### 2. Approval error model

`internal/approvals/approvals.go` currently treats every failed resolution update as `ErrApprovalNotPending`. That hides materially different conditions:

- approval not found
- approval belongs to a different tenant
- reviewer is the requester
- approval already resolved / not pending

The fix will introduce a small preflight read before the update so `resolve` can return distinct sentinel errors. The handler will then map them to clearer HTTP responses:

- `404` for not found
- `403` for self-approval blocked
- `409` for not pending

Tenant mismatch will still be treated as not found to avoid leaking cross-tenant existence.

### 3. Shared JSON writer

There are many `writeJSON` helpers across the repo, but this slice will only consolidate the trust-platform handlers we are actively modifying:

- `internal/approvals/handler.go`
- `internal/policies/handler.go`
- `internal/platform/server/server.go`

We will add a tiny shared helper under `internal/platform/httputil` and switch these handlers to it. This gives immediate duplication relief in the touched area without turning the slice into a repo-wide handler cleanup.

### 4. Outbound phone-number tuning

The current phone-number regex flags too many generic digit sequences. The fix will narrow review matches to more phone-like shapes by requiring stronger separators/structure instead of accepting many raw 10-digit patterns.

We will preserve:

- block-on-secret detection
- block-on-malicious payload detection
- review-on-email detection

We will add focused scanner tests showing:

- a realistic phone number still triggers review
- order IDs and similar long numeric strings do not

## Testing strategy

- Add targeted proxy handler tests covering both message and stream paths through the shared preflight helper.
- Add approval store and handler tests for each distinct error outcome.
- Add focused tests for the shared JSON helper only where behavior matters.
- Add outbound-scan tests for phone positives and false-positive regressions.
- Run full Go test verification after the targeted red/green cycle.

## Cleanup decisions

- Delete merged remote branch `feat/trust-platform-foundation`.
- Remove merged helper worktrees:
  - `/Users/fred/Documents/Heimdall/.worktrees/master-merge-fixes`
  - `/Users/fred/Documents/Heimdall/.worktrees/security-trust-platform`
- Remove matching local helper branches.
- Preserve the main dirty workspace on `feat/trust-platform-foundation` untouched.
- Execute this slice in the fresh worktree:
  - `/Users/fred/Documents/Heimdall/.worktrees/trust-platform-followups`
  - branch: `codex/trust-platform-followups`
