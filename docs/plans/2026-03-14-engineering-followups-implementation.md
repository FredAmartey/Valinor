# Engineering Follow-ups Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Address the four deferred trust-platform engineering follow-ups in one focused slice without broadening scope.

**Architecture:** Extract shared proxy preflight logic, introduce a precise approval resolution error model, add a small shared JSON response helper for touched trust-platform handlers, and tighten outbound phone-number review scanning with focused regression tests.

**Tech Stack:** Go, pgx, net/http, testify, GitHub Actions parity via `go test ./...`

---

### Task 1: Record the clean baseline

**Files:**
- Verify: `/Users/fred/Documents/Heimdall/.worktrees/trust-platform-followups`

**Step 1: Confirm branch and workspace**

Run:
```bash
git status --short --branch
```

Expected: clean `codex/trust-platform-followups` worktree.

**Step 2: Confirm baseline tests**

Run:
```bash
go test ./...
```

Expected: PASS.

---

### Task 2: Approval resolution error model

**Files:**
- Modify: `/Users/fred/Documents/Heimdall/.worktrees/trust-platform-followups/internal/approvals/approvals.go`
- Modify: `/Users/fred/Documents/Heimdall/.worktrees/trust-platform-followups/internal/approvals/handler.go`
- Test: `/Users/fred/Documents/Heimdall/.worktrees/trust-platform-followups/internal/approvals/approvals_test.go`
- Test: `/Users/fred/Documents/Heimdall/.worktrees/trust-platform-followups/internal/approvals/handler_test.go`

**Step 1: Write/extend failing store tests**

Add tests for:
- not found returns `ErrApprovalNotFound`
- self-approval returns a new sentinel error
- already-resolved returns `ErrApprovalNotPending`

**Step 2: Verify RED**

Run:
```bash
go test ./internal/approvals -run 'TestStoreResolve_|TestHandlerResolve_' -v
```

Expected: FAIL on the new cases.

**Step 3: Implement minimal store changes**

- add distinct sentinel error for self-approval
- preflight lookup inside `resolve`
- keep tenant mismatch indistinguishable from not found
- preserve existing outbox status updates on successful resolution

**Step 4: Update handler status mapping**

- `404` for not found
- `403` for self-approval blocked
- `409` for not pending

**Step 5: Verify GREEN**

Run:
```bash
go test ./internal/approvals -run 'TestStoreResolve_|TestHandlerResolve_' -v
```

Expected: PASS.

---

### Task 3: Proxy preflight extraction

**Files:**
- Modify: `/Users/fred/Documents/Heimdall/.worktrees/trust-platform-followups/internal/proxy/handler.go`
- Test: `/Users/fred/Documents/Heimdall/.worktrees/trust-platform-followups/internal/proxy/handler_test.go`

**Step 1: Add failing regression coverage**

Add or extend tests to prove both `HandleMessage` and `HandleStream` still:
- reject blocked sentinel scans the same way
- log prompt acceptance the same way
- preserve tenant ownership checks

**Step 2: Verify RED**

Run:
```bash
go test ./internal/proxy -run 'TestHandle(Message|Stream)_' -v
```

Expected: FAIL once assertions target the extracted shared behavior.

**Step 3: Implement minimal extraction**

- introduce a small shared helper for the common preflight path
- keep transport-specific response handling in each public handler
- do not change the runtime reply-switch semantics unless required by the refactor

**Step 4: Verify GREEN**

Run:
```bash
go test ./internal/proxy -run 'TestHandle(Message|Stream)_' -v
```

Expected: PASS.

---

### Task 4: Shared JSON writer for touched trust-platform handlers

**Files:**
- Create: `/Users/fred/Documents/Heimdall/.worktrees/trust-platform-followups/internal/platform/httputil/json.go`
- Modify: `/Users/fred/Documents/Heimdall/.worktrees/trust-platform-followups/internal/approvals/handler.go`
- Modify: `/Users/fred/Documents/Heimdall/.worktrees/trust-platform-followups/internal/policies/handler.go`
- Modify: `/Users/fred/Documents/Heimdall/.worktrees/trust-platform-followups/internal/platform/server/server.go`
- Test: `/Users/fred/Documents/Heimdall/.worktrees/trust-platform-followups/internal/approvals/handler_test.go`
- Test: `/Users/fred/Documents/Heimdall/.worktrees/trust-platform-followups/internal/policies/handler_test.go`

**Step 1: Add a focused helper test only if needed**

If existing handler tests already cover status/body behavior, prefer reusing them instead of inventing a new helper test package.

**Step 2: Implement the helper**

- write a minimal `WriteJSON` helper
- keep behavior identical: set content type, write status, encode response

**Step 3: Replace the touched local helpers**

- switch approvals, policies, and server handlers
- remove the now-unused local `writeJSON` duplicates in those files only

**Step 4: Verify**

Run:
```bash
go test ./internal/approvals ./internal/policies ./internal/platform/server -v
```

Expected: PASS.

---

### Task 5: Outbound phone-number noise reduction

**Files:**
- Modify: `/Users/fred/Documents/Heimdall/.worktrees/trust-platform-followups/internal/channels/outbound_scan.go`
- Test: `/Users/fred/Documents/Heimdall/.worktrees/trust-platform-followups/internal/channels/outbound_scan_test.go`

**Step 1: Write failing scanner tests**

Add tests for:
- a realistic phone number triggers `review`
- a generic order/ID digit string does not
- existing email detection still triggers `review`

**Step 2: Verify RED**

Run:
```bash
go test ./internal/channels -run 'TestStructuredOutboundScanner_' -v
```

Expected: FAIL on the new false-positive regression case.

**Step 3: Implement minimal regex tightening**

- require more phone-like formatting/separators
- avoid generic uninterrupted 10-digit matches

**Step 4: Verify GREEN**

Run:
```bash
go test ./internal/channels -run 'TestStructuredOutboundScanner_' -v
```

Expected: PASS.

---

### Task 6: Full verification

**Files:**
- Verify: `/Users/fred/Documents/Heimdall/.worktrees/trust-platform-followups`

**Step 1: Run targeted package tests**

Run:
```bash
go test ./internal/approvals ./internal/proxy ./internal/policies ./internal/platform/server ./internal/channels
```

Expected: PASS.

**Step 2: Run full verification**

Run:
```bash
go test ./...
```

Expected: PASS.

**Step 3: Inspect diff**

Run:
```bash
git status --short
git diff --stat
```

Expected: only the planned follow-up changes.

---

### Task 7: Commit the slice

**Files:**
- Commit all planned changes in the fresh worktree

**Step 1: Commit**

Run:
```bash
git add docs/plans/2026-03-14-engineering-followups-design.md \
        docs/plans/2026-03-14-engineering-followups-implementation.md \
        internal/approvals \
        internal/proxy/handler.go \
        internal/proxy/handler_test.go \
        internal/platform/httputil \
        internal/policies/handler.go \
        internal/platform/server/server.go \
        internal/channels/outbound_scan.go \
        internal/channels/outbound_scan_test.go
git commit -m "fix: address trust platform engineering follow-ups"
```

Expected: clean commit on `codex/trust-platform-followups`.
