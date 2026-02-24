# Phase 8 OpenClaw Runtime Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enforce loopback-only OpenClaw endpoint defaults in `valinor-agent` and document the production hardening checklist.

**Architecture:** Add a small URL validation layer in `cmd/valinor-agent` and enforce it both at startup and message-forwarding time. Keep break-glass support explicit via a CLI flag. Track remaining hardening items in a dedicated checklist doc.

**Tech Stack:** Go, stdlib `net/url` + `net`, existing valinor-agent/proxy tests.

---

### Task 1: Add failing tests for URL security validation

**Files:**
- Create: `cmd/valinor-agent/security_test.go`

**Step 1: Write failing unit tests**
- Add table-driven tests for URL validation behavior:
  - pass: `http://localhost:8081`, `http://127.0.0.1:8081`, `http://[::1]:8081`
  - fail: `http://example.com:8081`, `https://openclaw.internal`, malformed URL
  - pass when override enabled: remote host accepted.

**Step 2: Run to verify RED**
- Run: `go test ./cmd/valinor-agent -run TestValidateOpenClawURL -v`
- Expected: FAIL (validator function not implemented).

### Task 2: Implement minimal URL validator

**Files:**
- Create: `cmd/valinor-agent/security.go`

**Step 1: Implement validator**
- Add `validateOpenClawURL(raw string, allowRemote bool) error`.
- Rules:
  - require parseable absolute URL with host
  - allow only loopback hosts (`localhost`, `127.0.0.0/8`, `::1`) unless `allowRemote=true`

**Step 2: Run targeted tests to verify GREEN**
- Run: `go test ./cmd/valinor-agent -run TestValidateOpenClawURL -v`
- Expected: PASS.

### Task 3: Enforce guard in startup and runtime forwarding

**Files:**
- Modify: `cmd/valinor-agent/main.go`
- Modify: `cmd/valinor-agent/openclaw.go`
- Modify: `cmd/valinor-agent/openclaw_test.go`

**Step 1: Write failing behavior test first**
- Add test in `openclaw_test.go`:
  - configure agent with remote URL `http://example.com:8081`
  - send message frame
  - assert immediate `error` frame with `code=invalid_config`

**Step 2: Verify RED**
- Run: `go test ./cmd/valinor-agent -run TestOpenClawProxy_RejectsRemoteEndpoint -v`
- Expected: FAIL before implementation.

**Step 3: Implement startup guard**
- Add CLI flag: `--allow-remote-openclaw` (default `false`).
- Call `validateOpenClawURL` in `run()` and fail startup if invalid.

**Step 4: Implement runtime guard**
- In `forwardToOpenClaw`, validate configured URL with `allowRemote=false` and return `invalid_config` error frame if invalid.

**Step 5: Verify GREEN**
- Run: `go test ./cmd/valinor-agent -run 'OpenClaw|ValidateOpenClawURL' -v`
- Expected: PASS.

### Task 4: Add hardening checklist doc

**Files:**
- Create: `docs/runbooks/openclaw-security-hardening-checklist.md`

**Step 1: Document P0/P1 production hardening items**
- Include status checkboxes and verification commands.
- Mark this PR's P0 item as completed.

**Step 2: Verify docs included in tree**
- Run: `git status --short`
- Expected: new doc + code/test files staged candidates.

### Task 5: Full verification and commit

**Files:**
- Modify/add from Tasks 1-4.

**Step 1: Run full verification**
- Run: `go test ./... -count=1`
- Expected: PASS.

**Step 2: Commit**
- `git add cmd/valinor-agent/main.go cmd/valinor-agent/openclaw.go cmd/valinor-agent/openclaw_test.go cmd/valinor-agent/security.go cmd/valinor-agent/security_test.go docs/plans/2026-02-24-phase8-openclaw-runtime-hardening-*.md docs/runbooks/openclaw-security-hardening-checklist.md`
- `git commit -m "feat(agent): enforce local openclaw endpoint defaults"`
