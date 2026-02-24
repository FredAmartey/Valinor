# Phase 8 OpenClaw Runtime Policy Enforcement Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enforce secure OpenClaw runtime defaults in agent configuration, rejecting explicit insecure policy overrides.

**Architecture:** Add a config-policy normalization layer in orchestrator configure flow that mutates safe defaults and fails closed on unsafe values. Persist/push only normalized config.

**Tech Stack:** Go, orchestrator handler/store tests, testify.

---

### Task 1: Add failing policy unit tests

**Files:**
- Create: `internal/orchestrator/runtime_policy_test.go`

Steps:
1. Write tests for:
   - secure defaults injected when missing
   - reject `agents.defaults.sandbox.mode=off`
   - reject `tools.exec.workspaceOnly=false`
   - reject `tools.exec.applyPatch.workspaceOnly=false`
   - reject `gateway.bind=0.0.0.0`
2. Run: `go test ./internal/orchestrator -run TestEnforceOpenClawRuntimePolicy -v`
Expected: FAIL (helper missing).

### Task 2: Implement runtime policy enforcer

**Files:**
- Create: `internal/orchestrator/runtime_policy.go`

Steps:
1. Implement `enforceOpenClawRuntimePolicy(config map[string]any) (map[string]any, error)`.
2. Add deep-copy + nested path helpers.
3. Ensure fail-closed validation + secure default injection.
4. Run: `go test ./internal/orchestrator -run TestEnforceOpenClawRuntimePolicy -v`
Expected: PASS.

### Task 3: Wire enforcer into configure handler

**Files:**
- Modify: `internal/orchestrator/handler.go`
- Modify: `internal/orchestrator/handler_test.go`

Steps:
1. Call enforcer in `HandleConfigure` before marshal/store/push.
2. Add test asserting defaults appear in saved config.
3. Add test asserting insecure config gets `400`.
4. Run: `go test ./internal/orchestrator -run TestHandler_Configure -v`
Expected: PASS.

### Task 4: Update hardening checklist

**Files:**
- Modify: `docs/runbooks/openclaw-security-hardening-checklist.md`

Steps:
1. Mark runtime policy enforcement item complete.
2. Keep remaining P0/P1 unchecked.

### Task 5: Full verification and commit

Steps:
1. Run: `go test ./... -count=1`
Expected: PASS.
2. Commit all files with message:
   - `feat(orchestrator): enforce openclaw runtime security policy defaults`
