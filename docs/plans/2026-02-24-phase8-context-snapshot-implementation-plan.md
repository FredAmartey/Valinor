# Phase 8 Context Snapshot Persistence Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement persistent per-user context snapshots and inject them into agent dispatch so `/api/v1/agents/{id}/context` is no longer no-op.

**Architecture:** Add tenant-scoped RLS snapshot table, DB-backed proxy context store, context write endpoint behavior, and dispatch-time system-message projection for message/stream flows.

**Tech Stack:** Go, Postgres migrations, proxy handler tests, RLS integration tests.

---

### Task 1: Add failing proxy tests for context persistence + projection

**Files:**
- Modify: `internal/proxy/handler_test.go`

Steps:
1. Add failing test: `TestHandleContext_PersistsSnapshot` asserting endpoint stores caller context via context store and returns 200 without agent vsock ack.
2. Add failing tests for dispatch projection:
   - `TestHandleMessage_InjectsPersistedContext`
   - `TestHandleStream_InjectsPersistedContext`
3. Run: `go test ./internal/proxy -run 'TestHandleContext_PersistsSnapshot|TestHandleMessage_InjectsPersistedContext|TestHandleStream_InjectsPersistedContext' -v`
Expected: FAIL.

### Task 2: Add context snapshot storage schema

**Files:**
- Create: `migrations/000014_agent_context_snapshots.down.sql`
- Create: `migrations/000014_agent_context_snapshots.up.sql`

Steps:
1. Create `agent_context_snapshots` table and indexes.
2. Enable RLS + tenant isolation policy.
3. Run migration verification via tests:
   - `go test ./internal/platform/database -run TestRunMigrations -v`
Expected: PASS.

### Task 3: Implement DB-backed user context store and handler wiring

**Files:**
- Create: `internal/proxy/context_store.go`
- Modify: `internal/proxy/handler.go`
- Modify: `cmd/valinor/main.go`

Steps:
1. Add `UserContextStore` interface and Postgres implementation using `database.WithTenantConnection`.
2. Extend `proxy.Handler` with optional context store setter.
3. Update `HandleContext` to validate + persist snapshot.
4. Wire store in main server construction.
5. Run: `go test ./internal/proxy -run TestHandleContext_PersistsSnapshot -v`
Expected: PASS.

### Task 4: Implement dispatch payload injection

**Files:**
- Modify: `internal/proxy/handler.go`
- Modify: `internal/proxy/handler_test.go`

Steps:
1. Add helper to prepend system context to message payload `messages` array while preserving legacy fields.
2. Inject context in both `HandleMessage` and `HandleStream`.
3. Re-run targeted tests:
   - `go test ./internal/proxy -run 'InjectsPersistedContext|TestHandleMessage_Success|TestHandleStream_Success' -v`
Expected: PASS.

### Task 5: Extend RLS test coverage + checklist

**Files:**
- Modify: `internal/platform/database/rls_test.go`
- Modify: `docs/runbooks/openclaw-security-hardening-checklist.md`

Steps:
1. Seed `agent_context_snapshots` rows for two tenants in `seedTwoTenants`.
2. Add table to isolation table list.
3. Mark context no-op checklist item complete.
4. Run: `go test ./internal/platform/database -run TestRLS_TenantIsolation -v`
Expected: PASS.

### Task 6: Full verification and commit

Steps:
1. Run: `go test ./... -count=1`
Expected: PASS.
2. Commit with:
   - `feat(proxy): persist and project per-user agent context snapshots`
