# Phase 8 Tenant Channel Provider Credentials Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add tenant-scoped channel provider credentials and use them for outbox delivery so each tenant sends with isolated provider auth.

**Architecture:** Introduce an RLS-protected `channel_provider_credentials` table plus channel store APIs and RBAC-protected endpoints. Replace global-token outbox sender wiring with per-job tenant credential resolution and fail-closed permanent errors when credentials are missing or invalid.

**Tech Stack:** Go, PostgreSQL, pgx, existing tenant RLS model, channel outbox dispatcher/senders, integration tests with testcontainers.

---

### Task 1: Add Credentials Schema + RLS

**Files:**
- Create: `migrations/000012_channel_provider_credentials.up.sql`
- Create: `migrations/000012_channel_provider_credentials.down.sql`
- Modify: `internal/platform/database/rls_test.go`

**Step 1: Write failing test**

Add `channel_provider_credentials` to `TestRLS_TenantIsolation` table list.

**Step 2: Run test to verify it fails**

Run: `go test ./internal/platform/database -run TestRLS_TenantIsolation -v`
Expected: FAIL because relation does not exist.

**Step 3: Write minimal implementation**

Create migration with table, unique `(tenant_id, provider)`, indexes, and tenant RLS policy.

**Step 4: Run test to verify pass**

Run: `go test ./internal/platform/database -run TestRLS_TenantIsolation -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add migrations/000012_channel_provider_credentials.* internal/platform/database/rls_test.go
git commit -m "feat(channels): add tenant-scoped provider credentials schema"
```

### Task 2: Add Channel Store Credential APIs

**Files:**
- Modify: `internal/channels/channels.go`
- Modify: `internal/channels/store.go`
- Modify: `internal/channels/store_test.go`

**Step 1: Write failing tests**

Add tests for:
- upsert + get + delete lifecycle
- tenant isolation
- provider-specific validation (whatsapp requires phone number)

**Step 2: Run test to verify failures**

Run: `go test ./internal/channels -run TestChannelProviderCredentialStore_ -v`
Expected: FAIL due missing types/methods/errors.

**Step 3: Write minimal implementation**

Add typed model + errors and store methods:
- `UpsertProviderCredential`
- `GetProviderCredential`
- `DeleteProviderCredential`

Include provider normalization and validation.

**Step 4: Run tests to verify pass**

Run: `go test ./internal/channels -run TestChannelProviderCredentialStore_ -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/channels/channels.go internal/channels/store.go internal/channels/store_test.go
git commit -m "feat(channels): add tenant provider credential store APIs"
```

### Task 3: Add Credential Management HTTP Endpoints

**Files:**
- Modify: `internal/channels/handler.go`
- Modify: `internal/channels/handler_test.go`
- Modify: `internal/platform/server/server.go`
- Modify: `internal/platform/server/server_test.go`
- Modify: `cmd/valinor/main.go`

**Step 1: Write failing tests**

Add handler tests for:
- GET returns sanitized credential
- PUT upserts credential
- DELETE removes credential
- invalid provider/body handling

Add route tests for:
- `/api/v1/channels/providers/{provider}/credentials` registered
- legacy tenant path not registered

**Step 2: Run tests to verify failures**

Run: `go test ./internal/channels ./internal/platform/server -run 'Credential|Providers' -v`
Expected: FAIL due missing handler functions/routes.

**Step 3: Write minimal implementation**

Add handler wiring funcs and endpoint handlers, sanitize output, and route registration with RBAC:
- `channels:providers:read`
- `channels:providers:write`

Register default permissions in `cmd/valinor/main.go` role bootstrap.

**Step 4: Run tests to verify pass**

Run: `go test ./internal/channels ./internal/platform/server ./cmd/valinor -run 'Credential|Providers|BuildChannelHandler' -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/channels/handler.go internal/channels/handler_test.go internal/platform/server/server.go internal/platform/server/server_test.go cmd/valinor/main.go
git commit -m "feat(channels): add tenant credential management endpoints"
```

### Task 4: Resolve Outbox Sender Credentials Per Tenant

**Files:**
- Modify: `cmd/valinor/channels_outbox_worker.go`
- Modify: `cmd/valinor/channels_outbox_sender_whatsapp.go`
- Modify: `cmd/valinor/channels_outbox_sender_whatsapp_test.go`
- Modify: `cmd/valinor/main_test.go`

**Step 1: Write failing tests**

Add tests for sender behavior:
- missing tenant credential => permanent error
- resolved tenant credential drives provider send
- disabled provider remains unsupported

Adjust worker build tests to remove global token requirement and require pool for credential resolution.

**Step 2: Run tests to verify failures**

Run: `go test ./cmd/valinor -run 'OutboxSender|BuildChannelOutboxWorker|Credential' -v`
Expected: FAIL due old static sender behavior.

**Step 3: Write minimal implementation**

Add DB-backed credential resolver and route sender through it per outbox job.
Keep fail-closed with `channels.NewOutboxPermanentError` for missing/invalid tenant credentials.

**Step 4: Run tests to verify pass**

Run: `go test ./cmd/valinor -run 'OutboxSender|BuildChannelOutboxWorker|Credential' -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add cmd/valinor/channels_outbox_worker.go cmd/valinor/channels_outbox_sender_whatsapp.go cmd/valinor/channels_outbox_sender_whatsapp_test.go cmd/valinor/main_test.go
git commit -m "feat(channels): resolve outbox sender credentials per tenant"
```

### Task 5: Final Verification and PR Prep

**Files:**
- Modify: `docs/plans/2026-02-24-phase8-tenant-channel-provider-credentials-design.md` (only if implementation diverges)

**Step 1: Run targeted suites**

Run:
- `go test ./internal/channels -v`
- `go test ./cmd/valinor -v`
- `go test ./internal/platform/server -v`
- `go test ./internal/platform/database -run TestRLS_TenantIsolation -v`

**Step 2: Run full compile/test sweep**

Run: `go test ./... -run TestDoesNotExist -count=1`

**Step 3: Commit docs if changed**

```bash
git add docs/plans/2026-02-24-phase8-tenant-channel-provider-credentials-*.md
git commit -m "docs(channels): add tenant provider credential design and plan"
```

**Step 4: Push and open PR**

```bash
git push -u origin codex/phase8-tenant-channel-provider-credentials
```
