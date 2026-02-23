# Phase 8 Channels Prerequisites Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement Phase 8 channel security prerequisites (identity state model, signature verification, idempotency/replay defense, correlation/audit, and rollout controls) before any provider-specific feature rollout.

**Architecture:** Add a dedicated `internal/channels` module with clear boundaries: verification adapters, idempotency store, link state store, and HTTP handlers. Keep tenant isolation enforced with RLS on new channel tables and tenant context in handlers. Roll out with feature flags and fail-closed defaults.

**Tech Stack:** Go, `pgx/v5`, PostgreSQL migrations (`golang-migrate`), existing auth/RBAC/audit middleware, existing request ID middleware.

---

### Task 1: Schema Expand Migration (Links + Messages)

**Files:**
- Create: `migrations/000010_channels_prereq_expand.up.sql`
- Create: `migrations/000010_channels_prereq_expand.down.sql`
- Test/Verify: `internal/platform/database/migrate_test.go`

**Step 1: Write migration SQL (expand only)**

- Add `tenant_id`, `state`, `verified_at`, `revoked_at`, `verification_method`, `verification_metadata` to `channel_links`.
- Backfill `tenant_id` from `users.tenant_id`.
- Backfill `state` from legacy `verified` boolean.
- Add `channel_messages` table with idempotency fields and retention timestamp.
- Add unique index for idempotency (tenant-aware) and cleanup index.
- Add RLS policy for `channel_messages`.

**Step 2: Run migration tests**

Run: `go test ./internal/platform/database -run TestRunMigrations -v`
Expected: PASS

**Step 3: Commit**

```bash
git add migrations/000010_channels_prereq_expand.*
git commit -m "feat: add channels prerequisite expand migration"
```

---

### Task 2: Channels Domain Types and Store Contracts

**Files:**
- Create: `internal/channels/channels.go`
- Create: `internal/channels/store.go`
- Create: `internal/channels/store_test.go`

**Step 1: Write failing tests for state/idempotency behavior**

- `TestChannelLinkStore_GetByIdentity_TenantScoped`
- `TestChannelLinkStore_VerifiedGate`
- `TestMessageStore_InsertIdempotency_FirstSeen`
- `TestMessageStore_InsertIdempotency_Duplicate`

**Step 2: Run tests to confirm failure**

Run: `go test ./internal/channels -run 'Test(ChannelLinkStore|MessageStore)' -v`
Expected: FAIL (types/store not implemented)

**Step 3: Implement minimal domain/store code**

- Define link states: `pending_verification`, `verified`, `revoked`.
- Define message statuses: `accepted`, `duplicate`, `rejected_signature`, `replay_blocked`.
- Implement store methods for link lookup/update and idempotency insert/check.

**Step 4: Re-run tests**

Run: `go test ./internal/channels -run 'Test(ChannelLinkStore|MessageStore)' -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/channels/channels.go internal/channels/store.go internal/channels/store_test.go
git commit -m "feat: add channels domain types and stores"
```

---

### Task 3: Signature Verifier Interface + Provider Adapters

**Files:**
- Create: `internal/channels/verifier.go`
- Create: `internal/channels/verifier_slack.go`
- Create: `internal/channels/verifier_whatsapp.go`
- Create: `internal/channels/verifier_telegram.go`
- Create: `internal/channels/verifier_test.go`

**Step 1: Write failing verifier tests**

- `TestSlackVerifier_ValidSignature`
- `TestSlackVerifier_InvalidSignature`
- `TestSlackVerifier_ExpiredTimestamp`
- Similar valid/invalid tests for WhatsApp and Telegram secret token.

**Step 2: Run tests to confirm failure**

Run: `go test ./internal/channels -run 'Test(Slack|WhatsApp|Telegram)Verifier' -v`
Expected: FAIL

**Step 3: Implement verifier contract and adapters**

- Interface: `Verify(headers http.Header, body []byte, now time.Time) error`
- Return typed errors for invalid signature vs timestamp skew.
- Keep canonical signing logic isolated per adapter.

**Step 4: Re-run tests**

Run: `go test ./internal/channels -run 'Test(Slack|WhatsApp|Telegram)Verifier' -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/channels/verifier*.go
git commit -m "feat: add channel webhook verifiers"
```

---

### Task 4: Inbound Message Guard (Authenticity -> Idempotency -> Identity State)

**Files:**
- Create: `internal/channels/ingress.go`
- Create: `internal/channels/ingress_test.go`

**Step 1: Write failing pipeline tests**

- `TestIngress_RejectsInvalidSignature`
- `TestIngress_DuplicateMessage_NoReexecution`
- `TestIngress_ReplayBlocked`
- `TestIngress_UnverifiedLinkDenied`
- `TestIngress_VerifiedLinkAccepted`

**Step 2: Run tests to confirm failure**

Run: `go test ./internal/channels -run TestIngress -v`
Expected: FAIL

**Step 3: Implement ingress guard flow**

Order must be:
1. Verify signature.
2. Resolve tenant + identity link.
3. Check link state.
4. Apply idempotency/replay guard.
5. Emit correlation/audit metadata.

**Step 4: Re-run tests**

Run: `go test ./internal/channels -run TestIngress -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/channels/ingress.go internal/channels/ingress_test.go
git commit -m "feat: add channel ingress guard pipeline"
```

---

### Task 5: HTTP Handlers and Server Wiring

**Files:**
- Create: `internal/channels/handler.go`
- Create: `internal/channels/handler_test.go`
- Modify: `internal/platform/server/server.go`
- Modify: `internal/platform/server/server_test.go`

**Step 1: Write failing handler/server tests**

- Webhook route requires provider verification.
- Link management endpoints enforce RBAC permissions.
- Correlation ID is always present in response/audit metadata.

**Step 2: Run tests to confirm failure**

Run: `go test ./internal/platform/server -run TestServer -v`
Expected: FAIL for missing channel route wiring

**Step 3: Implement handlers and route registration**

- Add provider webhook endpoint(s) under `/api/v1/channels/{provider}/webhook`.
- Add link management endpoints under `/api/v1/channels/links`.
- Protect routes with `channels:*` permissions.

**Step 4: Re-run tests**

Run: `go test ./internal/channels ./internal/platform/server -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/channels/handler*.go internal/platform/server/server.go internal/platform/server/server_test.go
git commit -m "feat: wire channel handlers and routes"
```

---

### Task 6: RBAC Defaults and Config Flags

**Files:**
- Modify: `cmd/valinor/main.go`
- Modify: `cmd/valinor/main_test.go`
- Modify: `internal/platform/config/config.go`
- Modify: `config.yaml`

**Step 1: Write failing tests/config assertions**

- Default roles include intended `channels:*` permissions.
- Config defaults set `channels.ingress.enabled=false` and providers disabled.

**Step 2: Run tests to confirm failure**

Run: `go test ./cmd/valinor -run TestMain -v`
Expected: FAIL

**Step 3: Implement RBAC and config changes**

- Add channels permissions to selected roles.
- Add global ingress kill switch + per-provider enable flags.
- Ensure missing verifier secrets in prod fail closed.

**Step 4: Re-run tests**

Run: `go test ./cmd/valinor ./internal/platform/config -v`
Expected: PASS

**Step 5: Commit**

```bash
git add cmd/valinor/main.go cmd/valinor/main_test.go internal/platform/config/config.go config.yaml
git commit -m "feat: add channel RBAC defaults and feature flags"
```

---

### Task 7: Audit Integration and Correlation Propagation

**Files:**
- Modify: `internal/audit/audit.go`
- Modify: `internal/channels/ingress.go`
- Create: `internal/channels/audit_test.go`

**Step 1: Write failing audit tests**

- `TestChannelAudit_IncludesCorrelationAndDecision`
- `TestChannelAudit_RejectedSignature`
- `TestChannelAudit_DuplicateAndReplay`

**Step 2: Run tests to confirm failure**

Run: `go test ./internal/channels -run TestChannelAudit -v`
Expected: FAIL

**Step 3: Implement audit metadata contract**

- Include platform source, idempotency key, decision, and correlation ID in all channel audit events.

**Step 4: Re-run tests**

Run: `go test ./internal/channels -run TestChannelAudit -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/audit/audit.go internal/channels/ingress.go internal/channels/audit_test.go
git commit -m "feat: add channel audit metadata contract"
```

---

### Task 8: Integration, Cross-Tenant, and Concurrency Tests

**Files:**
- Create: `internal/channels/integration_test.go`
- Modify: `internal/platform/database/rls_test.go`
- Modify: `.github/workflows/ci.yml` (if new test job split is needed)

**Step 1: Add failing integration tests**

- Duplicate webhook concurrent delivery executes once.
- Same platform user ID in different tenants is isolated.
- Unverified/revoked link blocked end-to-end.

**Step 2: Run tests to confirm failure**

Run: `go test ./internal/channels ./internal/platform/database -v`
Expected: FAIL initially

**Step 3: Implement missing pieces discovered by tests**

- Tighten SQL constraints and handler checks as needed.

**Step 4: Run full verification**

Run:
- `go test ./... -v`
- `golangci-lint run ./...`
- `gosec ./...`

Expected: PASS

**Step 5: Commit**

```bash
git add internal/channels/integration_test.go internal/platform/database/rls_test.go .github/workflows/ci.yml
git commit -m "test: add channel prerequisite integration and isolation coverage"
```

---

### Task 9: Runbooks and Final Gate Checklist

**Files:**
- Modify: `docs/plans/2026-02-22-phase8-channels-prerequisites.md`
- Create: `docs/runbooks/channels-webhook-verification.md`
- Create: `docs/runbooks/channels-rollout-killswitch.md`

**Step 1: Document operational runbooks**

- Secret rotation procedure.
- Replay-window tuning guidance.
- Kill-switch activation + rollback checklist.

**Step 2: Verify gate checklist completion**

- Mark each gate item with evidence links (tests/PRs/runbook).

**Step 3: Commit**

```bash
git add docs/plans/2026-02-22-phase8-channels-prerequisites.md docs/runbooks/channels-webhook-verification.md docs/runbooks/channels-rollout-killswitch.md
git commit -m "docs: add channels security runbooks and gate evidence"
```

