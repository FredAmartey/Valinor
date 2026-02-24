# Phase 8 Channel Conversation Continuity Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add tenant-scoped, user-scoped conversation continuity so inbound channel execution includes recent context and produces context-aware responses.

**Architecture:** Reuse existing `channel_messages` persistence by storing request/response turn fields in metadata and reading the last 12 turns for `(tenant_id, user_id)` via RLS-scoped queries. Thread this history through `channels.ExecutionMessage` into proxy dispatch payload as `messages[]`, while keeping backward-compatible single-message fields. Update `valinor-agent` to normalize either payload shape into OpenClaw chat messages.

**Tech Stack:** Go, PostgreSQL/pgx, existing channels store/handler/execution pipeline, valinor-agent OpenClaw bridge, testify.

---

### Task 1: Add Conversation Domain Types and Store Read API

**Files:**
- Modify: `internal/channels/channels.go`
- Modify: `internal/channels/store.go`
- Test: `internal/channels/store_test.go`

**Step 1: Write the failing tests**

Add store tests:
- `TestStore_ListRecentConversationByUser_ReturnsChronologicalLimitedTurns`
- `TestStore_ListRecentConversationByUser_IgnoresRowsWithoutRequestContent`

Cover:
- user scoping by `metadata.user_id`
- limit behavior (`12` turns max)
- chronological order (oldest first in returned slice)

**Step 2: Run test to verify it fails**

Run: `go test ./internal/channels -run 'ListRecentConversationByUser' -v`
Expected: FAIL with undefined type/method errors.

**Step 3: Write minimal implementation**

- Add `ChannelConversationMessage`/`ChannelConversationTurn` domain types in `internal/channels/channels.go`.
- Implement `ListRecentConversationByUser(ctx, q, userID string, limit int) ([]ChannelConversationTurn, error)` in `internal/channels/store.go`:
  - validate `userID`, clamp limit to `12` default when invalid
  - select from `channel_messages` where `metadata->>'user_id' = $1`
  - require non-empty `request_content`
  - order newest-first in SQL, then reverse in Go for chronological output

**Step 4: Run test to verify it passes**

Run: `go test ./internal/channels -run 'ListRecentConversationByUser' -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/channels/channels.go internal/channels/store.go internal/channels/store_test.go
git commit -m "feat(channels): add user-scoped conversation history store query"
```

### Task 2: Persist Request/Response Metadata and Load History in Handler

**Files:**
- Modify: `internal/channels/execution.go`
- Modify: `internal/channels/handler.go`
- Test: `internal/channels/handler_test.go`

**Step 1: Write the failing tests**

Add handler tests:
- `TestHandleWebhook_ExecutionMessageIncludesConversationHistory`
- `TestHandleWebhook_PersistsRequestContentAndUserMetadata`
- `TestHandleWebhook_HistoryLookupFailureFallsBackToEmptyHistory`

Cover:
- execution receives history from store
- status metadata includes `user_id` + `request_content` (and response where present)
- history lookup errors do not fail the webhook

**Step 2: Run test to verify it fails**

Run: `go test ./internal/channels -run 'ExecutionMessageIncludesConversationHistory|PersistsRequestContentAndUserMetadata|HistoryLookupFailureFallsBackToEmptyHistory' -v`
Expected: FAIL due to missing fields/wiring.

**Step 3: Write minimal implementation**

- Extend `ExecutionMessage` in `internal/channels/execution.go` with `ConversationHistory []ChannelConversationTurn`.
- In `Handler.WithLinkStore`, wire a `listConversation` dependency that calls store `ListRecentConversationByUser`.
- In `HandleWebhook`, when a verified actionable message is about to execute:
  - load history by linked `UserID` (best-effort)
  - pass history into `ExecutionMessage`
- Ensure status metadata always includes:
  - `user_id` (linked user UUID)
  - `request_content` (trimmed inbound content)
  - existing `response_content` flow unchanged

**Step 4: Run test to verify it passes**

Run: `go test ./internal/channels -run 'ExecutionMessageIncludesConversationHistory|PersistsRequestContentAndUserMetadata|HistoryLookupFailureFallsBackToEmptyHistory' -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/channels/execution.go internal/channels/handler.go internal/channels/handler_test.go
git commit -m "feat(channels): attach persisted conversation history to execution input"
```

### Task 3: Send Conversation History to Agent Dispatch Payload

**Files:**
- Modify: `cmd/valinor/channels_execution.go`
- Test: `cmd/valinor/channels_execution_test.go`

**Step 1: Write the failing tests**

Add/extend tests:
- `TestDispatchChannelMessageToAgent_IncludesConversationMessages`
- `TestDispatchChannelMessageToAgent_PreservesLegacyRoleContentFields`

Cover payload contract:
- `messages[]` includes prior turns + current user message
- `role`/`content` still present for compatibility

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/valinor -run 'DispatchChannelMessageToAgent_IncludesConversationMessages|DispatchChannelMessageToAgent_PreservesLegacyRoleContentFields' -v`
Expected: FAIL due to payload mismatch.

**Step 3: Write minimal implementation**

- Add helper in `cmd/valinor/channels_execution.go` to build outbound message list from `ConversationHistory` + current content.
- Update `dispatchChannelMessageToAgent` signature to accept history and marshal:
  - `messages`
  - `role`
  - `content`
- Update executor call site accordingly.

**Step 4: Run test to verify it passes**

Run: `go test ./cmd/valinor -run 'DispatchChannelMessageToAgent_IncludesConversationMessages|DispatchChannelMessageToAgent_PreservesLegacyRoleContentFields|ChannelExecutor' -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add cmd/valinor/channels_execution.go cmd/valinor/channels_execution_test.go
git commit -m "feat(channels): dispatch channel requests with conversation history context"
```

### Task 4: Update valinor-agent OpenClaw Bridge for `messages[]` Payloads

**Files:**
- Modify: `cmd/valinor-agent/openclaw.go`
- Test: `cmd/valinor-agent/openclaw_test.go`

**Step 1: Write the failing tests**

Add tests:
- `TestOpenClawProxy_MessageArrayForwarded`
- `TestOpenClawProxy_FallbacksToLegacyRoleContent`

Use mock OpenClaw server to assert incoming `messages` request body.

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/valinor-agent -run 'MessageArrayForwarded|FallbacksToLegacyRoleContent' -v`
Expected: FAIL due to parser/request builder mismatch.

**Step 3: Write minimal implementation**

- In `openclaw.go`, decode payload into:
  - optional `messages []{role,content}`
  - optional `role`/`content`
- Normalize into `messages` array:
  - use provided non-empty array when present
  - else build single entry from legacy fields
  - reject empty result as invalid payload
- Send normalized array to OpenClaw request body.

**Step 4: Run test to verify it passes**

Run: `go test ./cmd/valinor-agent -run 'OpenClawProxy' -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add cmd/valinor-agent/openclaw.go cmd/valinor-agent/openclaw_test.go
git commit -m "feat(agent): support channel conversation message arrays for openclaw dispatch"
```

### Task 5: Full Verification and PR Prep

**Files:**
- Modify: `docs/plans/2026-02-23-phase8-channels-execution-path.md` (only if behavior notes changed)

**Step 1: Run focused suites**

Run:
- `go test ./internal/channels -v`
- `go test ./cmd/valinor -v`
- `go test ./cmd/valinor-agent -v`

Expected: PASS.

**Step 2: Run full verification**

Run: `go test ./... -count=1`
Expected: PASS.

**Step 3: Commit docs (if changed)**

```bash
git add docs/plans/2026-02-23-phase8-channels-execution-path.md
git commit -m "docs(channels): record conversation continuity execution behavior"
```

**Step 4: Push and open PR**

```bash
git push -u origin codex/phase8-channel-conversation-continuity
```

Create PR with summary + verification commands.

**Step 5: Request review before merge**

Run the required review skill workflow:
- [$requesting-code-review](/Users/fred/.codex/superpowers/skills/requesting-code-review/SKILL.md)

Address or challenge findings, rerun verification, and wait for your explicit merge approval.

