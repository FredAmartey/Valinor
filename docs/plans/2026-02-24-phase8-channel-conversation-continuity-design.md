# Phase 8 Channel Conversation Continuity Design

## Goal

Preserve conversation continuity across channel messages by sending recent tenant-scoped user/assistant history with each new inbound execution, so users can continue work seamlessly across desktop and messaging channels.

## Product Outcome

When a linked user sends a new WhatsApp/Slack/Telegram message, the agent receives context from the same user's recent turns in that tenant. Responses become context-aware instead of single-turn.

## Scope

### In Scope

- Persist execution-turn context in existing `channel_messages.metadata`:
  - `user_id`
  - `request_content`
  - `response_content`
  - `decision`
- Add store API to fetch recent conversation turns for `(tenant_id, user_id)` from `channel_messages`.
- Use a fixed history window of last `12` turns.
- Pass history through channel execution path into proxy dispatch payload.
- Update `valinor-agent` OpenClaw bridge to consume either:
  - `messages[]` (preferred), or
  - existing `role`/`content` payload (fallback compatibility).
- Tests for store query behavior, execution wiring, dispatch payload, and agent request translation.

### Out of Scope

- New dedicated conversation table.
- Token-budget aware truncation by provider model limits.
- Cross-user shared history.
- Tool execution changes.

## Approaches Considered

1. **Reuse `channel_messages` metadata (recommended)**
   - Fastest delivery and no migration churn.
   - Reuses existing tenant-isolated RLS model.
2. New `channel_conversation_turns` table
   - Cleaner long-term domain model.
   - Higher implementation and migration overhead now.
3. In-memory continuity cache
   - Lowest coding effort.
   - Not durable and not safe for restart/scale.

## Recommended Architecture

### Persistence

Keep continuity state in `channel_messages.metadata` as the execution path already updates this row per inbound idempotency key. This avoids extra write paths and keeps data naturally tenant-scoped via RLS.

### Read Path

Before executing a new accepted message, resolve recent conversation turns by:

- `tenant_id = current tenant` (RLS)
- `metadata.user_id = linked user`
- known terminal statuses (`executed`, `denied_*`, `dispatch_failed`)
- newest first, limit `12`, then reverse to chronological order

Only include turns with non-empty request text; include response text when available.

### Execution and Dispatch

- Extend `channels.ExecutionMessage` with `ConversationHistory`.
- Channel handler fetches history and attaches it to execution input.
- Dispatch payload to agent includes:
  - `messages`: ordered array of prior `user` and `assistant` messages plus current `user` message
  - legacy `role`/`content` fields for compatibility

### Agent Bridge

`valinor-agent` accepts payloads with:

- `messages: [{role, content}]` (primary)
- fallback to a single message built from `role`/`content` if `messages` is absent

OpenClaw request always uses the normalized `messages` array.

## Error Handling

- History load is best-effort. If history read fails, continue execution with empty history.
- Invalid message payloads to agent remain hard-fail (`TypeError` frame), as today.

## Security and Isolation

- History query uses tenant-scoped DB connection with RLS.
- Filter by linked `user_id` to avoid cross-user context bleed inside a tenant.
- No new cross-tenant surface area introduced.

## Verification Plan

- `go test ./internal/channels -run 'Conversation|History|HandleWebhook' -v`
- `go test ./cmd/valinor -run 'ChannelExecutor|DispatchChannelMessageToAgent' -v`
- `go test ./cmd/valinor-agent -run 'OpenClawProxy' -v`
- `go test ./... -count=1`

