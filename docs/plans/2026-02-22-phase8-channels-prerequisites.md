# Phase 8: Channels Prerequisites (Gate Document)

**Date:** 2026-02-22  
**Status:** Required before Phase 8 implementation

## Goal

Define non-negotiable identity, idempotency, and audit requirements for messaging channels (WhatsApp/Telegram/Slack) before writing channel handlers.

## Why This Gate Exists

Without strict channel gates, duplicate webhook deliveries, replayed messages, or ambiguous identity linking can cause unauthorized actions, double execution, and inconsistent state.

## Mandatory Requirements

### 1. Identity Linking

- A channel identity is modeled as `(platform, platform_user_id)`.
- Mapping must be one-to-one with a Valinor user at any point in time.
- Link states: `pending_verification`, `verified`, `revoked`.
- Only `verified` links may trigger agent actions.
- Linking/unlinking must emit audit events (`channel.linked`, `channel.unlinked`, `channel.link_verification_failed`).

### 2. Webhook Authenticity

- Every inbound webhook must pass provider signature verification before parsing business payload.
- Invalid signatures are rejected with 401/403 and audited (`channel.webhook.rejected_signature`).

### 3. Idempotency + Replay Defense

- Every inbound message must produce a deterministic idempotency key:
  - Preferred: provider message ID.
  - Fallback: stable hash of platform + sender + timestamp + payload fingerprint.
- Persist idempotency key with first-seen timestamp.
- Duplicates within configured replay window are acknowledged without re-execution.
- Expired/replayed keys are rejected and audited (`channel.message.replay_blocked`).

### 4. Correlation + Observability

- Generate or propagate a correlation ID per message.
- Correlation ID must flow through channel handler -> auth resolution -> RBAC -> sentinel -> proxy -> audit.
- All channel-originated audit events include `source=<platform>` and `correlation_id`.

## Suggested Data Additions

- `channel_messages` (or equivalent) with unique constraint on `(platform, idempotency_key)`.
- `channel_links` state extensions (`verified_at`, `revoked_at`, `verification_method`, `verification_metadata`).
- Optional `channel_replay_window_seconds` config.

## Acceptance Criteria (Blocking)

Phase 8 cannot be marked complete unless all pass:

1. Signature verification tests: valid accepted, invalid rejected.
2. Idempotency tests: duplicate message does not execute action twice.
3. Replay tests: stale/reused idempotency key blocked.
4. Identity tests: unverified link cannot execute actions.
5. End-to-end audit tests: each accepted/rejected path writes auditable event with correlation ID.
