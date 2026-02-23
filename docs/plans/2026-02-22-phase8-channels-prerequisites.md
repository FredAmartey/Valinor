# Phase 8: Channels Prerequisites (Gate Document)

**Date:** 2026-02-23  
**Status:** Required before Phase 8 implementation (revised after Phase 7 review)

## Goal

Define non-negotiable identity, entitlement, authenticity, idempotency, and audit requirements for messaging channels (WhatsApp/Telegram/Slack) before writing channel handlers.

## Why This Gate Exists

Without strict channel gates, duplicate webhook deliveries, replayed messages, ambiguous identity links, or mis-scoped entitlements can cause unauthorized actions, double execution, and cross-tenant risk.

## Classification and Ownership

| Area | Classification | Decision Owner | Default in this gate |
| --- | --- | --- | --- |
| Link/action entitlements | `product-policy` | Product + Security | Enforced role/permission matrix below |
| Identity state model and uniqueness scope | `product-policy` | Product + Data | Tenant-scoped identity uniqueness |
| Signature verification contract | `implementation` | Security Eng | Provider adapter contract + fail-closed |
| Idempotency semantics and replay window | `product-policy` | Product + Platform | 24h replay window, duplicate acknowledged without re-exec |
| Schema migration/backfill strategy | `implementation` | Platform Eng | Expand/backfill/contract migration sequence |
| Data retention and payload storage | `product-policy` | Product + Security | Minimal storage + explicit retention defaults |
| Rollout/kill switch controls | `implementation` | Platform Eng | Per-provider feature flags + global ingress kill switch |

## Mandatory Requirements

### 1) Identity Linking and Entitlement Matrix

- Channel identity is modeled as `(tenant_id, platform, platform_user_id)`.
- Mapping is one-to-one with a Valinor user per tenant at any point in time.
- Link states are `pending_verification`, `verified`, `revoked`.
- Only `verified` links can execute agent actions.
- Required permissions:
  - `channels:links:read`
  - `channels:links:write`
  - `channels:messages:write`
- Default role matrix (can be changed only via explicit product-policy decision):
  - `org_admin`: links read/write + messages write
  - `dept_head`: links read/write + messages write
  - `standard_user`: messages write for self only (no link management for others)
- Required audit events: `channel.linked`, `channel.unlinked`, `channel.link_verification_failed`, `channel.action_denied_unverified`.

### 2) Webhook Authenticity (Fail Closed)

- Inbound webhook must pass provider authenticity verification before business payload parsing or idempotency checks.
- Invalid authenticity checks return `401` or `403` and emit `channel.webhook.rejected_signature`.
- Provider adapters must implement:
  - Canonical string construction.
  - Allowed timestamp skew window.
  - Secret lookup and rotation handling.
- Minimum provider requirements:
  - Slack: verify `X-Slack-Signature` and `X-Slack-Request-Timestamp`.
  - WhatsApp Cloud API: verify `X-Hub-Signature-256`.
  - Telegram: verify configured secret token header.
- Fail mode is always deny (`fail closed`) on missing verifier config in production.

### 3) Idempotency and Replay Defense

- Every inbound message must derive deterministic idempotency key:
  - Preferred: provider message ID.
  - Fallback: stable hash of provider + sender + timestamp bucket + payload fingerprint.
- Persist each key in `channel_messages` with unique `(platform, idempotency_key)` within tenant scope.
- Duplicate handling semantics:
  - Return success acknowledgement (`200`) with no re-execution.
  - Reuse existing correlation ID for duplicate audit trace.
- Replay window default: `86400` seconds (24h).
- Replay/expired keys are rejected and audited as `channel.message.replay_blocked`.
- Cleanup policy:
  - Soft retention for idempotency rows: 30 days.
  - Scheduled cleanup job at least hourly.

### 4) Correlation and Observability

- Generate or propagate `correlation_id` per inbound message.
- Correlation ID must flow through channel handler -> auth resolution -> RBAC -> sentinel -> proxy -> audit.
- Channel audit events must include:
  - `source=<platform>`
  - `correlation_id`
  - `platform_message_id` (if present)
  - `idempotency_key`
  - `decision` (`accepted`, `duplicate`, `rejected_signature`, `replay_blocked`, `denied`)

### 5) Schema and Migration Strategy

- Existing `channel_links` has legacy `verified BOOLEAN`; migration must be zero-downtime:
  1. Expand: add `tenant_id`, `state`, `verified_at`, `revoked_at`, `verification_method`, `verification_metadata`.
  2. Backfill: derive `tenant_id` via `users` join and map `verified=true -> state=verified`, else `pending_verification`.
  3. Application dual-read/dual-write for one release.
  4. Contract: drop legacy `verified` only after rollout validation.
- Add `channel_messages` table with:
  - `tenant_id`, `platform`, `platform_message_id`, `idempotency_key`, `payload_fingerprint`, `correlation_id`, `status`, timestamps.
  - Unique constraint for idempotency lookup.
  - Index for retention cleanup (`expires_at` or equivalent timestamp).
- RLS must apply to new channel tables using `tenant_id` policies.

### 6) Data Handling and Retention Policy

- Never persist raw signature headers or webhook secrets.
- Persist minimal webhook data needed for idempotency, auditing, and debugging.
- Message body storage policy must be explicit:
  - Recommended default: store payload fingerprint and provider IDs, not full message body.
  - If full payload storage is enabled later, it must be encrypted and retention-bounded.
- Document and approve retention windows before enabling any provider in production.

### 7) Rollout and Kill Switch Controls

- Feature flags:
  - Global: `channels.ingress.enabled`
  - Per-provider: `channels.providers.<provider>.enabled`
- Global ingress kill switch must stop action execution immediately while still auditing rejected attempts.
- Rollout must be staged: dev -> staging -> single pilot tenant -> broader tenants.
- Rollback path must include migration rollback constraints and operational steps.

### 8) Cross-Tenant and Concurrency Test Gates

Blocking tests must include:

1. Signature verification: valid accepted, invalid rejected.
2. Idempotency: duplicate delivery executes action exactly once.
3. Replay: stale/reused keys blocked.
4. Identity state: unverified/revoked links cannot execute actions.
5. Cross-tenant isolation: same `platform_user_id` in different tenants cannot cross-read or cross-act.
6. Concurrency: two simultaneous deliveries of same message cannot double-execute.
7. Audit completeness: accepted and rejected paths write required event metadata with correlation ID.

## Acceptance Criteria (Blocking)

Phase 8 cannot be marked complete unless:

1. All test gates in section 8 pass in CI.
2. Policy decisions in section 1/3/6 are explicitly approved and recorded.
3. Migration rollout plan (expand/backfill/contract) is documented and rehearsed.
4. Global and per-provider kill switches are verified in non-prod.
