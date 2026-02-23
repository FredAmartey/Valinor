# Channels Webhook Verification Runbook

**Scope:** Slack, WhatsApp Cloud API, Telegram inbound webhook authenticity and replay controls.  
**Audience:** Platform/SRE/Security engineers operating channel ingress.

## 1) Preconditions

- `channels.ingress.enabled=true` only in approved environments.
- Provider secret is configured and non-empty for each enabled provider:
  - `channels.providers.slack.signingsecret`
  - `channels.providers.whatsapp.signingsecret`
  - `channels.providers.telegram.secrettoken`
- Replay window configured (`channels.ingress.replaywindowseconds`, default `86400`).

## 2) Signature Validation Contracts

### Slack

- Required headers:
  - `X-Slack-Signature`
  - `X-Slack-Request-Timestamp`
- Validation:
  - HMAC SHA-256 of `v0:<timestamp>:<body>`
  - Reject if timestamp skew exceeds verifier window.

### WhatsApp Cloud API

- Required header:
  - `X-Hub-Signature-256`
- Validation:
  - HMAC SHA-256 of raw request body.

### Telegram

- Required header:
  - `X-Telegram-Bot-Api-Secret-Token`
- Validation:
  - Constant-time equality check with configured token.

## 3) Verification Procedure (Non-Prod)

1. Send a valid signed webhook payload for each enabled provider.
2. Confirm HTTP `200` for accepted or duplicate flow.
3. Send same payload again:
   - Expect duplicate acknowledgement (`decision=duplicate`), no re-execution.
4. Send invalid signature:
   - Expect HTTP `401` with `decision=rejected_signature`.
5. Send stale payload (older than replay window):
   - Expect replay block (`decision=replay_blocked`).

## 4) Required Audit Metadata

For every accepted/rejected ingress path, verify event metadata includes:

- `correlation_id`
- `decision`
- `idempotency_key`
- `platform_message_id` (when present)

Event actions expected:

- `channel.message.accepted`
- `channel.message.duplicate`
- `channel.message.replay_blocked`
- `channel.webhook.rejected_signature`
- `channel.action_denied_unverified`

## 5) Secret Rotation

1. Update provider secret/token in secret manager.
2. Roll configuration update to app instances.
3. Validate valid/invalid signature behavior in staging.
4. Roll production.
5. Confirm no sustained spike in `rejected_signature` after cutover.

## 6) Incident Triage

If signature failures spike:

1. Verify configured secret/token matches provider console.
2. Confirm reverse proxy/body middleware is not mutating payload bytes.
3. Check server clock skew if Slack timestamp checks are failing.
4. Temporarily disable affected provider with per-provider flag if needed.
