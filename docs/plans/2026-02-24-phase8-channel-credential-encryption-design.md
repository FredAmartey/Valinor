# Phase 8 Channel Credential Encryption-at-Rest Design

## Goal

Encrypt tenant-scoped channel provider secrets at rest using an app-managed key so new and updated credentials are never stored plaintext.

## Scope

### In Scope

- Add symmetric encryption for `channel_provider_credentials` secret fields:
  - `access_token`
  - `signing_secret`
  - `secret_token`
- Config/env wiring for encryption key via `VALINOR_CHANNELS_CREDENTIALS_KEY`.
- Store-layer write encryption and read decryption.
- Forward-only compatibility: plaintext legacy rows remain readable.
- Fail-closed behavior for encrypted values that cannot be decrypted.
- Tests for crypto correctness, store behavior, and config loading.

### Out of Scope

- Re-encryption migration/backfill for legacy plaintext rows.
- KMS/HSM key providers.
- Secret versioning/rotation orchestration APIs.

## Approach

- Use AES-256-GCM with random nonce per value.
- Persist ciphertext in existing columns with a version prefix (`enc:v1:`) and base64 payload.
- On reads:
  - prefixed value -> decrypt
  - non-prefixed value -> treat as legacy plaintext
- On writes:
  - all non-empty secret values must be encrypted
  - if encryption key is missing/invalid, fail the write

## Key Management

- Add `channels.credentials.key` config path.
- Key format: base64-encoded 32-byte raw key.
- Expected env var: `VALINOR_CHANNELS_CREDENTIALS_KEY`.
- Runtime components that resolve credentials (webhook verifier and outbox sender) use a store instance configured with this key.

## Security and Failure Semantics

- Encrypted values with missing key or decrypt failure are treated as errors (fail closed).
- Legacy plaintext values are allowed for backward compatibility in this phase.
- API responses remain sanitized (`has_*` booleans only, no raw secrets).

## Product Outcome

After rollout, all newly written channel provider secrets are encrypted at rest while existing tenants continue operating without forced migration.
