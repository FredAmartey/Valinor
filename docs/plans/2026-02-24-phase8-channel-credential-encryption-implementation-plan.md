# Phase 8 Channel Credential Encryption-at-Rest Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Encrypt tenant-scoped channel provider secrets at rest while preserving forward-only compatibility for existing plaintext rows.

**Architecture:** Add AES-256-GCM encryption/decryption utilities in `internal/channels`, configure a credentials key via `VALINOR_CHANNELS_CREDENTIALS_KEY`, and wire channel store read/write paths to encrypt on write and decrypt on read with plaintext fallback for legacy values.

**Tech Stack:** Go, standard library crypto (`aes`, `cipher` GCM), PostgreSQL, existing channel store + config loaders.

---

### Task 1: Add Channels Credential Key Config

**Files:**
- Modify: `internal/platform/config/config.go`
- Modify: `internal/platform/config/config_test.go`

**Step 1: Write failing tests**

Add config tests asserting:
- default `cfg.Channels.Credentials.Key == ""`
- env override from `VALINOR_CHANNELS_CREDENTIALS_KEY`

**Step 2: Run tests to verify fail**

Run: `go test ./internal/platform/config -run 'TestLoad_Channels(Defaults|EnvOverrides)' -v`
Expected: FAIL due missing `Channels.Credentials` config structure.

**Step 3: Minimal implementation**

Add:
- `ChannelsCredentialsConfig` with `Key string`
- `ChannelsConfig.Credentials ChannelsCredentialsConfig`
- default map entry `channels.credentials.key` set to empty string

**Step 4: Re-run tests**

Run: `go test ./internal/platform/config -run 'TestLoad_Channels(Defaults|EnvOverrides)' -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/platform/config/config.go internal/platform/config/config_test.go
git commit -m "feat(channels): add credential encryption key config"
```

### Task 2: Add Credential Crypto Utility

**Files:**
- Create: `internal/channels/credential_crypto.go`
- Create: `internal/channels/credential_crypto_test.go`

**Step 1: Write failing tests**

Add tests for:
- base64 key decode + size validation
- encrypt/decrypt roundtrip
- decrypt with wrong key fails
- plaintext legacy passthrough handling helper

**Step 2: Run tests to verify fail**

Run: `go test ./internal/channels -run 'TestCredentialCrypto_' -v`
Expected: FAIL due missing crypto implementation.

**Step 3: Minimal implementation**

Implement:
- key loader from base64 (32-byte requirement)
- AES-256-GCM encrypt/decrypt
- version prefix tagging (`enc:v1:`)
- helper to detect encrypted value by prefix

**Step 4: Re-run tests**

Run: `go test ./internal/channels -run 'TestCredentialCrypto_' -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/channels/credential_crypto.go internal/channels/credential_crypto_test.go
git commit -m "feat(channels): add provider credential crypto utility"
```

### Task 3: Encrypt Store Writes, Decrypt Reads (Forward-Only)

**Files:**
- Modify: `internal/channels/channels.go`
- Modify: `internal/channels/store.go`
- Modify: `internal/channels/store_test.go`

**Step 1: Write failing tests**

Add store tests for:
- upsert stores encrypted ciphertext and get returns decrypted values
- legacy plaintext rows still readable
- encrypted row without configured key fails closed

**Step 2: Run tests to verify fail**

Run: `go test ./internal/channels -run 'TestChannelProviderCredentialStore_(EncryptsSecretsAtRest|LegacyPlaintextCompat|EncryptedValueRequiresKey)' -v`
Expected: FAIL due missing store encryption/decryption logic.

**Step 3: Minimal implementation**

Add to store:
- optional credential crypto dependency (via `NewStore` option)
- write-time encryption of non-empty secret fields
- read-time decryption for prefixed values
- plaintext passthrough for non-prefixed values
- typed errors for missing key/decrypt failures

**Step 4: Re-run tests**

Run: `go test ./internal/channels -run 'TestChannelProviderCredentialStore_(EncryptsSecretsAtRest|LegacyPlaintextCompat|EncryptedValueRequiresKey)' -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/channels/channels.go internal/channels/store.go internal/channels/store_test.go
git commit -m "feat(channels): encrypt provider credentials at rest in store"
```

### Task 4: Wire Runtime Components to Keyed Store

**Files:**
- Modify: `cmd/valinor/main.go`
- Modify: `cmd/valinor/channels_outbox_worker.go`
- Modify: `cmd/valinor/main_test.go`
- Modify: `cmd/valinor/channels_outbox_sender_whatsapp_test.go`

**Step 1: Write failing tests**

Add/extend tests asserting:
- keyed store construction from `cfg.Channels.Credentials.Key`
- invalid key format fails fast in builder paths
- existing behavior remains for plaintext credentials when key not set

**Step 2: Run tests to verify fail**

Run: `go test ./cmd/valinor -run 'TestBuildChannel(Handler|OutboxWorker)' -v`
Expected: FAIL until store wiring and key validation are implemented.

**Step 3: Minimal implementation**

Implement helper in `cmd/valinor` to:
- parse key (if provided)
- build `channels.Store` with crypto option
- return explicit config error for invalid key

Use helper in:
- `buildChannelHandler`
- `buildChannelOutboxWorker`

**Step 4: Re-run tests**

Run: `go test ./cmd/valinor -run 'TestBuildChannel(Handler|OutboxWorker)' -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add cmd/valinor/main.go cmd/valinor/channels_outbox_worker.go cmd/valinor/main_test.go cmd/valinor/channels_outbox_sender_whatsapp_test.go
git commit -m "feat(channels): wire keyed credential store for runtime components"
```

### Task 5: End-to-End Verification + Docs Sync

**Files:**
- Modify: `docs/plans/2026-02-24-phase8-tenant-channel-provider-credentials-design.md` (if needed)

**Step 1: Run targeted suites**

Run:
- `go test ./internal/platform/config -v`
- `go test ./internal/channels -v`
- `go test ./cmd/valinor -v`
- `go test ./internal/platform/server -v`
- `go test ./internal/platform/database -run TestRLS_TenantIsolation -v`

**Step 2: Run compile sweep**

Run: `go test ./... -run TestDoesNotExist -count=1`

**Step 3: Commit docs if changed**

```bash
git add docs/plans/2026-02-24-phase8-tenant-channel-provider-credentials-design.md
git commit -m "docs(channels): document credential encryption-at-rest behavior"
```

**Step 4: Push and open PR**

```bash
git push -u origin codex/phase8-channel-credential-encryption
```
