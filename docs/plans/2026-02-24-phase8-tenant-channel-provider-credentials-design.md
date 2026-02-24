# Phase 8 Tenant Channel Provider Credentials Design

## Goal

Add tenant-scoped provider credentials so outbound channel delivery and inbound webhook verification are isolated per tenant and do not rely on global provider secrets.

## Scope

### In Scope

- New RLS-protected tenant-scoped credential table for channel providers.
- Store APIs to upsert, read, and delete provider credentials in tenant context.
- RBAC-protected HTTP endpoints to manage credentials for a tenant.
- Outbox sender credential resolution per job tenant + provider.
- Inbound webhook verifier secret resolution per request tenant + provider.
- Fail-closed delivery behavior when credentials are missing/invalid.
- Integration tests for tenant isolation and sender behavior.

### Out of Scope (deferred)

- Application-level encryption for stored credentials.
- Secret rotation workflows/versioning.

## Approaches Considered

1. **DB-backed tenant credentials, no fallback (recommended)**
   - Strict isolation and explicit onboarding.
   - Missing credentials fail closed.
2. DB-backed with global config fallback
   - Easier migration, weaker isolation guarantees.
3. Config-only per deployment
   - Strong isolation only with infrastructure split, poor multi-tenant ergonomics.

## Recommended Architecture

### Data model

Add `channel_provider_credentials`:

- `id UUID PK`
- `tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE`
- `provider TEXT NOT NULL`
- `access_token TEXT NOT NULL`
- `signing_secret TEXT NOT NULL DEFAULT ''`
- `secret_token TEXT NOT NULL DEFAULT ''`
- `api_base_url TEXT NOT NULL DEFAULT ''`
- `api_version TEXT NOT NULL DEFAULT ''`
- `phone_number_id TEXT NOT NULL DEFAULT ''`
- `created_at`, `updated_at`
- Unique `(tenant_id, provider)`
- RLS policy aligned with existing tenant tables

`provider` allowed values in app validation: `slack`, `whatsapp`, `telegram`.

### API shape

Tenant-scoped, auth-context tenant (same route style as connectors/channels links):

- `GET /api/v1/channels/providers/{provider}/credentials`
- `PUT /api/v1/channels/providers/{provider}/credentials`
- `DELETE /api/v1/channels/providers/{provider}/credentials`

Response from GET/PUT is sanitized (never returns access token):

- `provider`
- `api_base_url`
- `api_version`
- `phone_number_id`
- `has_access_token`
- `has_signing_secret`
- `has_secret_token`
- `updated_at`

RBAC:

- `channels:providers:read`
- `channels:providers:write`

### Outbox send path

- Outbox sender resolves provider credentials using job `tenant_id` + `provider`.
- If credentials are missing/invalid, return `OutboxPermanentError` and dead-letter immediately.
- If credentials are present, construct provider sender with resolved credentials and send normally.

### Inbound webhook verification path

- Ingress verifier resolves provider credentials using request tenant context + `provider`.
- Slack and WhatsApp verification use tenant `signing_secret`; Telegram uses tenant `secret_token`.
- Missing tenant credential or missing required verifier secret is treated as invalid signature (fail-closed).

### Validation rules

- All providers require non-empty `access_token`.
- WhatsApp additionally requires non-empty `phone_number_id`.
- Slack and WhatsApp additionally require non-empty `signing_secret`.
- Telegram additionally requires non-empty `secret_token`.
- `api_base_url` and `api_version` optional; fallback to provider defaults when empty.

## Risks and Mitigations

1. Credentials leaked via API responses
   - Mitigation: sanitize responses; never return raw token.
2. Operational failure from missing credentials
   - Mitigation: explicit fail-closed permanent errors with clear `last_error` text.
3. Plaintext-at-rest storage risk
   - Mitigation: keep scope minimal now; schedule envelope-encryption follow-up.

## Rollout

1. Deploy migration.
2. Configure provider credentials per tenant via API.
3. Enable/verify outbox sends in staging tenant.
4. Expand to pilot tenants.

## Product Outcome

After this slice, two tenants can use the same provider integration type without sharing delivery credentials or inbound verifier secrets, and failures from mis-scoped credentials are isolated to the owning tenant.
