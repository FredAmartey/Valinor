# Channels Rollout and Kill Switch Runbook

**Scope:** Safe rollout/rollback for channel ingress and emergency stop procedures.

## 1) Feature Controls

### Global ingress switch

- Config key: `channels.ingress.enabled`
- Environment override: `VALINOR_CHANNELS_INGRESS_ENABLED`
- Effect: disables all channel ingress when `false`.

### Per-provider switches

- `channels.providers.slack.enabled`
- `channels.providers.whatsapp.enabled`
- `channels.providers.telegram.enabled`

These allow provider-specific rollback without disabling all channels.

## 2) Recommended Rollout Sequence

1. Dev:
   - Enable ingress + one provider.
   - Validate signature, duplicate, replay, and audit behaviors.
2. Staging:
   - Enable ingress + selected provider.
   - Run smoke tests and load tests for duplicate delivery behavior.
3. Pilot tenant:
   - Enable provider for a single tenant cohort.
   - Monitor for 24h minimum.
4. Wider rollout:
   - Expand tenant scope incrementally.

## 3) Kill Switch Procedure

### Emergency global stop

1. Set `channels.ingress.enabled=false`.
2. Reload/redeploy configuration.
3. Verify webhook endpoints stop processing actions.
4. Confirm ingress attempts are rejected and observable.

### Provider-specific stop

1. Set target provider `enabled=false`.
2. Reload/redeploy configuration.
3. Verify only that provider is blocked; others remain healthy.

## 4) Rollback Procedure (Code + Config)

1. Revert to last known good release.
2. Keep `channels.ingress.enabled=false` during rollback validation.
3. Re-enable provider flags one-by-one after verification checks pass.
4. Re-run webhook verification runbook before reopening production traffic.

## 5) Post-Rollback Validation Checklist

- Signature validation succeeds for valid requests and rejects invalid requests.
- Duplicate deliveries are acknowledged without re-execution.
- Replay protection blocks stale/reused messages.
- Audit events include correlation and decision metadata.
- Cross-tenant isolation checks pass.
