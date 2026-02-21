-- Reject replay of legacy refresh tokens after first upgrade.
-- Stores the hash of the original pre-rotation JWT so that repeated
-- upgrade attempts can be detected and rejected.
ALTER TABLE refresh_token_families
    ADD COLUMN legacy_token_hash TEXT;

CREATE INDEX idx_rtf_legacy_hash ON refresh_token_families(user_id, tenant_id, legacy_token_hash)
    WHERE legacy_token_hash IS NOT NULL AND revoked_at IS NULL;
