-- Refresh token family rotation (RFC 6819 §5.2.2.3)
-- Tracks token families for reuse detection and revocation.
CREATE TABLE refresh_token_families (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    current_generation INT NOT NULL DEFAULT 1,
    current_token_hash TEXT NOT NULL,
    revoked_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_rtf_tenant_id ON refresh_token_families(tenant_id);
CREATE INDEX idx_rtf_user_id ON refresh_token_families(user_id);
CREATE INDEX idx_rtf_active_lookup ON refresh_token_families(id, tenant_id)
    WHERE revoked_at IS NULL;

ALTER TABLE refresh_token_families ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON refresh_token_families
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
