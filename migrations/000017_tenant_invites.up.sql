CREATE TABLE tenant_invites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    code        VARCHAR(32) UNIQUE NOT NULL,
    role        VARCHAR(64) NOT NULL DEFAULT 'standard_user',
    created_by  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tenant_invites_code ON tenant_invites(code) WHERE used_at IS NULL;
CREATE INDEX idx_tenant_invites_tenant ON tenant_invites(tenant_id);

ALTER TABLE tenant_invites ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_invites
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
