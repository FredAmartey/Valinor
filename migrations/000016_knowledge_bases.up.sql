-- Knowledge bases: named collections of shared knowledge per tenant.
CREATE TABLE knowledge_bases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    layer TEXT NOT NULL CHECK (layer IN ('tenant', 'department')),
    source_department_id UUID REFERENCES departments(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_knowledge_bases_tenant_id ON knowledge_bases(tenant_id);

ALTER TABLE knowledge_bases ENABLE ROW LEVEL SECURITY;

CREATE POLICY knowledge_bases_tenant_isolation ON knowledge_bases
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- Knowledge base access grants: map KB to departments/roles/users.
CREATE TABLE knowledge_base_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    knowledge_base_id UUID NOT NULL REFERENCES knowledge_bases(id) ON DELETE CASCADE,
    grant_type TEXT NOT NULL CHECK (grant_type IN ('department', 'role', 'user')),
    grant_target_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_kb_grants_kb_id ON knowledge_base_grants(knowledge_base_id);
CREATE UNIQUE INDEX idx_kb_grants_unique ON knowledge_base_grants(knowledge_base_id, grant_type, grant_target_id);

ALTER TABLE knowledge_base_grants ENABLE ROW LEVEL SECURITY;

-- RLS via join to knowledge_bases for tenant isolation.
CREATE POLICY kb_grants_tenant_isolation ON knowledge_base_grants
    USING (
        knowledge_base_id IN (
            SELECT id FROM knowledge_bases
            WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
        )
    );
