CREATE TABLE IF NOT EXISTS agent_context_snapshots (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agent_instances(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    context TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, agent_id, user_id)
);

ALTER TABLE agent_context_snapshots ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'agent_context_snapshots'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON agent_context_snapshots
            USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_agent_context_snapshots_tenant_agent
    ON agent_context_snapshots(tenant_id, agent_id);

