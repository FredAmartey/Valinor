ALTER TABLE agent_instances
    ADD COLUMN IF NOT EXISTS user_id TEXT;

CREATE INDEX IF NOT EXISTS idx_agent_instances_tenant_user_status
    ON agent_instances(tenant_id, user_id, status)
    WHERE user_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_instances_tenant_user_active_unique
    ON agent_instances(tenant_id, user_id)
    WHERE user_id IS NOT NULL
      AND status IN ('provisioning', 'running', 'unhealthy', 'destroying');
