DROP INDEX IF EXISTS idx_agent_instances_tenant_user_active_unique;
DROP INDEX IF EXISTS idx_agent_instances_tenant_user_status;

ALTER TABLE agent_instances
    DROP COLUMN IF EXISTS user_id;
