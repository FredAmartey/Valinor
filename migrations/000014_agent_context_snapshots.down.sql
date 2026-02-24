DROP POLICY IF EXISTS tenant_isolation ON agent_context_snapshots;

DROP INDEX IF EXISTS idx_agent_context_snapshots_tenant_agent;

DROP TABLE IF EXISTS agent_context_snapshots;

