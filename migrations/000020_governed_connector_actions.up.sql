CREATE TABLE governed_connector_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agent_instances(id) ON DELETE SET NULL,
    approval_request_id UUID REFERENCES approval_requests(id) ON DELETE SET NULL,
    connector_id UUID NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    session_id TEXT,
    correlation_id TEXT,
    tool_name TEXT NOT NULL,
    risk_class TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_label TEXT NOT NULL,
    action_summary TEXT NOT NULL,
    arguments JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT governed_connector_actions_status_check
        CHECK (status IN ('pending', 'awaiting_approval', 'approved', 'denied', 'executed', 'failed'))
);

CREATE INDEX idx_governed_connector_actions_tenant_status_created_at
    ON governed_connector_actions(tenant_id, status, created_at DESC);

CREATE INDEX idx_governed_connector_actions_tenant_connector_created_at
    ON governed_connector_actions(tenant_id, connector_id, created_at DESC);

CREATE INDEX idx_governed_connector_actions_tenant_correlation
    ON governed_connector_actions(tenant_id, correlation_id)
    WHERE correlation_id IS NOT NULL;

ALTER TABLE governed_connector_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE governed_connector_actions FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON governed_connector_actions
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

REVOKE DELETE ON governed_connector_actions FROM PUBLIC;
