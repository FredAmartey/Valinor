CREATE TABLE agent_activity_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id UUID,
    user_id UUID,
    department_id UUID,
    session_id TEXT,
    correlation_id TEXT,
    approval_id UUID,
    connector_id UUID,
    channel_message_id UUID,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    risk_class TEXT,
    source TEXT NOT NULL,
    provenance TEXT,
    internal_event_type TEXT,
    binding TEXT,
    delivery_target TEXT,
    runtime_source TEXT,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    actor_label TEXT,
    target_label TEXT,
    sensitive_content_ref JSONB,
    metadata JSONB,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_agent_activity_events_tenant_occurred_at
    ON agent_activity_events(tenant_id, occurred_at DESC, created_at DESC);

CREATE INDEX idx_agent_activity_events_tenant_agent_occurred_at
    ON agent_activity_events(tenant_id, agent_id, occurred_at DESC)
    WHERE agent_id IS NOT NULL;

CREATE INDEX idx_agent_activity_events_tenant_kind_occurred_at
    ON agent_activity_events(tenant_id, kind, occurred_at DESC);

CREATE INDEX idx_agent_activity_events_tenant_status_occurred_at
    ON agent_activity_events(tenant_id, status, occurred_at DESC);

CREATE INDEX idx_agent_activity_events_tenant_risk_class_occurred_at
    ON agent_activity_events(tenant_id, risk_class, occurred_at DESC)
    WHERE risk_class IS NOT NULL;

ALTER TABLE agent_activity_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON agent_activity_events
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

REVOKE DELETE ON agent_activity_events FROM PUBLIC;
