ALTER TABLE channel_outbox DROP CONSTRAINT IF EXISTS channel_outbox_status_check;

ALTER TABLE channel_outbox
    ADD CONSTRAINT channel_outbox_status_check
    CHECK (status IN ('pending', 'sending', 'sent', 'dead', 'pending_approval'));

CREATE TABLE approval_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agent_instances(id) ON DELETE SET NULL,
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    channel_outbox_id UUID REFERENCES channel_outbox(id) ON DELETE SET NULL,
    risk_class TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    target_type TEXT NOT NULL,
    target_label TEXT NOT NULL,
    action_summary TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    CONSTRAINT approval_requests_status_check
        CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'cancelled'))
);

CREATE INDEX idx_approval_requests_tenant_created_at
    ON approval_requests(tenant_id, created_at DESC);

CREATE INDEX idx_approval_requests_tenant_status_created_at
    ON approval_requests(tenant_id, status, created_at DESC);

CREATE INDEX idx_approval_requests_channel_outbox_id
    ON approval_requests(channel_outbox_id)
    WHERE channel_outbox_id IS NOT NULL;

ALTER TABLE approval_requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON approval_requests
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

REVOKE DELETE ON approval_requests FROM PUBLIC;
