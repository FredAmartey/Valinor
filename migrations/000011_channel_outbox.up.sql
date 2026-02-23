CREATE TABLE IF NOT EXISTS channel_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    channel_message_id UUID NOT NULL REFERENCES channel_messages(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempt_count INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error TEXT,
    locked_at TIMESTAMPTZ,
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT channel_outbox_status_check
        CHECK (status IN ('pending', 'sending', 'sent', 'dead'))
);

ALTER TABLE channel_outbox ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'channel_outbox'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON channel_outbox
            USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_channel_outbox_tenant_status_next_attempt
    ON channel_outbox(tenant_id, status, next_attempt_at);

CREATE INDEX IF NOT EXISTS idx_channel_outbox_active_work
    ON channel_outbox(tenant_id, next_attempt_at)
    WHERE status IN ('pending', 'sending');

CREATE INDEX IF NOT EXISTS idx_channel_outbox_channel_message_id
    ON channel_outbox(channel_message_id);
