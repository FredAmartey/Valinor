DROP POLICY IF EXISTS tenant_isolation ON channel_outbox;

DROP INDEX IF EXISTS idx_channel_outbox_channel_message_id;
DROP INDEX IF EXISTS idx_channel_outbox_active_work;
DROP INDEX IF EXISTS idx_channel_outbox_tenant_status_next_attempt;

DROP TABLE IF EXISTS channel_outbox;
