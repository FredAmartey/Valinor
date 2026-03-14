DROP TABLE IF EXISTS approval_requests;

ALTER TABLE channel_outbox DROP CONSTRAINT IF EXISTS channel_outbox_status_check;

ALTER TABLE channel_outbox
    ADD CONSTRAINT channel_outbox_status_check
    CHECK (status IN ('pending', 'sending', 'sent', 'dead'));
