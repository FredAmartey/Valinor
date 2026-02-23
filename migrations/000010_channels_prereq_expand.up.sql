ALTER TABLE channel_links
    ADD COLUMN IF NOT EXISTS tenant_id UUID,
    ADD COLUMN IF NOT EXISTS state TEXT,
    ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS verification_method TEXT,
    ADD COLUMN IF NOT EXISTS verification_metadata JSONB NOT NULL DEFAULT '{}';

UPDATE channel_links cl
SET tenant_id = u.tenant_id
FROM users u
WHERE cl.user_id = u.id
  AND cl.tenant_id IS NULL;

UPDATE channel_links
SET state = CASE
    WHEN verified THEN 'verified'
    ELSE 'pending_verification'
END
WHERE state IS NULL;

UPDATE channel_links
SET verified_at = created_at
WHERE verified = true
  AND verified_at IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'channel_links_tenant_id_fkey'
    ) THEN
        ALTER TABLE channel_links
            ADD CONSTRAINT channel_links_tenant_id_fkey
                FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
    END IF;
END $$;

ALTER TABLE channel_links
    ALTER COLUMN tenant_id SET NOT NULL,
    ALTER COLUMN state SET DEFAULT 'pending_verification',
    ALTER COLUMN state SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'channel_links_state_check'
    ) THEN
        ALTER TABLE channel_links
            ADD CONSTRAINT channel_links_state_check
                CHECK (state IN ('pending_verification', 'verified', 'revoked'));
    END IF;
END $$;

ALTER TABLE channel_links
    DROP CONSTRAINT IF EXISTS channel_links_platform_platform_user_id_key;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'channel_links_tenant_platform_identity_unique'
    ) THEN
        ALTER TABLE channel_links
            ADD CONSTRAINT channel_links_tenant_platform_identity_unique
                UNIQUE (tenant_id, platform, platform_user_id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_channel_links_tenant_id ON channel_links(tenant_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'channel_links'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON channel_links
            USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS channel_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    platform TEXT NOT NULL,
    platform_user_id TEXT NOT NULL,
    platform_message_id TEXT,
    idempotency_key TEXT NOT NULL,
    payload_fingerprint TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    status TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE channel_messages ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'channel_messages'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON channel_messages
            USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'channel_messages_tenant_platform_idempotency_unique'
    ) THEN
        ALTER TABLE channel_messages
            ADD CONSTRAINT channel_messages_tenant_platform_idempotency_unique
                UNIQUE (tenant_id, platform, idempotency_key);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_channel_messages_tenant_created_at
    ON channel_messages(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_channel_messages_expires_at
    ON channel_messages(expires_at);
