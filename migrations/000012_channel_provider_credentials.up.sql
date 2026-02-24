CREATE TABLE IF NOT EXISTS channel_provider_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    access_token TEXT NOT NULL,
    api_base_url TEXT NOT NULL DEFAULT '',
    api_version TEXT NOT NULL DEFAULT '',
    phone_number_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT channel_provider_credentials_tenant_provider_unique
        UNIQUE (tenant_id, provider)
);

ALTER TABLE channel_provider_credentials ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'channel_provider_credentials'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON channel_provider_credentials
            USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_channel_provider_credentials_tenant_provider
    ON channel_provider_credentials (tenant_id, provider);
