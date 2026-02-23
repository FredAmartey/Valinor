DROP TABLE IF EXISTS channel_messages;

DROP POLICY IF EXISTS tenant_isolation ON channel_links;

ALTER TABLE channel_links
    DROP CONSTRAINT IF EXISTS channel_links_tenant_platform_identity_unique;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM channel_links
        GROUP BY platform, platform_user_id
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot restore global channel identity uniqueness: duplicate (platform, platform_user_id) rows exist across tenants';
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'channel_links_platform_platform_user_id_key'
    ) THEN
        ALTER TABLE channel_links
            ADD CONSTRAINT channel_links_platform_platform_user_id_key
                UNIQUE (platform, platform_user_id);
    END IF;
END $$;

UPDATE channel_links
SET verified = (state = 'verified')
WHERE state IS NOT NULL;

ALTER TABLE channel_links
    DROP CONSTRAINT IF EXISTS channel_links_state_check,
    DROP CONSTRAINT IF EXISTS channel_links_tenant_id_fkey,
    DROP COLUMN IF EXISTS state,
    DROP COLUMN IF EXISTS verified_at,
    DROP COLUMN IF EXISTS revoked_at,
    DROP COLUMN IF EXISTS verification_method,
    DROP COLUMN IF EXISTS verification_metadata,
    DROP COLUMN IF EXISTS tenant_id;

DROP INDEX IF EXISTS idx_channel_links_tenant_id;
