ALTER TABLE channel_provider_credentials
    DROP COLUMN IF EXISTS secret_token,
    DROP COLUMN IF EXISTS signing_secret;
