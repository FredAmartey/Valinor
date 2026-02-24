ALTER TABLE channel_provider_credentials
    ADD COLUMN IF NOT EXISTS signing_secret TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS secret_token TEXT NOT NULL DEFAULT '';
