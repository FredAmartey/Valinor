DROP INDEX IF EXISTS idx_rtf_legacy_hash;
ALTER TABLE refresh_token_families DROP COLUMN IF EXISTS legacy_token_hash;
