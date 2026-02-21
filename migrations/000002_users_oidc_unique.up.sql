-- Replace non-unique index with unique constraint to prevent TOCTOU race
-- in FindOrCreateByOIDC.
DROP INDEX IF EXISTS idx_users_oidc;
ALTER TABLE users ADD CONSTRAINT uq_users_oidc UNIQUE (oidc_issuer, oidc_subject);
