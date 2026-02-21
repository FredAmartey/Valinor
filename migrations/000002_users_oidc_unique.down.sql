ALTER TABLE users DROP CONSTRAINT IF EXISTS uq_users_oidc;
CREATE INDEX idx_users_oidc ON users(oidc_issuer, oidc_subject);
