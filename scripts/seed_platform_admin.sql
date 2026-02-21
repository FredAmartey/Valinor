-- Seed a platform admin user.
-- Run this once after initial deployment:
--   psql $DATABASE_URL -f scripts/seed_platform_admin.sql
--
-- Customize the VALUES below for your environment.
-- The user must already exist via OIDC login, OR you can insert directly.

-- Option A: Promote an existing user to platform admin
-- UPDATE users SET is_platform_admin = true WHERE email = 'admin@yourcompany.com';

-- Option B: Create a bootstrap tenant + platform admin user
INSERT INTO tenants (name, slug) VALUES ('Platform Operations', 'platform-ops')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO users (tenant_id, email, display_name, oidc_subject, oidc_issuer, is_platform_admin)
VALUES (
    (SELECT id FROM tenants WHERE slug = 'platform-ops'),
    'admin@example.com',       -- CHANGE THIS
    'Platform Admin',
    'replace-with-oidc-sub',   -- CHANGE THIS
    'https://accounts.google.com',
    true
)
ON CONFLICT (oidc_issuer, oidc_subject) DO UPDATE SET is_platform_admin = true;
