-- Enable RLS on audit_events
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;

-- Allow inserts from any tenant (audit writes use superuser or bypass RLS)
-- Read access restricted to own tenant
CREATE POLICY audit_tenant_read ON audit_events
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- Revoke DELETE on audit_events from the app role to ensure append-only
-- (The app role is the non-superuser connection used by WithTenantConnection)
REVOKE DELETE ON audit_events FROM PUBLIC;
