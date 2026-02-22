DROP POLICY IF EXISTS audit_tenant_read ON audit_events;
ALTER TABLE audit_events DISABLE ROW LEVEL SECURITY;
GRANT DELETE ON audit_events TO PUBLIC;
