-- user_roles: RLS enabled in 000001 but no policy exists — add one
CREATE POLICY tenant_isolation ON user_roles
    USING (EXISTS (
        SELECT 1 FROM users
        WHERE users.id = user_roles.user_id
        AND users.tenant_id = current_setting('app.current_tenant_id', true)::UUID
    ));

-- user_departments: no RLS at all — enable and add policy
ALTER TABLE user_departments ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON user_departments
    USING (EXISTS (
        SELECT 1 FROM users
        WHERE users.id = user_departments.user_id
        AND users.tenant_id = current_setting('app.current_tenant_id', true)::UUID
    ));
