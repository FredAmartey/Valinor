DROP POLICY IF EXISTS tenant_isolation ON user_roles;
DROP POLICY IF EXISTS tenant_isolation ON user_departments;
ALTER TABLE user_departments DISABLE ROW LEVEL SECURITY;
