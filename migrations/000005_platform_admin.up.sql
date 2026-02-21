-- Platform admin flag for cross-tenant operations.
-- Revisit: once we discover what platform-level operations exist beyond
-- tenant CRUD, may need to graduate to platform_role TEXT or a table.
ALTER TABLE users ADD COLUMN is_platform_admin BOOLEAN NOT NULL DEFAULT false;
