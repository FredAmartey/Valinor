-- Seed default system roles and assign them to dev users.
-- Run once after initial dev setup:
--   psql postgres://valinor:valinor@localhost:5432/valinor -f scripts/seed_dev_roles.sql
--
-- Role names must match those registered in cmd/valinor/main.go.
-- The permissions column is stored for display; enforcement uses the in-memory evaluator.

DO $$
DECLARE
    v_tenant_id uuid := 'a1b2c3d4-0001-4000-8000-000000000001';
    role_org_admin    uuid;
    role_dept_head    uuid;
    role_standard     uuid;
    role_read_only    uuid;
BEGIN
    -- Set RLS context
    PERFORM set_config('app.current_tenant_id', v_tenant_id::text, true);

    -- Insert system roles (idempotent)
    INSERT INTO roles (tenant_id, name, permissions, is_system)
    VALUES
        (v_tenant_id, 'org_admin',     '["*"]'::jsonb, true),
        (v_tenant_id, 'dept_head',     '["agents:read","agents:write","agents:message","users:read","users:write","departments:read","connectors:read","connectors:write","channels:links:read","channels:links:write","channels:messages:write","channels:outbox:read","channels:outbox:write","channels:providers:read","channels:providers:write"]'::jsonb, true),
        (v_tenant_id, 'standard_user', '["agents:read","agents:message","channels:messages:write"]'::jsonb, true),
        (v_tenant_id, 'read_only',     '["agents:read"]'::jsonb, true)
    ON CONFLICT (tenant_id, name) DO NOTHING;

    -- Fetch role IDs
    SELECT id INTO role_org_admin    FROM roles WHERE tenant_id = v_tenant_id AND name = 'org_admin';
    SELECT id INTO role_dept_head    FROM roles WHERE tenant_id = v_tenant_id AND name = 'dept_head';
    SELECT id INTO role_standard     FROM roles WHERE tenant_id = v_tenant_id AND name = 'standard_user';
    SELECT id INTO role_read_only    FROM roles WHERE tenant_id = v_tenant_id AND name = 'read_only';

    -- Assign roles to dev users (idempotent)
    -- turgon: org admin
    INSERT INTO user_roles (user_id, role_id, scope_type, scope_id)
    VALUES ('a1b2c3d4-1001-4000-8000-000000000001', role_org_admin, 'org', v_tenant_id)
    ON CONFLICT DO NOTHING;

    -- glorfindel: standard user
    INSERT INTO user_roles (user_id, role_id, scope_type, scope_id)
    VALUES ('a1b2c3d4-1001-4000-8000-000000000002', role_standard, 'org', v_tenant_id)
    ON CONFLICT DO NOTHING;

    -- ecthelion: dept head
    INSERT INTO user_roles (user_id, role_id, scope_type, scope_id)
    VALUES ('a1b2c3d4-1001-4000-8000-000000000003', role_dept_head, 'org', v_tenant_id)
    ON CONFLICT DO NOTHING;

    -- maeglin: read only
    INSERT INTO user_roles (user_id, role_id, scope_type, scope_id)
    VALUES ('a1b2c3d4-1001-4000-8000-000000000004', role_read_only, 'org', v_tenant_id)
    ON CONFLICT DO NOTHING;

    RAISE NOTICE 'Dev roles seeded for tenant %', v_tenant_id;
END;
$$;
