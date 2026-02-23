DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM connectors
        GROUP BY tenant_id, name
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot enforce connectors_tenant_name_unique: duplicate (tenant_id, name) rows exist';
    END IF;
END $$;

ALTER TABLE connectors
    ADD CONSTRAINT connectors_tenant_name_unique UNIQUE (tenant_id, name);
