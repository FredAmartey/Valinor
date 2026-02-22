DROP INDEX IF EXISTS idx_agent_instances_status;
ALTER TABLE agent_instances DROP CONSTRAINT IF EXISTS agent_instances_vsock_cid_unique;
ALTER TABLE agent_instances DROP COLUMN IF EXISTS consecutive_failures;
ALTER TABLE agent_instances DROP COLUMN IF EXISTS vm_driver;

-- Restore NOT NULL (delete any warm VMs first to avoid constraint violation).
DELETE FROM agent_instances WHERE tenant_id IS NULL;
ALTER TABLE agent_instances ALTER COLUMN tenant_id SET NOT NULL;
