-- Warm-pool VMs have no tenant assigned yet, so tenant_id must be nullable.
ALTER TABLE agent_instances ALTER COLUMN tenant_id DROP NOT NULL;

-- Track which driver started this VM.
ALTER TABLE agent_instances ADD COLUMN vm_driver TEXT NOT NULL DEFAULT 'mock';

-- Health-check failure counter (survives process restart).
ALTER TABLE agent_instances ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0;

-- Each VM gets a unique vsock CID.
ALTER TABLE agent_instances ADD CONSTRAINT agent_instances_vsock_cid_unique UNIQUE (vsock_cid);

-- Index for warm-pool queries (status='warm', tenant_id IS NULL).
CREATE INDEX idx_agent_instances_status ON agent_instances(status);
