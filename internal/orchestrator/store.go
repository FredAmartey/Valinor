package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

// Store handles agent_instances database operations for the orchestrator.
// Operates on the owner pool (no RLS) since warm VMs have no tenant_id.
type Store struct{}

func NewStore() *Store {
	return &Store{}
}

func (s *Store) Create(ctx context.Context, q database.Querier, inst *AgentInstance) error {
	configJSON, err := json.Marshal(inst.Config)
	if err != nil {
		configJSON = []byte("{}")
	}

	return q.QueryRow(ctx,
		`INSERT INTO agent_instances (tenant_id, department_id, vm_id, status, config, vsock_cid, vm_driver, tool_allowlist)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id, created_at`,
		inst.TenantID, inst.DepartmentID, inst.VMID, inst.Status, configJSON,
		inst.VsockCID, inst.VMDriver, inst.ToolAllowlist,
	).Scan(&inst.ID, &inst.CreatedAt)
}

func (s *Store) GetByID(ctx context.Context, q database.Querier, id string) (*AgentInstance, error) {
	var inst AgentInstance
	err := q.QueryRow(ctx,
		`SELECT id, tenant_id, department_id, vm_id, status, config, vsock_cid,
		        vm_driver, tool_allowlist, consecutive_failures, created_at, last_health_check
		 FROM agent_instances WHERE id = $1`,
		id,
	).Scan(&inst.ID, &inst.TenantID, &inst.DepartmentID, &inst.VMID, &inst.Status,
		&inst.Config, &inst.VsockCID, &inst.VMDriver, &inst.ToolAllowlist,
		&inst.ConsecutiveFailures, &inst.CreatedAt, &inst.LastHealthCheck)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrVMNotFound
		}
		return nil, fmt.Errorf("getting agent instance: %w", err)
	}
	return &inst, nil
}

func (s *Store) UpdateStatus(ctx context.Context, q database.Querier, id, status string) error {
	tag, err := q.Exec(ctx,
		`UPDATE agent_instances SET status = $1 WHERE id = $2`,
		status, id,
	)
	if err != nil {
		return fmt.Errorf("updating status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrVMNotFound
	}
	return nil
}

func (s *Store) ListByStatus(ctx context.Context, q database.Querier, status string) ([]AgentInstance, error) {
	rows, err := q.Query(ctx,
		`SELECT id, tenant_id, department_id, vm_id, status, config, vsock_cid,
		        vm_driver, tool_allowlist, consecutive_failures, created_at, last_health_check
		 FROM agent_instances WHERE status = $1 ORDER BY created_at`,
		status,
	)
	if err != nil {
		return nil, fmt.Errorf("listing by status: %w", err)
	}
	defer rows.Close()

	return scanAgentInstances(rows)
}

func (s *Store) ListByTenant(ctx context.Context, q database.Querier, tenantID string) ([]AgentInstance, error) {
	rows, err := q.Query(ctx,
		`SELECT id, tenant_id, department_id, vm_id, status, config, vsock_cid,
		        vm_driver, tool_allowlist, consecutive_failures, created_at, last_health_check
		 FROM agent_instances WHERE tenant_id = $1 AND status != $2 ORDER BY created_at`,
		tenantID, StatusDestroyed,
	)
	if err != nil {
		return nil, fmt.Errorf("listing by tenant: %w", err)
	}
	defer rows.Close()

	return scanAgentInstances(rows)
}

// ClaimWarm atomically assigns a warm VM to a tenant.
// Uses FOR UPDATE SKIP LOCKED to avoid contention.
func (s *Store) ClaimWarm(ctx context.Context, q database.Querier, tenantID string) (*AgentInstance, error) {
	var inst AgentInstance
	err := q.QueryRow(ctx,
		`UPDATE agent_instances
		 SET tenant_id = $1, status = $2
		 WHERE id = (
		     SELECT id FROM agent_instances
		     WHERE status = $3 AND tenant_id IS NULL
		     ORDER BY created_at LIMIT 1
		     FOR UPDATE SKIP LOCKED
		 )
		 RETURNING id, tenant_id, department_id, vm_id, status, config, vsock_cid,
		           vm_driver, tool_allowlist, consecutive_failures, created_at, last_health_check`,
		tenantID, StatusProvisioning, StatusWarm,
	).Scan(&inst.ID, &inst.TenantID, &inst.DepartmentID, &inst.VMID, &inst.Status,
		&inst.Config, &inst.VsockCID, &inst.VMDriver, &inst.ToolAllowlist,
		&inst.ConsecutiveFailures, &inst.CreatedAt, &inst.LastHealthCheck)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrNoWarmVMs
		}
		return nil, fmt.Errorf("claiming warm VM: %w", err)
	}
	return &inst, nil
}

// RecordHealthCheck updates health state. If healthy, resets failures and updates timestamp.
// If unhealthy, increments consecutive_failures.
func (s *Store) RecordHealthCheck(ctx context.Context, q database.Querier, id string, healthy bool) error {
	var query string
	if healthy {
		query = `UPDATE agent_instances
		         SET last_health_check = now(), consecutive_failures = 0
		         WHERE id = $1`
	} else {
		query = `UPDATE agent_instances
		         SET consecutive_failures = consecutive_failures + 1
		         WHERE id = $1`
	}
	tag, err := q.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("recording health check: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrVMNotFound
	}
	return nil
}

// NextVsockCID returns the next available vsock CID.
// CIDs 0-2 are reserved by the vsock spec.
func (s *Store) NextVsockCID(ctx context.Context, q database.Querier) (uint32, error) {
	var cid uint32
	err := q.QueryRow(ctx,
		`SELECT COALESCE(MAX(vsock_cid), 2) + 1 FROM agent_instances`,
	).Scan(&cid)
	if err != nil {
		return 0, fmt.Errorf("getting next vsock CID: %w", err)
	}
	return cid, nil
}

// CountByStatus returns the count of agent instances with the given status.
func (s *Store) CountByStatus(ctx context.Context, q database.Querier, status string) (int, error) {
	var count int
	err := q.QueryRow(ctx,
		`SELECT COUNT(*) FROM agent_instances WHERE status = $1`,
		status,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting by status: %w", err)
	}
	return count, nil
}

// UpdateConfig updates the config and tool_allowlist columns.
func (s *Store) UpdateConfig(ctx context.Context, q database.Querier, id string, config string, toolAllowlist string) error {
	tag, err := q.Exec(ctx,
		`UPDATE agent_instances SET config = $1, tool_allowlist = $2 WHERE id = $3`,
		config, toolAllowlist, id,
	)
	if err != nil {
		return fmt.Errorf("updating config: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrVMNotFound
	}
	return nil
}

func scanAgentInstances(rows pgx.Rows) ([]AgentInstance, error) {
	var instances []AgentInstance
	for rows.Next() {
		var inst AgentInstance
		if err := rows.Scan(&inst.ID, &inst.TenantID, &inst.DepartmentID, &inst.VMID,
			&inst.Status, &inst.Config, &inst.VsockCID, &inst.VMDriver, &inst.ToolAllowlist,
			&inst.ConsecutiveFailures, &inst.CreatedAt, &inst.LastHealthCheck); err != nil {
			return nil, fmt.Errorf("scanning agent instance: %w", err)
		}
		instances = append(instances, inst)
	}
	return instances, rows.Err()
}
