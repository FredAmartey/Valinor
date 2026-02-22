package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/valinor-ai/valinor/internal/platform/database"
	"golang.org/x/sync/errgroup"
)

// ManagerConfig holds orchestrator configuration.
type ManagerConfig struct {
	Driver                 string
	WarmPoolSize           int
	HealthInterval         time.Duration
	ReconcileInterval      time.Duration
	MaxConsecutiveFailures int
}

// Manager orchestrates VM lifecycles.
type Manager struct {
	driver VMDriver
	store  *Store
	pool   *database.Pool
	cfg    ManagerConfig
	mu     sync.Mutex // protects CID allocation
}

func NewManager(pool *database.Pool, driver VMDriver, store *Store, cfg ManagerConfig) *Manager {
	if cfg.WarmPoolSize <= 0 {
		cfg.WarmPoolSize = 2
	}
	if cfg.HealthInterval <= 0 {
		cfg.HealthInterval = 10 * time.Second
	}
	if cfg.ReconcileInterval <= 0 {
		cfg.ReconcileInterval = 30 * time.Second
	}
	if cfg.MaxConsecutiveFailures <= 0 {
		cfg.MaxConsecutiveFailures = 3
	}
	return &Manager{
		driver: driver,
		store:  store,
		pool:   pool,
		cfg:    cfg,
	}
}

// Provision assigns a VM to a tenant. Tries warm pool first, falls back to cold-start.
func (m *Manager) Provision(ctx context.Context, tenantID string, opts ProvisionOpts) (*AgentInstance, error) {
	// Build config string for claim
	configStr := "{}"
	if opts.Config != nil {
		configJSON, _ := json.Marshal(opts.Config)
		configStr = string(configJSON)
	}

	// Try claiming a warm VM — dept/config are set atomically in the claim query.
	inst, err := m.store.ClaimWarm(ctx, m.pool, tenantID, opts.DepartmentID, configStr)
	if err == nil {
		// Transition to running
		if err := m.store.UpdateStatus(ctx, m.pool, inst.ID, StatusRunning); err != nil {
			return nil, fmt.Errorf("transitioning to running: %w", err)
		}
		inst.Status = StatusRunning
		slog.Info("provisioned agent from warm pool", "id", inst.ID, "tenant", tenantID)
		return inst, nil
	}

	// Cold-start fallback
	slog.Info("no warm VMs available, cold-starting", "tenant", tenantID)
	return m.coldStart(ctx, tenantID, opts)
}

func (m *Manager) coldStart(ctx context.Context, tenantID string, opts ProvisionOpts) (*AgentInstance, error) {
	// Hold mutex from CID allocation through DB insert to prevent TOCTOU races.
	m.mu.Lock()
	defer m.mu.Unlock()

	cid, err := m.store.NextVsockCID(ctx, m.pool)
	if err != nil {
		return nil, fmt.Errorf("allocating vsock CID: %w", err)
	}

	prefix := tenantID
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	vmID := fmt.Sprintf("vm-%s-%d", prefix, time.Now().UnixMilli())

	spec := VMSpec{
		VMID:     vmID,
		VsockCID: cid,
	}

	handle, err := m.driver.Start(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("starting VM: %w: %v", ErrDriverFailure, err)
	}

	configStr := "{}"
	if opts.Config != nil {
		configJSON, _ := json.Marshal(opts.Config)
		configStr = string(configJSON)
	}

	inst := &AgentInstance{
		TenantID:      &tenantID,
		DepartmentID:  opts.DepartmentID,
		VMID:          &vmID,
		Status:        StatusRunning,
		Config:        configStr,
		VsockCID:      &handle.VsockCID,
		VMDriver:      m.cfg.Driver,
		ToolAllowlist: "[]",
	}

	if err := m.store.Create(ctx, m.pool, inst); err != nil {
		// Best-effort cleanup on DB failure
		_ = m.driver.Stop(ctx, vmID)
		_ = m.driver.Cleanup(ctx, vmID)
		return nil, fmt.Errorf("saving agent instance: %w", err)
	}

	slog.Info("cold-started agent", "id", inst.ID, "tenant", tenantID, "vm", vmID)
	return inst, nil
}

// Destroy stops and cleans up a VM, then marks it destroyed.
func (m *Manager) Destroy(ctx context.Context, id string) error {
	inst, err := m.store.GetByID(ctx, m.pool, id)
	if err != nil {
		return err
	}

	if err := m.store.UpdateStatus(ctx, m.pool, id, StatusDestroying); err != nil {
		return fmt.Errorf("marking destroying: %w", err)
	}

	if inst.VMID != nil {
		if stopErr := m.driver.Stop(ctx, *inst.VMID); stopErr != nil {
			slog.Warn("failed to stop VM", "id", id, "vm", *inst.VMID, "error", stopErr)
		}
		if cleanErr := m.driver.Cleanup(ctx, *inst.VMID); cleanErr != nil {
			slog.Warn("failed to cleanup VM", "id", id, "vm", *inst.VMID, "error", cleanErr)
		}
	}

	if err := m.store.UpdateStatus(ctx, m.pool, id, StatusDestroyed); err != nil {
		return fmt.Errorf("marking destroyed: %w", err)
	}

	slog.Info("destroyed agent", "id", id)
	return nil
}

// GetByID returns an agent instance by ID.
func (m *Manager) GetByID(ctx context.Context, id string) (*AgentInstance, error) {
	return m.store.GetByID(ctx, m.pool, id)
}

// ListByTenant returns all non-destroyed agents for a tenant.
func (m *Manager) ListByTenant(ctx context.Context, tenantID string) ([]AgentInstance, error) {
	return m.store.ListByTenant(ctx, m.pool, tenantID)
}

// UpdateConfig updates an agent's config and tool allow-list.
func (m *Manager) UpdateConfig(ctx context.Context, id, config, toolAllowlist string) error {
	return m.store.UpdateConfig(ctx, m.pool, id, config, toolAllowlist)
}

// Run starts the warm pool reconciler and health check loops.
// Blocks until context is canceled.
func (m *Manager) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		m.reconcileLoop(ctx)
		return nil
	})

	g.Go(func() error {
		m.healthCheckLoop(ctx)
		return nil
	})

	return g.Wait()
}

// reconcileLoop maintains the warm pool at the target size.
func (m *Manager) reconcileLoop(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.ReconcileInterval)
	defer ticker.Stop()

	// Run once immediately at startup
	m.ReconcileOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.ReconcileOnce(ctx)
		}
	}
}

// ReconcileOnce replenishes the warm pool to the target size.
func (m *Manager) ReconcileOnce(ctx context.Context) {
	count, err := m.store.CountByStatus(ctx, m.pool, StatusWarm)
	if err != nil {
		slog.Error("warm pool count failed", "error", err)
		return
	}

	deficit := m.cfg.WarmPoolSize - count
	if deficit <= 0 {
		return
	}

	slog.Info("replenishing warm pool", "current", count, "target", m.cfg.WarmPoolSize, "starting", deficit)

	for range deficit {
		if ctx.Err() != nil {
			return
		}
		m.createWarmVM(ctx)
	}
}

// createWarmVM allocates a CID, starts a VM, and inserts it as warm.
// Holds the mutex from CID allocation through DB insert to prevent TOCTOU races.
func (m *Manager) createWarmVM(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cid, err := m.store.NextVsockCID(ctx, m.pool)
	if err != nil {
		slog.Error("CID allocation failed", "error", err)
		return
	}

	vmID := fmt.Sprintf("warm-%d-%d", cid, time.Now().UnixMilli())
	spec := VMSpec{
		VMID:     vmID,
		VsockCID: cid,
	}

	handle, err := m.driver.Start(ctx, spec)
	if err != nil {
		slog.Error("warm VM start failed", "error", err)
		return
	}

	inst := &AgentInstance{
		VMID:          &vmID,
		Status:        StatusWarm,
		Config:        "{}",
		VsockCID:      &handle.VsockCID,
		VMDriver:      m.cfg.Driver,
		ToolAllowlist: "[]",
	}

	if err := m.store.Create(ctx, m.pool, inst); err != nil {
		slog.Error("saving warm VM failed", "error", err)
		_ = m.driver.Stop(ctx, vmID)
		_ = m.driver.Cleanup(ctx, vmID)
		return
	}

	slog.Info("warm VM started", "id", inst.ID, "cid", cid)
}

// healthCheckLoop checks all running VMs and replaces unhealthy ones.
func (m *Manager) healthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.HealthInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.HealthCheckOnce(ctx)
		}
	}
}

// HealthCheckOnce checks all running VMs and handles unhealthy ones.
func (m *Manager) HealthCheckOnce(ctx context.Context) {
	instances, err := m.store.ListByStatus(ctx, m.pool, StatusRunning)
	if err != nil {
		slog.Error("listing running instances failed", "error", err)
		return
	}

	if len(instances) == 0 {
		return
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(10) // concurrency cap

	for _, inst := range instances {
		inst := inst
		g.Go(func() error {
			if inst.VMID == nil {
				return nil
			}

			healthy, err := m.driver.IsHealthy(ctx, *inst.VMID)
			if err != nil {
				slog.Warn("health check error", "id", inst.ID, "error", err)
				healthy = false
			}

			if err := m.store.RecordHealthCheck(ctx, m.pool, inst.ID, healthy); err != nil {
				slog.Error("recording health check failed", "id", inst.ID, "error", err)
				return nil
			}

			if !healthy {
				// Re-read to get updated consecutive_failures count
				updated, err := m.store.GetByID(ctx, m.pool, inst.ID)
				if err != nil {
					return nil
				}
				if updated.ConsecutiveFailures >= m.cfg.MaxConsecutiveFailures {
					slog.Warn("VM exceeded failure threshold, replacing",
						"id", inst.ID, "failures", updated.ConsecutiveFailures)
					m.replaceUnhealthy(ctx, updated)
				}
			}

			return nil
		})
	}

	_ = g.Wait()
}

func (m *Manager) replaceUnhealthy(ctx context.Context, inst *AgentInstance) {
	// Mark unhealthy
	if err := m.store.UpdateStatus(ctx, m.pool, inst.ID, StatusUnhealthy); err != nil {
		slog.Error("marking unhealthy failed", "id", inst.ID, "error", err)
		return
	}

	// Destroy old VM
	if inst.VMID != nil {
		_ = m.driver.Stop(ctx, *inst.VMID)
		_ = m.driver.Cleanup(ctx, *inst.VMID)
	}
	_ = m.store.UpdateStatus(ctx, m.pool, inst.ID, StatusDestroyed)

	// Provision replacement if this VM had a tenant, carrying forward config.
	if inst.TenantID != nil {
		var prevConfig map[string]any
		if inst.Config != "" && inst.Config != "{}" {
			_ = json.Unmarshal([]byte(inst.Config), &prevConfig)
		}
		replacement, err := m.Provision(ctx, *inst.TenantID, ProvisionOpts{
			DepartmentID: inst.DepartmentID,
			Config:       prevConfig,
		})
		if err != nil {
			slog.Error("replacement provision failed", "original", inst.ID, "error", err)
			return
		}
		// Carry forward tool_allowlist from the old instance.
		if inst.ToolAllowlist != "" && inst.ToolAllowlist != "[]" {
			if updateErr := m.store.UpdateConfig(ctx, m.pool, replacement.ID, replacement.Config, inst.ToolAllowlist); updateErr != nil {
				slog.Error("carrying forward tool_allowlist failed", "id", replacement.ID, "error", updateErr)
			}
		}
		slog.Info("replaced unhealthy VM", "original", inst.ID, "replacement", replacement.ID)
	}
}
