package orchestrator

import (
	"context"
	"errors"
	"time"
)

// VM status constants — state machine:
// [warm] → [provisioning] → [running] → [unhealthy] → [destroying] → [destroyed]
const (
	StatusWarm         = "warm"
	StatusProvisioning = "provisioning"
	StatusRunning      = "running"
	StatusUnhealthy    = "unhealthy"
	StatusDestroying   = "destroying"
	StatusDestroyed    = "destroyed"
)

// Error sentinels.
var (
	ErrNoWarmVMs     = errors.New("no warm VMs available")
	ErrVMNotFound    = errors.New("agent instance not found")
	ErrVMNotRunning  = errors.New("VM is not in running state")
	ErrDriverFailure = errors.New("VM driver operation failed")
)

// VMDriver is the pluggable backend for starting/stopping/checking VMs.
// Implementations: FirecrackerDriver (Linux), DockerDriver (integration tests), MockDriver (unit tests).
type VMDriver interface {
	Start(ctx context.Context, spec VMSpec) (VMHandle, error)
	Stop(ctx context.Context, id string) error
	IsHealthy(ctx context.Context, id string) (bool, error)
	Cleanup(ctx context.Context, id string) error
}

// VMSpec describes the configuration for a new VM.
type VMSpec struct {
	VMID             string
	RootDrive        string
	DataDrive        string
	DataDriveQuotaMB int
	KernelPath       string
	KernelArgs       string
	VCPUs            int
	MemoryMB         int
	VsockCID         uint32
	UseJailer        bool
	JailerPath       string
}

// VMHandle is returned after a VM starts successfully.
type VMHandle struct {
	ID        string
	PID       int
	VsockCID  uint32
	StartedAt time.Time
}

// AgentInstance represents a row in the agent_instances table.
type AgentInstance struct {
	ID                  string     `json:"id"`
	TenantID            *string    `json:"tenant_id,omitempty"`
	DepartmentID        *string    `json:"department_id,omitempty"`
	VMID                *string    `json:"vm_id,omitempty"`
	Status              string     `json:"status"`
	Config              string     `json:"config"`
	VsockCID            *uint32    `json:"vsock_cid,omitempty"`
	VMDriver            string     `json:"vm_driver"`
	ToolAllowlist       string     `json:"tool_allowlist"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	CreatedAt           time.Time  `json:"created_at"`
	LastHealthCheck     *time.Time `json:"last_health_check,omitempty"`
}

// ProvisionOpts are options passed when provisioning a new agent.
type ProvisionOpts struct {
	DepartmentID *string
	// Config accepts arbitrary JSON since agent configuration varies by driver and use-case.
	Config map[string]any
}
