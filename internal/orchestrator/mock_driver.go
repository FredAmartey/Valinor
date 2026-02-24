package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type mockVM struct {
	handle  VMHandle
	running bool
	healthy bool
}

// MockDriver is an in-memory VMDriver for unit testing.
type MockDriver struct {
	mu    sync.Mutex
	vms   map[string]*mockVM
	specs map[string]VMSpec
}

func NewMockDriver() *MockDriver {
	return &MockDriver{
		vms:   make(map[string]*mockVM),
		specs: make(map[string]VMSpec),
	}
}

func (d *MockDriver) Start(_ context.Context, spec VMSpec) (VMHandle, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	handle := VMHandle{
		ID:        spec.VMID,
		PID:       len(d.vms) + 1000, // fake PID
		VsockCID:  spec.VsockCID,
		StartedAt: time.Now(),
	}

	d.vms[spec.VMID] = &mockVM{
		handle:  handle,
		running: true,
		healthy: true,
	}
	d.specs[spec.VMID] = spec

	return handle, nil
}

func (d *MockDriver) Stop(_ context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	vm, ok := d.vms[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrVMNotFound, id)
	}
	vm.running = false
	vm.healthy = false
	return nil
}

func (d *MockDriver) IsHealthy(_ context.Context, id string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	vm, ok := d.vms[id]
	if !ok {
		return false, fmt.Errorf("%w: %s", ErrVMNotFound, id)
	}
	return vm.running && vm.healthy, nil
}

func (d *MockDriver) Cleanup(_ context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.vms, id)
	return nil
}

// SetUnhealthy marks a VM as unhealthy (for testing health check logic).
func (d *MockDriver) SetUnhealthy(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if vm, ok := d.vms[id]; ok {
		vm.healthy = false
	}
}

// SetHealthy marks a VM as healthy again.
func (d *MockDriver) SetHealthy(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if vm, ok := d.vms[id]; ok {
		vm.healthy = true
	}
}

// RunningCount returns how many VMs are running.
func (d *MockDriver) RunningCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	count := 0
	for _, vm := range d.vms {
		if vm.running {
			count++
		}
	}
	return count
}

// LastSpec returns the most recent VM start spec for the given VM ID.
func (d *MockDriver) LastSpec(id string) (VMSpec, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	spec, ok := d.specs[id]
	return spec, ok
}
