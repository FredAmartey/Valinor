//go:build linux

package orchestrator

import (
	"context"
	"fmt"
)

// FirecrackerDriver manages Firecracker MicroVMs.
// Requires Linux with KVM support.
type FirecrackerDriver struct {
	kernelPath string
	rootDrive  string
	jailerPath string
}

// NewFirecrackerDriver creates a new FirecrackerDriver.
func NewFirecrackerDriver(kernelPath, rootDrive, jailerPath string) *FirecrackerDriver {
	return &FirecrackerDriver{
		kernelPath: kernelPath,
		rootDrive:  rootDrive,
		jailerPath: jailerPath,
	}
}

func (d *FirecrackerDriver) Start(_ context.Context, spec VMSpec) (VMHandle, error) {
	// TODO: implement with firecracker-go-sdk when Linux CI is available
	return VMHandle{}, fmt.Errorf("%w: firecracker driver not yet implemented", ErrDriverFailure)
}

func (d *FirecrackerDriver) Stop(_ context.Context, id string) error {
	return fmt.Errorf("%w: firecracker driver not yet implemented", ErrDriverFailure)
}

func (d *FirecrackerDriver) IsHealthy(_ context.Context, id string) (bool, error) {
	return false, fmt.Errorf("%w: firecracker driver not yet implemented", ErrDriverFailure)
}

func (d *FirecrackerDriver) Cleanup(_ context.Context, id string) error {
	return fmt.Errorf("%w: firecracker driver not yet implemented", ErrDriverFailure)
}
