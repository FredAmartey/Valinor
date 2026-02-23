//go:build !linux

package orchestrator

import (
	"context"
	"fmt"
)

// FirecrackerDriver is unavailable on non-Linux hosts.
type FirecrackerDriver struct {
	kernelPath string
	rootDrive  string
	jailer     FirecrackerJailerConfig
}

// NewFirecrackerDriver creates a stub driver for non-Linux platforms.
func NewFirecrackerDriver(kernelPath, rootDrive, jailerPath string) *FirecrackerDriver {
	jailerCfg := FirecrackerJailerConfig{}
	if jailerPath != "" {
		jailerCfg.Enabled = true
		jailerCfg.BinaryPath = jailerPath
	}
	return NewFirecrackerDriverWithConfig(kernelPath, rootDrive, jailerCfg)
}

// NewFirecrackerDriverWithConfig creates a stub driver for non-Linux platforms.
func NewFirecrackerDriverWithConfig(kernelPath, rootDrive string, jailerCfg FirecrackerJailerConfig) *FirecrackerDriver {
	return &FirecrackerDriver{
		kernelPath: kernelPath,
		rootDrive:  rootDrive,
		jailer:     jailerCfg,
	}
}

func (d *FirecrackerDriver) Start(_ context.Context, _ VMSpec) (VMHandle, error) {
	return VMHandle{}, fmt.Errorf("%w: firecracker requires linux host", ErrDriverFailure)
}

func (d *FirecrackerDriver) Stop(_ context.Context, _ string) error {
	return fmt.Errorf("%w: firecracker requires linux host", ErrDriverFailure)
}

func (d *FirecrackerDriver) IsHealthy(_ context.Context, _ string) (bool, error) {
	return false, fmt.Errorf("%w: firecracker requires linux host", ErrDriverFailure)
}

func (d *FirecrackerDriver) Cleanup(_ context.Context, _ string) error {
	return fmt.Errorf("%w: firecracker requires linux host", ErrDriverFailure)
}
