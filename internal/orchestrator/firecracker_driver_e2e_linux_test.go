//go:build linux

package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFirecrackerDriver_RealBinaryLifecycle exercises the real Firecracker binary.
// It is intentionally opt-in to keep CI portable.
func TestFirecrackerDriver_RealBinaryLifecycle(t *testing.T) {
	if os.Getenv("VALINOR_FIRECRACKER_E2E") != "1" {
		t.Skip("set VALINOR_FIRECRACKER_E2E=1 to run real Firecracker e2e")
	}

	kernelPath := os.Getenv("VALINOR_FIRECRACKER_KERNEL_PATH")
	rootDrive := os.Getenv("VALINOR_FIRECRACKER_ROOT_DRIVE")
	if kernelPath == "" || rootDrive == "" {
		t.Skip("set VALINOR_FIRECRACKER_KERNEL_PATH and VALINOR_FIRECRACKER_ROOT_DRIVE")
	}

	driver := NewFirecrackerDriver(kernelPath, rootDrive, "")
	driver.stateRoot = filepath.Join(t.TempDir(), "state")
	driver.socketWaitTimeout = 10 * time.Second
	driver.stopTimeout = 10 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	handle, err := driver.Start(ctx, VMSpec{
		VMID:     "vm-firecracker-real",
		VsockCID: 57,
	})
	require.NoError(t, err)
	assert.Equal(t, "vm-firecracker-real", handle.ID)
	assert.Equal(t, uint32(57), handle.VsockCID)

	healthy, err := driver.IsHealthy(ctx, "vm-firecracker-real")
	require.NoError(t, err)
	assert.True(t, healthy)

	require.NoError(t, driver.Stop(ctx, "vm-firecracker-real"))
	require.NoError(t, driver.Cleanup(ctx, "vm-firecracker-real"))
}
