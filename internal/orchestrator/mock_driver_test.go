package orchestrator_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/orchestrator"
)

func TestMockDriver_StartAndHealth(t *testing.T) {
	driver := orchestrator.NewMockDriver()
	ctx := context.Background()

	handle, err := driver.Start(ctx, orchestrator.VMSpec{
		VMID:     "vm-1",
		VsockCID: 3,
	})
	require.NoError(t, err)
	assert.Equal(t, "vm-1", handle.ID)
	assert.Equal(t, uint32(3), handle.VsockCID)

	healthy, err := driver.IsHealthy(ctx, "vm-1")
	require.NoError(t, err)
	assert.True(t, healthy)
}

func TestMockDriver_StopAndCleanup(t *testing.T) {
	driver := orchestrator.NewMockDriver()
	ctx := context.Background()

	_, err := driver.Start(ctx, orchestrator.VMSpec{VMID: "vm-1"})
	require.NoError(t, err)

	err = driver.Stop(ctx, "vm-1")
	require.NoError(t, err)

	healthy, err := driver.IsHealthy(ctx, "vm-1")
	require.NoError(t, err)
	assert.False(t, healthy, "stopped VM should not be healthy")

	err = driver.Cleanup(ctx, "vm-1")
	require.NoError(t, err)

	_, err = driver.IsHealthy(ctx, "vm-1")
	assert.Error(t, err, "cleaned up VM should error")
}

func TestMockDriver_FailureInjection(t *testing.T) {
	driver := orchestrator.NewMockDriver()
	ctx := context.Background()

	_, err := driver.Start(ctx, orchestrator.VMSpec{VMID: "vm-1"})
	require.NoError(t, err)

	driver.SetUnhealthy("vm-1")

	healthy, err := driver.IsHealthy(ctx, "vm-1")
	require.NoError(t, err)
	assert.False(t, healthy)
}
