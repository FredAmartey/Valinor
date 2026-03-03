package orchestrator_test

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/orchestrator"
)

// requireDocker skips the test if Docker daemon is not available.
func requireDocker(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping Docker integration test in short mode")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("skipping: Docker daemon not available")
	}
}

// TestDockerDriver_Start_Integration requires Docker daemon.
func TestDockerDriver_Start_Integration(t *testing.T) {
	requireDocker(t)

	driver := orchestrator.NewDockerDriver(orchestrator.DockerDriverConfig{
		Image:           "alpine:latest",
		NetworkMode:     "none",
		DefaultCPUs:     1,
		DefaultMemoryMB: 128,
		Cmd:             []string{"sleep", "30"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := orchestrator.VMSpec{
		VMID:     "test-docker-start",
		VsockCID: 100,
	}

	handle, err := driver.Start(ctx, spec)
	require.NoError(t, err)
	require.Equal(t, spec.VMID, handle.ID)
	require.Equal(t, spec.VsockCID, handle.VsockCID)
	require.True(t, handle.PID > 0, "expected non-zero PID")
	require.False(t, handle.StartedAt.IsZero())

	// Verify container is running
	healthy, err := driver.IsHealthy(ctx, spec.VMID)
	require.NoError(t, err)
	require.True(t, healthy)

	// Cleanup
	require.NoError(t, driver.Stop(ctx, spec.VMID))
	require.NoError(t, driver.Cleanup(ctx, spec.VMID))
}
