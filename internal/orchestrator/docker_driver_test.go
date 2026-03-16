package orchestrator_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/FredAmartey/heimdall/internal/orchestrator"
)

// requireDocker skips the test if Docker daemon is not available or the test
// image cannot be pulled. These are integration tests requiring Docker.
func requireDocker(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping Docker integration test in short mode")
	}
	if err := exec.CommandContext(context.Background(), "docker", "info").Run(); err != nil {
		t.Skip("skipping: Docker daemon not available")
	}
	// Ensure the test image is available (pull if needed).
	if err := exec.CommandContext(context.Background(), "docker", "image", "inspect", "alpine:latest").Run(); err != nil {
		t.Log("pulling alpine:latest for Docker integration tests...")
		if pullErr := exec.CommandContext(context.Background(), "docker", "pull", "alpine:latest").Run(); pullErr != nil {
			t.Skipf("skipping: cannot pull alpine:latest: %v", pullErr)
		}
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

func TestDockerDriver_PerTenantNetwork(t *testing.T) {
	requireDocker(t)

	driver := orchestrator.NewDockerDriver(orchestrator.DockerDriverConfig{
		Image:           "alpine:latest",
		NetworkMode:     "per-tenant",
		DefaultCPUs:     1,
		DefaultMemoryMB: 128,
		Cmd:             []string{"sleep", "30"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := orchestrator.VMSpec{
		VMID:     "test-net-iso",
		TenantID: "tenant-abc",
		VsockCID: 200,
	}

	handle, err := driver.Start(ctx, spec)
	require.NoError(t, err)
	require.NotEmpty(t, handle.ID)

	// Cleanup
	require.NoError(t, driver.Stop(ctx, spec.VMID))
	require.NoError(t, driver.Cleanup(ctx, spec.VMID))
}

func TestDockerDriver_NoNetworkForWarmVM(t *testing.T) {
	requireDocker(t)

	driver := orchestrator.NewDockerDriver(orchestrator.DockerDriverConfig{
		Image:           "alpine:latest",
		NetworkMode:     "per-tenant",
		DefaultCPUs:     1,
		DefaultMemoryMB: 128,
		Cmd:             []string{"sleep", "30"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Warm VM has no tenant — should still start successfully
	spec := orchestrator.VMSpec{
		VMID:     "test-warm-no-net",
		VsockCID: 201,
	}

	handle, err := driver.Start(ctx, spec)
	require.NoError(t, err)
	require.NotEmpty(t, handle.ID)

	require.NoError(t, driver.Stop(ctx, spec.VMID))
	require.NoError(t, driver.Cleanup(ctx, spec.VMID))
}

func TestDockerDriver_MemoryVolumeMounts(t *testing.T) {
	requireDocker(t)

	memBase := t.TempDir()
	driver := orchestrator.NewDockerDriver(orchestrator.DockerDriverConfig{
		Image:           "alpine:latest",
		NetworkMode:     "none",
		DefaultCPUs:     1,
		DefaultMemoryMB: 128,
		MemoryBasePath:  memBase,
		Cmd:             []string{"sleep", "30"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := orchestrator.VMSpec{
		VMID:     "test-memory-vols",
		VsockCID: 300,
	}

	handle, err := driver.Start(ctx, spec)
	require.NoError(t, err)
	require.NotEmpty(t, handle.ID)

	// Verify host-side personal memory dir was created
	personalDir := filepath.Join(memBase, spec.VMID, "personal")
	info, err := os.Stat(personalDir)
	require.NoError(t, err)
	require.True(t, info.IsDir())

	require.NoError(t, driver.Stop(ctx, spec.VMID))
	require.NoError(t, driver.Cleanup(ctx, spec.VMID))
}

func TestDockerDriver_MemoryMounts_AllLayers(t *testing.T) {
	requireDocker(t)

	tmpDir := t.TempDir()
	driver := orchestrator.NewDockerDriver(orchestrator.DockerDriverConfig{
		Image:           "alpine:latest",
		NetworkMode:     "none",
		DefaultCPUs:     1,
		DefaultMemoryMB: 64,
		MemoryBasePath:  tmpDir,
		Cmd:             []string{"sleep", "30"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := orchestrator.VMSpec{
		VMID:         "mount-test",
		TenantID:     "tenant-abc",
		UserID:       "user-123",
		DepartmentID: "dept-456",
		VsockCID:     600,
		KnowledgeBases: []orchestrator.KBMount{
			{ID: "kb-001", Name: "transfer-targets"},
			{ID: "kb-002", Name: "playbook"},
		},
	}

	handle, err := driver.Start(ctx, spec)
	require.NoError(t, err)
	defer func() {
		_ = driver.Stop(ctx, spec.VMID)
		_ = driver.Cleanup(ctx, spec.VMID)
	}()
	require.Equal(t, "mount-test", handle.ID)

	// Verify host directories were created
	require.DirExists(t, filepath.Join(tmpDir, "mount-test", "personal"))
	require.DirExists(t, filepath.Join(tmpDir, "departments", "dept-456"))
	require.DirExists(t, filepath.Join(tmpDir, "tenants", "tenant-abc"))
	require.DirExists(t, filepath.Join(tmpDir, "kbs", "kb-001"))
	require.DirExists(t, filepath.Join(tmpDir, "kbs", "kb-002"))

	// NOTE: ReadOnly flags (personal=rw, dept/tenant/shared=ro) are set on the
	// Docker mount config but cannot be asserted without inspecting the running
	// container's mount table, which requires Docker daemon access.
}

func TestDockerDriver_MemoryMounts_RejectsInvalidKBName(t *testing.T) {
	requireDocker(t)

	tmpDir := t.TempDir()
	driver := orchestrator.NewDockerDriver(orchestrator.DockerDriverConfig{
		Image:           "alpine:latest",
		NetworkMode:     "none",
		DefaultCPUs:     1,
		DefaultMemoryMB: 64,
		MemoryBasePath:  tmpDir,
		Cmd:             []string{"sleep", "30"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	badNames := []string{
		"../personal",
		"foo/bar",
		"foo\\bar",
		"..",
		".",
		"",
	}

	for _, name := range badNames {
		t.Run("name="+name, func(t *testing.T) {
			spec := orchestrator.VMSpec{
				VMID:     "kb-name-test",
				VsockCID: 700,
				KnowledgeBases: []orchestrator.KBMount{
					{ID: "kb-bad", Name: name},
				},
			}
			_, err := driver.Start(ctx, spec)
			require.Error(t, err, "expected error for KB name %q", name)
			require.Contains(t, err.Error(), "invalid knowledge base name")
		})
	}
}

func TestDockerDriver_NoMemoryMountsWithoutBasePath(t *testing.T) {
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
		VMID:     "test-no-memory",
		VsockCID: 301,
	}

	// Should succeed without memory base path — no mounts added
	handle, err := driver.Start(ctx, spec)
	require.NoError(t, err)
	require.NotEmpty(t, handle.ID)

	require.NoError(t, driver.Stop(ctx, spec.VMID))
	require.NoError(t, driver.Cleanup(ctx, spec.VMID))
}
