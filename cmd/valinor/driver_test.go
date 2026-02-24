package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/platform/config"
)

func TestSelectVMDriver_MockAllowedInDevMode(t *testing.T) {
	driver, err := selectVMDriver(config.OrchestratorConfig{Driver: "mock"}, true)
	require.NoError(t, err)
	_, ok := driver.(*orchestrator.MockDriver)
	assert.True(t, ok)
}

func TestSelectVMDriver_MockRejectedOutsideDevMode(t *testing.T) {
	_, err := selectVMDriver(config.OrchestratorConfig{Driver: "mock"}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only allowed in dev mode")
}

func TestSelectVMDriver_UnknownDriver(t *testing.T) {
	_, err := selectVMDriver(config.OrchestratorConfig{Driver: "unknown"}, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported orchestrator driver")
}

func TestSelectVMDriver_FirecrackerPlatformAndConfig(t *testing.T) {
	cfg := config.OrchestratorConfig{
		Driver: "firecracker",
	}

	if runtime.GOOS != "linux" {
		driver, err := selectVMDriver(cfg, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires linux host")
		assert.Nil(t, driver)
		return
	}

	tmp := t.TempDir()
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")
	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	t.Setenv("VALINOR_FIRECRACKER_BIN", "true")
	cfg.Firecracker = config.FirecrackerConfig{
		KernelPath: kernelPath,
		RootDrive:  rootDrive,
		Jailer: config.JailerConfig{
			Enabled:       true,
			BinaryPath:    "true",
			ChrootBaseDir: filepath.Join(tmp, "jailer"),
			UID:           1001,
			GID:           1001,
			NetNSPath:     "/var/run/netns/valinor",
		},
		Network: config.FirecrackerNetworkConfig{
			Policy: "outbound_only",
		},
	}

	driver, err := selectVMDriver(cfg, false)
	require.NoError(t, err)
	require.NotNil(t, driver)
}

func TestSelectVMDriver_FirecrackerMissingPathsOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only validation")
	}

	_, err := selectVMDriver(config.OrchestratorConfig{Driver: "firecracker"}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kernel_path is required")
}

func TestSelectVMDriver_FirecrackerMissingArtifactsOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only validation")
	}

	t.Setenv("VALINOR_FIRECRACKER_BIN", "true")
	_, err := selectVMDriver(config.OrchestratorConfig{
		Driver: "firecracker",
		Firecracker: config.FirecrackerConfig{
			KernelPath: "/tmp/does-not-exist-kernel",
			RootDrive:  "/tmp/does-not-exist-root",
		},
	}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
}

func TestSelectVMDriver_FirecrackerMissingBinaryOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only validation")
	}

	tmp := t.TempDir()
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")
	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	t.Setenv("VALINOR_FIRECRACKER_BIN", "definitely-not-a-real-firecracker-bin")
	_, err := selectVMDriver(config.OrchestratorConfig{
		Driver: "firecracker",
		Firecracker: config.FirecrackerConfig{
			KernelPath: kernelPath,
			RootDrive:  rootDrive,
		},
	}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found in PATH")
}

func TestSelectVMDriver_FirecrackerJailerEnabledOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only validation")
	}

	tmp := t.TempDir()
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")
	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	t.Setenv("VALINOR_FIRECRACKER_BIN", "true")
	driver, err := selectVMDriver(config.OrchestratorConfig{
		Driver: "firecracker",
		Firecracker: config.FirecrackerConfig{
			KernelPath: kernelPath,
			RootDrive:  rootDrive,
			Jailer: config.JailerConfig{
				Enabled:       true,
				BinaryPath:    "true",
				ChrootBaseDir: filepath.Join(tmp, "jailer"),
				UID:           1001,
				GID:           1001,
				NetNSPath:     "/var/run/netns/valinor",
			},
		},
	}, false)
	require.NoError(t, err)
	require.NotNil(t, driver)
}

func TestSelectVMDriver_FirecrackerJailerMissingChrootOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only validation")
	}

	tmp := t.TempDir()
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")
	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	t.Setenv("VALINOR_FIRECRACKER_BIN", "true")
	_, err := selectVMDriver(config.OrchestratorConfig{
		Driver: "firecracker",
		Firecracker: config.FirecrackerConfig{
			KernelPath: kernelPath,
			RootDrive:  rootDrive,
			Jailer: config.JailerConfig{
				Enabled:    true,
				BinaryPath: "true",
				UID:        1001,
				GID:        1001,
			},
		},
	}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chroot_base_dir")
}

func TestSelectVMDriver_FirecrackerJailerDaemonizeOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only validation")
	}

	tmp := t.TempDir()
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")
	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	t.Setenv("VALINOR_FIRECRACKER_BIN", "true")
	driver, err := selectVMDriver(config.OrchestratorConfig{
		Driver: "firecracker",
		Firecracker: config.FirecrackerConfig{
			KernelPath: kernelPath,
			RootDrive:  rootDrive,
			Jailer: config.JailerConfig{
				Enabled:       true,
				BinaryPath:    "true",
				ChrootBaseDir: filepath.Join(tmp, "jailer"),
				UID:           1001,
				GID:           1001,
				NetNSPath:     "/var/run/netns/valinor",
				Daemonize:     true,
			},
		},
	}, false)
	require.NoError(t, err)
	require.NotNil(t, driver)
}

func TestSelectVMDriver_FirecrackerNetworkPolicyRequiresJailerInProd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only validation")
	}

	tmp := t.TempDir()
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")
	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	t.Setenv("VALINOR_FIRECRACKER_BIN", "true")
	_, err := selectVMDriver(config.OrchestratorConfig{
		Driver: "firecracker",
		Firecracker: config.FirecrackerConfig{
			KernelPath: kernelPath,
			RootDrive:  rootDrive,
			Network: config.FirecrackerNetworkConfig{
				Policy: "outbound_only",
			},
		},
	}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires jailer enabled")
}

func TestSelectVMDriver_FirecrackerNetworkPolicyRequiresNetNSInProd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only validation")
	}

	tmp := t.TempDir()
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")
	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	t.Setenv("VALINOR_FIRECRACKER_BIN", "true")
	_, err := selectVMDriver(config.OrchestratorConfig{
		Driver: "firecracker",
		Firecracker: config.FirecrackerConfig{
			KernelPath: kernelPath,
			RootDrive:  rootDrive,
			Jailer: config.JailerConfig{
				Enabled:       true,
				BinaryPath:    "true",
				ChrootBaseDir: filepath.Join(tmp, "jailer"),
				UID:           1001,
				GID:           1001,
			},
			Network: config.FirecrackerNetworkConfig{
				Policy: "outbound_only",
			},
		},
	}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "netns_path is required")
}

func TestSelectVMDriver_FirecrackerRejectsIsolatedNetworkPolicyInProd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only validation")
	}

	tmp := t.TempDir()
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")
	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	t.Setenv("VALINOR_FIRECRACKER_BIN", "true")
	_, err := selectVMDriver(config.OrchestratorConfig{
		Driver: "firecracker",
		Firecracker: config.FirecrackerConfig{
			KernelPath: kernelPath,
			RootDrive:  rootDrive,
			Network: config.FirecrackerNetworkConfig{
				Policy: "isolated",
			},
		},
	}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network policy")
}

func TestSelectVMDriver_FirecrackerAllowsIsolatedNetworkPolicyInDevMode(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only validation")
	}

	tmp := t.TempDir()
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")
	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	t.Setenv("VALINOR_FIRECRACKER_BIN", "true")
	driver, err := selectVMDriver(config.OrchestratorConfig{
		Driver: "firecracker",
		Firecracker: config.FirecrackerConfig{
			KernelPath: kernelPath,
			RootDrive:  rootDrive,
			Network: config.FirecrackerNetworkConfig{
				Policy: "isolated",
			},
		},
	}, true)
	require.NoError(t, err)
	require.NotNil(t, driver)
}

func TestSelectVMDriver_FirecrackerWorkspaceQuotaMustBePositive(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only validation")
	}

	tmp := t.TempDir()
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")
	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	t.Setenv("VALINOR_FIRECRACKER_BIN", "true")
	_, err := selectVMDriver(config.OrchestratorConfig{
		Driver: "firecracker",
		Firecracker: config.FirecrackerConfig{
			KernelPath: kernelPath,
			RootDrive:  rootDrive,
			Workspace: config.FirecrackerWorkspaceConfig{
				Enabled: true,
				QuotaMB: 0,
			},
		},
	}, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workspace quotamb")
}
