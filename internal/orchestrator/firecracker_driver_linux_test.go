//go:build linux

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	firecrackerTestHelperEnv   = "VALINOR_TEST_FIRECRACKER_HELPER"
	firecrackerTestFailPathEnv = "VALINOR_TEST_FIRECRACKER_FAIL_PATH"
	firecrackerRequireSMTEnv   = "VALINOR_TEST_FIRECRACKER_REQUIRE_SMT"
	firecrackerRequireHTEnv    = "VALINOR_TEST_FIRECRACKER_REQUIRE_HT"
	jailerTestHelperEnv        = "VALINOR_TEST_JAILER_HELPER"
	jailerTestArgsFileEnv      = "VALINOR_TEST_JAILER_ARGS_FILE"
	jailerTestChildEnv         = "VALINOR_TEST_JAILER_CHILD"
	jailerTestChildSockEnv     = "VALINOR_TEST_JAILER_CHILD_SOCK"
	jailerTestChildPIDFileEnv  = "VALINOR_TEST_JAILER_CHILD_PIDFILE"
)

func TestMain(m *testing.M) {
	if os.Getenv(firecrackerTestHelperEnv) == "1" {
		os.Exit(runFakeFirecracker())
	}
	if os.Getenv(jailerTestHelperEnv) == "1" {
		if os.Getenv(jailerTestChildEnv) == "1" {
			os.Exit(runFakeJailerChild())
		}
		os.Exit(runFakeJailer())
	}
	os.Exit(m.Run())
}

func TestFirecrackerDriver_StartStopCleanup(t *testing.T) {
	t.Setenv("VALINOR_FIRECRACKER_BIN", os.Args[0])
	t.Setenv(firecrackerTestHelperEnv, "1")

	tmp := shortTempDir(t)
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")

	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	driver := NewFirecrackerDriver(kernelPath, rootDrive, "")
	driver.stateRoot = filepath.Join(tmp, "state")
	driver.socketWaitTimeout = 2 * time.Second
	driver.stopTimeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	handle, err := driver.Start(ctx, VMSpec{
		VMID:     "vm-firecracker-ok",
		VsockCID: 33,
	})
	require.NoError(t, err)
	assert.Equal(t, "vm-firecracker-ok", handle.ID)
	assert.Equal(t, uint32(33), handle.VsockCID)
	assert.NotZero(t, handle.PID)

	healthy, err := driver.IsHealthy(ctx, "vm-firecracker-ok")
	require.NoError(t, err)
	assert.True(t, healthy)

	require.NoError(t, driver.Stop(ctx, "vm-firecracker-ok"))

	healthy, err = driver.IsHealthy(ctx, "vm-firecracker-ok")
	require.Error(t, err)
	assert.False(t, healthy)

	require.NoError(t, driver.Cleanup(ctx, "vm-firecracker-ok"))

	_, statErr := os.Stat(filepath.Join(driver.stateRoot, "vm-firecracker-ok"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestFirecrackerDriver_StartFailsWhenMachineConfigRejected(t *testing.T) {
	t.Setenv("VALINOR_FIRECRACKER_BIN", os.Args[0])
	t.Setenv(firecrackerTestHelperEnv, "1")
	t.Setenv(firecrackerTestFailPathEnv, "/machine-config")

	tmp := shortTempDir(t)
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")

	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	driver := NewFirecrackerDriver(kernelPath, rootDrive, "")
	driver.stateRoot = filepath.Join(tmp, "state")
	driver.socketWaitTimeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := driver.Start(ctx, VMSpec{
		VMID:     "vm-firecracker-fail",
		VsockCID: 44,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configuring machine")

	_, statErr := os.Stat(filepath.Join(driver.stateRoot, "vm-firecracker-fail"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestFirecrackerDriver_StartRejectsInvalidVMID(t *testing.T) {
	t.Setenv("VALINOR_FIRECRACKER_BIN", os.Args[0])
	t.Setenv(firecrackerTestHelperEnv, "1")

	tmp := shortTempDir(t)
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")

	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	driver := NewFirecrackerDriver(kernelPath, rootDrive, "")
	driver.stateRoot = filepath.Join(tmp, "state")
	driver.socketWaitTimeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := driver.Start(ctx, VMSpec{
		VMID:     "../escape",
		VsockCID: 50,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid vm id")
}

func TestFirecrackerDriver_StartRejectsUnsafePathOverrides(t *testing.T) {
	t.Setenv("VALINOR_FIRECRACKER_BIN", os.Args[0])
	t.Setenv(firecrackerTestHelperEnv, "1")

	tmp := shortTempDir(t)
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")

	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	driver := NewFirecrackerDriver(kernelPath, rootDrive, "")
	driver.stateRoot = filepath.Join(tmp, "state")
	driver.socketWaitTimeout = 2 * time.Second

	tests := []struct {
		name    string
		spec    VMSpec
		errLike string
	}{
		{
			name: "relative kernel path",
			spec: VMSpec{
				VMID:       "vm-relative-kernel",
				VsockCID:   51,
				KernelPath: "relative-kernel",
			},
			errLike: "kernel path must be an absolute file path",
		},
		{
			name: "relative root drive path",
			spec: VMSpec{
				VMID:      "vm-relative-root",
				VsockCID:  52,
				RootDrive: "relative-root",
			},
			errLike: "root drive path must be an absolute file path",
		},
		{
			name: "relative data drive path",
			spec: VMSpec{
				VMID:      "vm-relative-data",
				VsockCID:  53,
				DataDrive: "relative-data",
			},
			errLike: "data drive path must be an absolute file path",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err := driver.Start(ctx, tc.spec)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errLike)
		})
	}
}

func TestFirecrackerDriver_ManagementRejectsInvalidVMID(t *testing.T) {
	tmp := shortTempDir(t)
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")

	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	driver := NewFirecrackerDriver(kernelPath, rootDrive, "")

	_, healthyErr := driver.IsHealthy(context.Background(), "../bad-id")
	require.Error(t, healthyErr)
	assert.Contains(t, healthyErr.Error(), "invalid vm id")

	stopErr := driver.Stop(context.Background(), "../bad-id")
	require.Error(t, stopErr)
	assert.Contains(t, stopErr.Error(), "invalid vm id")

	cleanupErr := driver.Cleanup(context.Background(), "../bad-id")
	require.Error(t, cleanupErr)
	assert.Contains(t, cleanupErr.Error(), "invalid vm id")
}

func TestFirecrackerDriver_StartUsesSMTMachineConfigWhenRequired(t *testing.T) {
	t.Setenv("VALINOR_FIRECRACKER_BIN", os.Args[0])
	t.Setenv(firecrackerTestHelperEnv, "1")
	t.Setenv(firecrackerRequireSMTEnv, "1")

	tmp := shortTempDir(t)
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")

	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	driver := NewFirecrackerDriver(kernelPath, rootDrive, "")
	driver.stateRoot = filepath.Join(tmp, "state")
	driver.socketWaitTimeout = 2 * time.Second
	driver.stopTimeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := driver.Start(ctx, VMSpec{
		VMID:     "vm-firecracker-require-smt",
		VsockCID: 45,
	})
	require.NoError(t, err)
	require.NoError(t, driver.Stop(ctx, "vm-firecracker-require-smt"))
	require.NoError(t, driver.Cleanup(ctx, "vm-firecracker-require-smt"))
}

func TestFirecrackerDriver_StartAutoCreatesQuotaDataDrive(t *testing.T) {
	t.Setenv("VALINOR_FIRECRACKER_BIN", os.Args[0])
	t.Setenv(firecrackerTestHelperEnv, "1")

	tmp := shortTempDir(t)
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")

	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	driver := NewFirecrackerDriver(kernelPath, rootDrive, "")
	driver.stateRoot = filepath.Join(tmp, "state")
	driver.socketWaitTimeout = 2 * time.Second
	driver.stopTimeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := driver.Start(ctx, VMSpec{
		VMID:             "vm-firecracker-auto-data",
		VsockCID:         56,
		DataDriveQuotaMB: 4,
	})
	require.NoError(t, err)

	dataDrivePath := filepath.Join(driver.stateRoot, "vm-firecracker-auto-data", "data.ext4")
	info, err := os.Stat(dataDrivePath)
	require.NoError(t, err)
	assert.Equal(t, int64(4*1024*1024), info.Size())

	require.NoError(t, driver.Stop(ctx, "vm-firecracker-auto-data"))
	require.NoError(t, driver.Cleanup(ctx, "vm-firecracker-auto-data"))
}

func TestFirecrackerDriver_StartFailsWhenNetworkInterfaceRejected(t *testing.T) {
	t.Setenv("VALINOR_FIRECRACKER_BIN", "true")
	t.Setenv(jailerTestHelperEnv, "1")
	t.Setenv(firecrackerTestFailPathEnv, "/network-interfaces/eth0")

	tmp := shortTempDir(t)
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")

	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	driver := NewFirecrackerDriverWithConfig(kernelPath, rootDrive, FirecrackerJailerConfig{
		Enabled:       true,
		BinaryPath:    os.Args[0],
		ChrootBaseDir: filepath.Join(tmp, "jailer"),
		UID:           1001,
		GID:           1001,
		NetNSPath:     "/var/run/netns/valinor",
		NetworkPolicy: "outbound_only",
		TapDevice:     "tap0",
	})
	driver.stateRoot = filepath.Join(tmp, "state")
	driver.socketWaitTimeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := driver.Start(ctx, VMSpec{
		VMID:     "vm-firecracker-net-reject",
		VsockCID: 57,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configuring network interface")
}

func TestCreateSparseDataDrive_RejectsNonPositiveQuota(t *testing.T) {
	err := createSparseDataDrive("/tmp/data.ext4", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "quota must be > 0")
}

func TestCreateSparseDataDrive_RejectsRelativePath(t *testing.T) {
	err := createSparseDataDrive("relative/data.ext4", 4)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
}

func TestCreateSparseDataDrive_RejectsQuotaAboveMaximum(t *testing.T) {
	err := createSparseDataDrive("/tmp/data.ext4", maxDataDriveQuotaMB+1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be <=")
}

func TestCreateSparseDataDrive_FailsInNonWritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission test is not meaningful as root")
	}

	tmp := shortTempDir(t)
	readOnlyDir := filepath.Join(tmp, "readonly")
	require.NoError(t, os.MkdirAll(readOnlyDir, 0o500))

	err := createSparseDataDrive(filepath.Join(readOnlyDir, "data.ext4"), 4)
	require.Error(t, err)
}

func TestFirecrackerDriver_StartStopCleanup_WithJailer(t *testing.T) {
	tmp := shortTempDir(t)
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")
	argsPath := filepath.Join(tmp, "jailer.args")
	firecrackerPath, err := exec.LookPath("true")
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	t.Setenv("VALINOR_FIRECRACKER_BIN", "true")
	t.Setenv(jailerTestHelperEnv, "1")
	t.Setenv(jailerTestArgsFileEnv, argsPath)

	driver := NewFirecrackerDriverWithConfig(kernelPath, rootDrive, FirecrackerJailerConfig{
		Enabled:       true,
		BinaryPath:    os.Args[0],
		ChrootBaseDir: filepath.Join(tmp, "jailer"),
		UID:           1001,
		GID:           1001,
	})
	driver.stateRoot = filepath.Join(tmp, "state")
	driver.socketWaitTimeout = 2 * time.Second
	driver.stopTimeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	handle, err := driver.Start(ctx, VMSpec{
		VMID:     "vm-firecracker-jailer",
		VsockCID: 46,
	})
	require.NoError(t, err)
	assert.Equal(t, "vm-firecracker-jailer", handle.ID)
	assert.Equal(t, uint32(46), handle.VsockCID)

	healthy, err := driver.IsHealthy(ctx, "vm-firecracker-jailer")
	require.NoError(t, err)
	assert.True(t, healthy)

	require.NoError(t, driver.Stop(ctx, "vm-firecracker-jailer"))
	require.NoError(t, driver.Cleanup(ctx, "vm-firecracker-jailer"))

	argsBytes, err := os.ReadFile(argsPath)
	require.NoError(t, err)
	argsStr := string(argsBytes)
	assert.Contains(t, argsStr, "--id")
	assert.Contains(t, argsStr, "vm-firecracker-jailer")
	assert.Contains(t, argsStr, "--uid")
	assert.Contains(t, argsStr, "1001")
	assert.Contains(t, argsStr, "--gid")
	assert.Contains(t, argsStr, "--chroot-base-dir")
	assert.Contains(t, argsStr, firecrackerPath)
	assert.Contains(t, argsStr, "--api-sock")
}

func TestFirecrackerDriver_StartStopCleanup_WithJailerDaemonize(t *testing.T) {
	tmp := shortTempDir(t)
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")
	argsPath := filepath.Join(tmp, "jailer-daemonize.args")

	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	t.Setenv("VALINOR_FIRECRACKER_BIN", "true")
	t.Setenv(jailerTestHelperEnv, "1")
	t.Setenv(jailerTestArgsFileEnv, argsPath)

	driver := NewFirecrackerDriverWithConfig(kernelPath, rootDrive, FirecrackerJailerConfig{
		Enabled:       true,
		BinaryPath:    os.Args[0],
		ChrootBaseDir: filepath.Join(tmp, "jailer"),
		UID:           1001,
		GID:           1001,
		Daemonize:     true,
	})
	driver.stateRoot = filepath.Join(tmp, "state")
	driver.socketWaitTimeout = 2 * time.Second
	driver.stopTimeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	handle, err := driver.Start(ctx, VMSpec{
		VMID:     "vm-firecracker-jailer-daemon",
		VsockCID: 47,
	})
	require.NoError(t, err)
	assert.Equal(t, "vm-firecracker-jailer-daemon", handle.ID)
	assert.Equal(t, uint32(47), handle.VsockCID)
	assert.True(t, handle.PID > 0)

	healthy, err := driver.IsHealthy(ctx, "vm-firecracker-jailer-daemon")
	require.NoError(t, err)
	assert.True(t, healthy)

	require.NoError(t, driver.Stop(ctx, "vm-firecracker-jailer-daemon"))
	require.NoError(t, driver.Cleanup(ctx, "vm-firecracker-jailer-daemon"))

	argsBytes, err := os.ReadFile(argsPath)
	require.NoError(t, err)
	argsStr := string(argsBytes)
	assert.Contains(t, argsStr, "--daemonize")
	assert.Contains(t, argsStr, "--api-sock")
}

func TestFirecrackerDriver_ReattachDaemonizedJailerAfterDriverRestart(t *testing.T) {
	tmp := shortTempDir(t)
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")

	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	t.Setenv("VALINOR_FIRECRACKER_BIN", "true")
	t.Setenv(jailerTestHelperEnv, "1")

	jailerCfg := FirecrackerJailerConfig{
		Enabled:       true,
		BinaryPath:    os.Args[0],
		ChrootBaseDir: filepath.Join(tmp, "jailer"),
		UID:           1001,
		GID:           1001,
		Daemonize:     true,
	}
	stateRoot := filepath.Join(tmp, "state")

	driver1 := NewFirecrackerDriverWithConfig(kernelPath, rootDrive, jailerCfg)
	driver1.stateRoot = stateRoot
	driver1.socketWaitTimeout = 2 * time.Second
	driver1.stopTimeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := driver1.Start(ctx, VMSpec{
		VMID:     "vm-firecracker-reattach",
		VsockCID: 48,
	})
	require.NoError(t, err)

	driver2 := NewFirecrackerDriverWithConfig(kernelPath, rootDrive, jailerCfg)
	driver2.stateRoot = stateRoot
	driver2.socketWaitTimeout = 2 * time.Second
	driver2.stopTimeout = 2 * time.Second

	healthy, err := driver2.IsHealthy(ctx, "vm-firecracker-reattach")
	require.NoError(t, err)
	assert.True(t, healthy)

	require.NoError(t, driver2.Stop(ctx, "vm-firecracker-reattach"))
	require.NoError(t, driver2.Cleanup(ctx, "vm-firecracker-reattach"))

	_, statErr := os.Stat(filepath.Join(stateRoot, "vm-firecracker-reattach"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestFirecrackerDriver_CleanupDaemonizedJailerAfterDriverRestart(t *testing.T) {
	tmp := shortTempDir(t)
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")

	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	t.Setenv("VALINOR_FIRECRACKER_BIN", "true")
	t.Setenv(jailerTestHelperEnv, "1")

	jailerCfg := FirecrackerJailerConfig{
		Enabled:       true,
		BinaryPath:    os.Args[0],
		ChrootBaseDir: filepath.Join(tmp, "jailer"),
		UID:           1001,
		GID:           1001,
		Daemonize:     true,
	}
	stateRoot := filepath.Join(tmp, "state")

	driver1 := NewFirecrackerDriverWithConfig(kernelPath, rootDrive, jailerCfg)
	driver1.stateRoot = stateRoot
	driver1.socketWaitTimeout = 2 * time.Second
	driver1.stopTimeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := driver1.Start(ctx, VMSpec{
		VMID:     "vm-firecracker-cleanup-reattach",
		VsockCID: 49,
	})
	require.NoError(t, err)
	require.NoError(t, driver1.Stop(ctx, "vm-firecracker-cleanup-reattach"))

	driver2 := NewFirecrackerDriverWithConfig(kernelPath, rootDrive, jailerCfg)
	driver2.stateRoot = stateRoot
	driver2.socketWaitTimeout = 2 * time.Second
	driver2.stopTimeout = 2 * time.Second

	require.NoError(t, driver2.Cleanup(ctx, "vm-firecracker-cleanup-reattach"))

	_, statErr := os.Stat(filepath.Join(stateRoot, "vm-firecracker-cleanup-reattach"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestFirecrackerDriver_CleanupPersistedNonDaemonizedStateDoesNotKillPID(t *testing.T) {
	tmp := shortTempDir(t)
	kernelPath := filepath.Join(tmp, "vmlinux")
	rootDrive := filepath.Join(tmp, "rootfs.ext4")
	require.NoError(t, os.WriteFile(kernelPath, []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(rootDrive, []byte("rootfs"), 0o644))

	sleeper := exec.CommandContext(context.Background(), "sleep", "60")
	require.NoError(t, sleeper.Start())
	t.Cleanup(func() {
		if sleeper.Process != nil {
			_ = sleeper.Process.Kill()
		}
		_ = sleeper.Wait()
	})

	driver := NewFirecrackerDriver(kernelPath, rootDrive, "")
	driver.stateRoot = filepath.Join(tmp, "state")

	vmID := "vm-cleanup-non-daemonized"
	vmStateDir := filepath.Join(driver.stateRoot, vmID)
	require.NoError(t, os.MkdirAll(vmStateDir, 0o755))

	state := firecrackerVMPersistedState{
		VMID:           vmID,
		StateDir:       vmStateDir,
		APISock:        filepath.Join(vmStateDir, "api.sock"),
		FirecrackerPID: sleeper.Process.Pid,
		Daemonized:     false,
	}
	encoded, err := json.Marshal(state)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(vmStateDir, defaultVMStateFileName), encoded, 0o644))

	require.NoError(t, driver.Cleanup(context.Background(), vmID))

	alive, err := processAlive(sleeper.Process.Pid)
	require.NoError(t, err)
	assert.True(t, alive, "cleanup must not signal persisted non-daemonized PID")

	_, statErr := os.Stat(vmStateDir)
	assert.True(t, os.IsNotExist(statErr))
}

func runFakeFirecracker() int {
	apiSock := ""
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "--api-sock" && i+1 < len(os.Args) {
			apiSock = os.Args[i+1]
			break
		}
	}

	if strings.TrimSpace(apiSock) == "" {
		fmt.Fprintln(os.Stderr, "missing --api-sock")
		return 2
	}

	if err := os.MkdirAll(filepath.Dir(apiSock), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "creating socket dir: %v\n", err)
		return 2
	}
	_ = os.Remove(apiSock)

	lc := net.ListenConfig{}
	lis, err := lc.Listen(context.Background(), "unix", apiSock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listening on unix socket: %v\n", err)
		return 2
	}
	defer lis.Close()

	failPath := os.Getenv(firecrackerTestFailPathEnv)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failPath != "" && r.URL.Path == failPath {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		switch r.Method + " " + r.URL.Path {
		case "PUT /machine-config",
			"PUT /boot-source",
			"PUT /drives/rootfs",
			"PUT /drives/data",
			"PUT /network-interfaces/eth0",
			"PUT /vsock",
			"PUT /actions":
			if r.Method == http.MethodPut && r.URL.Path == "/machine-config" {
				body, _ := io.ReadAll(r.Body)
				bodyStr := string(body)
				requireSMT := os.Getenv(firecrackerRequireSMTEnv) == "1"
				requireHT := os.Getenv(firecrackerRequireHTEnv) == "1"
				if requireSMT && !strings.Contains(bodyStr, "\"smt\"") {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"fault_message":"missing smt field"}`))
					return
				}
				if requireHT && !strings.Contains(bodyStr, "\"ht_enabled\"") {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"fault_message":"missing ht_enabled field"}`))
					return
				}
			}
			w.WriteHeader(http.StatusNoContent)
			return
		case "GET /machine-config":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"vcpu_count":1,"mem_size_mib":256}`))
			return
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
	})

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "serving fake firecracker api: %v\n", err)
		return 2
	}
	return 0
}

func runFakeJailer() int {
	id, ok := findArgValue(os.Args[1:], "--id")
	if !ok {
		fmt.Fprintln(os.Stderr, "missing --id")
		return 2
	}
	execFile, ok := findArgValue(os.Args[1:], "--exec-file")
	if !ok {
		fmt.Fprintln(os.Stderr, "missing --exec-file")
		return 2
	}
	chrootBase, ok := findArgValue(os.Args[1:], "--chroot-base-dir")
	if !ok {
		fmt.Fprintln(os.Stderr, "missing --chroot-base-dir")
		return 2
	}
	if uid, ok := findArgValue(os.Args[1:], "--uid"); !ok || uid == "" {
		fmt.Fprintln(os.Stderr, "missing --uid")
		return 2
	}
	if gid, ok := findArgValue(os.Args[1:], "--gid"); !ok || gid == "" {
		fmt.Fprintln(os.Stderr, "missing --gid")
		return 2
	}

	guestSock := "/run/firecracker.socket"
	if idx := indexOf(os.Args, "--"); idx != -1 {
		if sock, ok := findArgValue(os.Args[idx+1:], "--api-sock"); ok {
			guestSock = sock
		}
	}

	jailerDir := filepath.Join(chrootBase, filepath.Base(execFile), id)
	jailRoot := filepath.Join(jailerDir, "root")
	hostSock := filepath.Join(jailRoot, strings.TrimPrefix(guestSock, "/"))
	if argsFile := strings.TrimSpace(os.Getenv(jailerTestArgsFileEnv)); argsFile != "" {
		_ = os.WriteFile(argsFile, []byte(strings.Join(os.Args[1:], "\n")), 0o644)
	}

	pidPath := filepath.Join(jailRoot, defaultJailerPIDFileName)
	if indexOf(os.Args[1:], "--daemonize") != -1 {
		child := exec.CommandContext(context.Background(), os.Args[0])
		child.Env = append(os.Environ(),
			jailerTestHelperEnv+"=1",
			jailerTestChildEnv+"=1",
			jailerTestChildSockEnv+"="+hostSock,
			jailerTestChildPIDFileEnv+"="+pidPath,
		)
		if err := child.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "starting fake daemonized jailer child: %v\n", err)
			return 2
		}
		return 0
	}

	return runFakeJailerServer(hostSock, pidPath)
}

func runFakeJailerChild() int {
	hostSock := strings.TrimSpace(os.Getenv(jailerTestChildSockEnv))
	pidPath := strings.TrimSpace(os.Getenv(jailerTestChildPIDFileEnv))
	if hostSock == "" || pidPath == "" {
		fmt.Fprintln(os.Stderr, "missing child jailer socket/pidfile env")
		return 2
	}
	return runFakeJailerServer(hostSock, pidPath)
}

func runFakeJailerServer(hostSock, pidPath string) int {
	if err := os.MkdirAll(filepath.Dir(hostSock), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "creating socket dir: %v\n", err)
		return 2
	}
	if err := os.MkdirAll(filepath.Dir(pidPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "creating pid dir: %v\n", err)
		return 2
	}
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", os.Getpid())), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "writing pid file: %v\n", err)
		return 2
	}

	_ = os.Remove(hostSock)

	lc := net.ListenConfig{}
	lis, err := lc.Listen(context.Background(), "unix", hostSock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listening on jailed socket: %v\n", err)
		return 2
	}
	defer lis.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "PUT /machine-config",
			"PUT /boot-source",
			"PUT /drives/rootfs",
			"PUT /drives/data",
			"PUT /network-interfaces/eth0",
			"PUT /vsock",
			"PUT /actions":
			w.WriteHeader(http.StatusNoContent)
			return
		case "GET /machine-config":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"vcpu_count":1,"mem_size_mib":256}`))
			return
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
	})

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "serving fake jailer api: %v\n", err)
		return 2
	}
	return 0
}

func findArgValue(args []string, key string) (string, bool) {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key {
			return args[i+1], true
		}
	}
	return "", false
}

func indexOf(args []string, needle string) int {
	for i, arg := range args {
		if arg == needle {
			return i
		}
	}
	return -1
}

func shortTempDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "val-fc-")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}
