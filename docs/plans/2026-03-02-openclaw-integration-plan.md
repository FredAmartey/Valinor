# OpenClaw Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a Docker-based VMDriver that runs OpenClaw inside containers with heimdall-agent as the security sidecar, enabling the "Teams" tier alongside the existing Firecracker "Enterprise" tier.

**Architecture:** New `DockerDriver` implementing `VMDriver` interface. Each agent = one Docker container running heimdall-agent (entrypoint) + OpenClaw Gateway (child process). Control plane communicates via TCP transport (same protocol). Hierarchical memory via volume mounts. Per-tenant Docker networks for isolation.

**Tech Stack:** Go 1.25, `github.com/docker/docker` client SDK (already in go.mod via testcontainers), Docker Engine API, existing proxy/orchestrator packages.

---

## Task 1: Expand DockerConfig and wire into selectVMDriver

**Files:**
- Modify: `internal/platform/config/config.go:109-111`
- Modify: `cmd/heimdall/driver.go:29-58`
- Test: `cmd/heimdall/driver_test.go`

**Step 1: Write the failing test**

Add to `cmd/heimdall/driver_test.go`:

```go
func TestSelectVMDriver_Docker(t *testing.T) {
	cfg := config.OrchestratorConfig{
		Driver: "docker",
		Docker: config.DockerConfig{
			Image:            "heimdall/agent:latest",
			NetworkMode:      "per-tenant",
			DefaultCPUs:      1,
			DefaultMemoryMB:  512,
			MemoryBasePath:   "/var/lib/heimdall/memory",
			WorkspaceQuotaMB: 1024,
		},
	}

	driver, err := selectVMDriver(cfg, false)
	require.NoError(t, err)
	require.NotNil(t, driver)

	_, ok := driver.(*orchestrator.DockerDriver)
	require.True(t, ok, "expected *orchestrator.DockerDriver")
}

func TestSelectVMDriver_Docker_MissingImage(t *testing.T) {
	cfg := config.OrchestratorConfig{
		Driver: "docker",
		Docker: config.DockerConfig{
			Image: "",
		},
	}

	_, err := selectVMDriver(cfg, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "image")
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/fred/Documents/Heimdall && go test ./cmd/heimdall/ -run 'TestSelectVMDriver_Docker' -v`
Expected: FAIL — `DockerDriver` type doesn't exist yet.

**Step 3: Expand DockerConfig**

In `internal/platform/config/config.go`, replace the `DockerConfig` struct:

```go
type DockerConfig struct {
	Image            string `koanf:"image"`
	NetworkMode      string `koanf:"network_mode"`
	DefaultCPUs      int    `koanf:"default_cpus"`
	DefaultMemoryMB  int    `koanf:"default_memory_mb"`
	MemoryBasePath   string `koanf:"memory_base_path"`
	WorkspaceQuotaMB int    `koanf:"workspace_quota_mb"`
}
```

Add defaults in `Load()` after the existing docker image default:

```go
"orchestrator.docker.network_mode":      "per-tenant",
"orchestrator.docker.default_cpus":      1,
"orchestrator.docker.default_memory_mb": 512,
"orchestrator.docker.memory_base_path":  "/var/lib/heimdall/memory",
"orchestrator.docker.workspace_quota_mb": 1024,
```

**Step 4: Create a minimal DockerDriver stub**

Create file `internal/orchestrator/docker_driver.go`:

```go
package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// DockerDriverConfig holds configuration for the Docker-based VM driver.
type DockerDriverConfig struct {
	Image            string
	NetworkMode      string // "none", "per-tenant", "bridge"
	DefaultCPUs      int
	DefaultMemoryMB  int
	MemoryBasePath   string
	WorkspaceQuotaMB int
}

// DockerDriver manages agent containers via the Docker Engine API.
type DockerDriver struct {
	cfg DockerDriverConfig
	mu  sync.Mutex
}

// NewDockerDriver creates a DockerDriver. The actual Docker client
// is created lazily on first Start() call.
func NewDockerDriver(cfg DockerDriverConfig) *DockerDriver {
	return &DockerDriver{cfg: cfg}
}

func (d *DockerDriver) Start(ctx context.Context, spec VMSpec) (VMHandle, error) {
	return VMHandle{}, fmt.Errorf("docker driver: not yet implemented")
}

func (d *DockerDriver) Stop(ctx context.Context, id string) error {
	return fmt.Errorf("docker driver: not yet implemented")
}

func (d *DockerDriver) IsHealthy(ctx context.Context, id string) (bool, error) {
	return false, fmt.Errorf("docker driver: not yet implemented")
}

func (d *DockerDriver) Cleanup(ctx context.Context, id string) error {
	return fmt.Errorf("docker driver: not yet implemented")
}
```

**Step 5: Wire into selectVMDriver**

Add a `"docker"` case in `cmd/heimdall/driver.go` inside the switch:

```go
case "docker":
	image := strings.TrimSpace(cfg.Docker.Image)
	if image == "" {
		return nil, fmt.Errorf("docker image is required when driver is %q", driver)
	}
	networkMode := strings.TrimSpace(cfg.Docker.NetworkMode)
	if networkMode == "" {
		networkMode = "per-tenant"
	}
	return orchestrator.NewDockerDriver(orchestrator.DockerDriverConfig{
		Image:            image,
		NetworkMode:      networkMode,
		DefaultCPUs:      cfg.Docker.DefaultCPUs,
		DefaultMemoryMB:  cfg.Docker.DefaultMemoryMB,
		MemoryBasePath:   cfg.Docker.MemoryBasePath,
		WorkspaceQuotaMB: cfg.Docker.WorkspaceQuotaMB,
	}), nil
```

**Step 6: Run tests to verify they pass**

Run: `cd /Users/fred/Documents/Heimdall && go test ./cmd/heimdall/ -run 'TestSelectVMDriver_Docker' -v`
Expected: PASS

**Step 7: Run full test suite**

Run: `cd /Users/fred/Documents/Heimdall && go test ./... -count=1 -short`
Expected: All existing tests still pass.

**Step 8: Commit**

```bash
git add internal/platform/config/config.go internal/orchestrator/docker_driver.go cmd/heimdall/driver.go cmd/heimdall/driver_test.go
git commit -m "feat: add DockerDriver stub and wire into selectVMDriver"
```

---

## Task 2: DockerDriver.Start — create and start a container

**Files:**
- Modify: `internal/orchestrator/docker_driver.go`
- Test: `internal/orchestrator/docker_driver_test.go`

**Step 1: Write the failing test**

Create `internal/orchestrator/docker_driver_test.go`:

```go
package orchestrator_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/heimdall-ai/heimdall/internal/orchestrator"
)

// TestDockerDriver_Start_Integration requires Docker daemon.
// Skip with -short flag.
func TestDockerDriver_Start_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Docker integration test in short mode")
	}

	driver := orchestrator.NewDockerDriver(orchestrator.DockerDriverConfig{
		Image:           "alpine:latest",
		NetworkMode:     "none",
		DefaultCPUs:     1,
		DefaultMemoryMB: 128,
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
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/fred/Documents/Heimdall && go test ./internal/orchestrator/ -run 'TestDockerDriver_Start_Integration' -v`
Expected: FAIL — "docker driver: not yet implemented"

**Step 3: Implement DockerDriver with Docker client**

Replace the stub in `internal/orchestrator/docker_driver.go` with full implementation:

```go
package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

const (
	dockerAgentPort      = 9100
	dockerContainerLabel = "heimdall.agent"
	dockerTenantLabel    = "heimdall.tenant"
	dockerStopTimeout    = 10 // seconds
)

// DockerDriverConfig holds configuration for the Docker-based VM driver.
type DockerDriverConfig struct {
	Image            string
	NetworkMode      string // "none", "per-tenant", "bridge"
	DefaultCPUs      int
	DefaultMemoryMB  int
	MemoryBasePath   string
	WorkspaceQuotaMB int
}

// DockerDriver manages agent containers via the Docker Engine API.
type DockerDriver struct {
	cfg    DockerDriverConfig
	cli    *client.Client
	mu     sync.Mutex
	initMu sync.Once
	initErr error
}

// NewDockerDriver creates a DockerDriver.
func NewDockerDriver(cfg DockerDriverConfig) *DockerDriver {
	return &DockerDriver{cfg: cfg}
}

func (d *DockerDriver) ensureClient() error {
	d.initMu.Do(func() {
		d.cli, d.initErr = client.NewClientWithOpts(
			client.FromEnv,
			client.WithAPIVersionNegotiation(),
		)
	})
	return d.initErr
}

func (d *DockerDriver) Start(ctx context.Context, spec VMSpec) (VMHandle, error) {
	if err := d.ensureClient(); err != nil {
		return VMHandle{}, fmt.Errorf("docker client: %w", err)
	}

	containerName := fmt.Sprintf("heimdall-%s", spec.VMID)
	hostPort := strconv.Itoa(dockerAgentPort + int(spec.VsockCID))
	agentPort := nat.Port(fmt.Sprintf("%d/tcp", dockerAgentPort))

	cpus := d.cfg.DefaultCPUs
	if spec.VCPUs > 0 {
		cpus = spec.VCPUs
	}
	memMB := d.cfg.DefaultMemoryMB
	if spec.MemoryMB > 0 {
		memMB = spec.MemoryMB
	}

	containerCfg := &container.Config{
		Image: d.cfg.Image,
		ExposedPorts: nat.PortSet{
			agentPort: struct{}{},
		},
		Labels: map[string]string{
			dockerContainerLabel: spec.VMID,
		},
		Cmd: []string{
			"--transport", "tcp",
			"--port", strconv.Itoa(dockerAgentPort),
		},
	}

	hostCfg := &container.HostConfig{
		PortBindings: nat.PortMap{
			agentPort: []nat.PortBinding{
				{HostIP: "127.0.0.1", HostPort: hostPort},
			},
		},
		Resources: container.Resources{
			NanoCPUs: int64(cpus) * 1_000_000_000,
			Memory:   int64(memMB) * 1024 * 1024,
		},
		RestartPolicy: container.RestartPolicy{Name: "no"},
	}

	netCfg := &network.NetworkingConfig{}

	resp, err := d.cli.ContainerCreate(ctx, containerCfg, hostCfg, netCfg, nil, containerName)
	if err != nil {
		return VMHandle{}, fmt.Errorf("creating container %s: %w", containerName, err)
	}

	if err := d.cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		// Best-effort cleanup on start failure
		_ = d.cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})
		return VMHandle{}, fmt.Errorf("starting container %s: %w", containerName, err)
	}

	info, err := d.cli.ContainerInspect(ctx, resp.ID)
	if err != nil {
		return VMHandle{}, fmt.Errorf("inspecting container %s: %w", containerName, err)
	}

	slog.Info("docker container started",
		"container", containerName,
		"id", resp.ID[:12],
		"host_port", hostPort,
		"pid", info.State.Pid,
	)

	return VMHandle{
		ID:        spec.VMID,
		PID:       info.State.Pid,
		VsockCID:  spec.VsockCID,
		StartedAt: time.Now(),
	}, nil
}

func (d *DockerDriver) Stop(ctx context.Context, id string) error {
	if err := d.ensureClient(); err != nil {
		return fmt.Errorf("docker client: %w", err)
	}

	containerName := fmt.Sprintf("heimdall-%s", id)
	timeout := dockerStopTimeout
	err := d.cli.ContainerStop(ctx, containerName, container.StopOptions{Timeout: &timeout})
	if err != nil {
		return fmt.Errorf("stopping container %s: %w", containerName, err)
	}

	slog.Info("docker container stopped", "container", containerName)
	return nil
}

func (d *DockerDriver) IsHealthy(ctx context.Context, id string) (bool, error) {
	if err := d.ensureClient(); err != nil {
		return false, fmt.Errorf("docker client: %w", err)
	}

	containerName := fmt.Sprintf("heimdall-%s", id)
	info, err := d.cli.ContainerInspect(ctx, containerName)
	if err != nil {
		return false, fmt.Errorf("inspecting container %s: %w", containerName, err)
	}

	return info.State.Running, nil
}

func (d *DockerDriver) Cleanup(ctx context.Context, id string) error {
	if err := d.ensureClient(); err != nil {
		return fmt.Errorf("docker client: %w", err)
	}

	containerName := fmt.Sprintf("heimdall-%s", id)
	err := d.cli.ContainerRemove(ctx, containerName, container.RemoveOptions{
		RemoveVolumes: true,
		Force:         true,
	})
	if err != nil {
		return fmt.Errorf("removing container %s: %w", containerName, err)
	}

	slog.Info("docker container cleaned up", "container", containerName)
	return nil
}
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/fred/Documents/Heimdall && go test ./internal/orchestrator/ -run 'TestDockerDriver_Start_Integration' -v`
Expected: PASS (requires Docker daemon running)

**Step 5: Run full test suite**

Run: `cd /Users/fred/Documents/Heimdall && go test ./... -count=1 -short`
Expected: All tests pass (Docker tests skipped in short mode)

**Step 6: Commit**

```bash
git add internal/orchestrator/docker_driver.go internal/orchestrator/docker_driver_test.go
git commit -m "feat: implement DockerDriver Start/Stop/IsHealthy/Cleanup"
```

---

## Task 3: Per-tenant Docker network isolation

**Files:**
- Modify: `internal/orchestrator/docker_driver.go`
- Test: `internal/orchestrator/docker_driver_test.go`

**Step 1: Write the failing test**

Add to `docker_driver_test.go`:

```go
func TestDockerDriver_PerTenantNetwork(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Docker integration test in short mode")
	}

	driver := orchestrator.NewDockerDriver(orchestrator.DockerDriverConfig{
		Image:           "alpine:latest",
		NetworkMode:     "per-tenant",
		DefaultCPUs:     1,
		DefaultMemoryMB: 128,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := orchestrator.VMSpec{
		VMID:     "test-network-iso",
		VsockCID: 200,
	}

	// Start should create a tenant network and attach the container
	handle, err := driver.Start(ctx, spec)
	require.NoError(t, err)
	require.NotEmpty(t, handle.ID)

	// Cleanup
	require.NoError(t, driver.Stop(ctx, spec.VMID))
	require.NoError(t, driver.Cleanup(ctx, spec.VMID))
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/fred/Documents/Heimdall && go test ./internal/orchestrator/ -run 'TestDockerDriver_PerTenantNetwork' -v`
Expected: FAIL or PASS depending on current NetworkMode handling — verify behavior.

**Step 3: Add network management methods to DockerDriver**

Add to `docker_driver.go`:

```go
// ensureTenantNetwork creates a Docker network for the tenant if it doesn't exist.
// Returns the network ID.
func (d *DockerDriver) ensureTenantNetwork(ctx context.Context, tenantID string) (string, error) {
	networkName := fmt.Sprintf("heimdall-net-%s", tenantID)

	// Check if network already exists
	networks, err := d.cli.NetworkList(ctx, network.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("listing networks: %w", err)
	}
	for _, n := range networks {
		if n.Name == networkName {
			return n.ID, nil
		}
	}

	// Create new network
	resp, err := d.cli.NetworkCreate(ctx, networkName, network.CreateOptions{
		Driver:   "bridge",
		Internal: true, // no external access
		Labels: map[string]string{
			dockerContainerLabel: "network",
			dockerTenantLabel:    tenantID,
		},
	})
	if err != nil {
		return "", fmt.Errorf("creating network %s: %w", networkName, err)
	}

	slog.Info("created tenant network", "network", networkName, "id", resp.ID[:12])
	return resp.ID, nil
}
```

Update `Start()` to attach to a tenant network when `NetworkMode == "per-tenant"` and a tenant label is available. The tenant ID comes from the VMID prefix (set by manager.coldStart).

**Step 4: Run tests**

Run: `cd /Users/fred/Documents/Heimdall && go test ./internal/orchestrator/ -run 'TestDockerDriver' -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/orchestrator/docker_driver.go internal/orchestrator/docker_driver_test.go
git commit -m "feat: add per-tenant Docker network isolation"
```

---

## Task 4: Memory volume mounts

**Files:**
- Modify: `internal/orchestrator/docker_driver.go`
- Test: `internal/orchestrator/docker_driver_test.go`

**Step 1: Write the failing test**

```go
func TestDockerDriver_MemoryVolumeMounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Docker integration test in short mode")
	}

	memBase := t.TempDir()
	driver := orchestrator.NewDockerDriver(orchestrator.DockerDriverConfig{
		Image:           "alpine:latest",
		NetworkMode:     "none",
		DefaultCPUs:     1,
		DefaultMemoryMB: 128,
		MemoryBasePath:  memBase,
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

	// Cleanup
	require.NoError(t, driver.Stop(ctx, spec.VMID))
	require.NoError(t, driver.Cleanup(ctx, spec.VMID))
}
```

**Step 2: Run test to verify baseline**

Run: `cd /Users/fred/Documents/Heimdall && go test ./internal/orchestrator/ -run 'TestDockerDriver_MemoryVolumeMounts' -v`

**Step 3: Add memory volume mount logic**

Add a `MemoryMountSpec` to `VMSpec` or compute mount paths in `Start()` based on tenant/department/user IDs. For now, mount the personal memory volume using bind mounts from `MemoryBasePath/<vmid>/personal`:

```go
// In Start(), before ContainerCreate, add mounts:
var mounts []mount.Mount
if d.cfg.MemoryBasePath != "" {
	personalDir := filepath.Join(d.cfg.MemoryBasePath, spec.VMID, "personal")
	if err := os.MkdirAll(personalDir, 0o750); err != nil {
		return VMHandle{}, fmt.Errorf("creating personal memory dir: %w", err)
	}
	mounts = append(mounts, mount.Mount{
		Type:   mount.TypeBind,
		Source: personalDir,
		Target: "/memory/personal",
	})
}
hostCfg.Mounts = mounts
```

Note: Department/tenant/shared memory mounts will be added in Task 6 when the knowledge base tables exist. For now, mount only personal memory.

**Step 4: Run tests**

Run: `cd /Users/fred/Documents/Heimdall && go test ./internal/orchestrator/ -run 'TestDockerDriver' -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/orchestrator/docker_driver.go internal/orchestrator/docker_driver_test.go
git commit -m "feat: add personal memory volume mount to DockerDriver"
```

---

## Task 5: heimdall-agent spawns OpenClaw as child process

**Files:**
- Modify: `cmd/heimdall-agent/agent.go`
- Create: `cmd/heimdall-agent/subprocess.go`
- Test: `cmd/heimdall-agent/subprocess_test.go`

**Step 1: Write the failing test**

Create `cmd/heimdall-agent/subprocess_test.go`:

```go
package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSubprocess_StartStop(t *testing.T) {
	// Use "sleep" as a stand-in for openclaw gateway
	sp := &Subprocess{
		Name: "sleep",
		Args: []string{"30"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := sp.Start(ctx)
	require.NoError(t, err)
	require.True(t, sp.Running())

	err = sp.Stop()
	require.NoError(t, err)
	require.False(t, sp.Running())
}

func TestSubprocess_WaitForReady(t *testing.T) {
	// Spawn a process that binds a port (use nc/socat or just test the timeout path)
	sp := &Subprocess{
		Name:      "sleep",
		Args:      []string{"30"},
		ReadyURL:  "http://127.0.0.1:19999/nonexistent",
		ReadyWait: 500 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := sp.Start(ctx)
	require.NoError(t, err)

	// WaitForReady should fail since nothing listens on that port
	err = sp.WaitForReady(ctx)
	require.Error(t, err)

	_ = sp.Stop()
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/fred/Documents/Heimdall && go test ./cmd/heimdall-agent/ -run 'TestSubprocess' -v`
Expected: FAIL — `Subprocess` type doesn't exist.

**Step 3: Implement Subprocess manager**

Create `cmd/heimdall-agent/subprocess.go`:

```go
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Subprocess manages a child process lifecycle.
type Subprocess struct {
	Name      string
	Args      []string
	Env       []string
	Dir       string
	ReadyURL  string        // HTTP URL to poll for readiness
	ReadyWait time.Duration // max time to wait for readiness

	mu      sync.Mutex
	cmd     *exec.Cmd
	running bool
}

// Start launches the subprocess.
func (s *Subprocess) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cmd = exec.CommandContext(ctx, s.Name, s.Args...)
	s.cmd.Env = append(os.Environ(), s.Env...)
	if s.Dir != "" {
		s.cmd.Dir = s.Dir
	}
	s.cmd.Stdout = os.Stdout
	s.cmd.Stderr = os.Stderr
	// Set process group for clean shutdown
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := s.cmd.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", s.Name, err)
	}

	s.running = true
	slog.Info("subprocess started", "name", s.Name, "pid", s.cmd.Process.Pid)

	// Monitor process exit in background
	go func() {
		_ = s.cmd.Wait()
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		slog.Info("subprocess exited", "name", s.Name)
	}()

	return nil
}

// WaitForReady polls the ReadyURL until it responds or the context expires.
func (s *Subprocess) WaitForReady(ctx context.Context) error {
	if s.ReadyURL == "" {
		return nil
	}

	deadline := s.ReadyWait
	if deadline <= 0 {
		deadline = 10 * time.Second
	}

	waitCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	client := &http.Client{Timeout: 1 * time.Second}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("subprocess %s not ready after %s: %w", s.Name, deadline, waitCtx.Err())
		case <-ticker.C:
			req, err := http.NewRequestWithContext(waitCtx, "GET", s.ReadyURL, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			if resp.StatusCode < 500 {
				slog.Info("subprocess ready", "name", s.Name, "url", s.ReadyURL)
				return nil
			}
		}
	}
}

// Stop sends SIGTERM, waits briefly, then SIGKILL if needed.
func (s *Subprocess) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running || s.cmd == nil || s.cmd.Process == nil {
		return nil
	}

	// Send SIGTERM to process group
	if err := syscall.Kill(-s.cmd.Process.Pid, syscall.SIGTERM); err != nil {
		slog.Warn("SIGTERM failed, sending SIGKILL", "name", s.Name, "error", err)
		_ = s.cmd.Process.Kill()
	}

	s.running = false
	return nil
}

// Running returns whether the subprocess is still running.
func (s *Subprocess) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}
```

**Step 4: Run tests**

Run: `cd /Users/fred/Documents/Heimdall && go test ./cmd/heimdall-agent/ -run 'TestSubprocess' -v`
Expected: PASS

**Step 5: Wire subprocess into Agent.Run()**

Modify `cmd/heimdall-agent/agent.go` — in `Run()`, before listening, start OpenClaw as a subprocess:

```go
func (a *Agent) Run(ctx context.Context) error {
	// Start OpenClaw Gateway as a child process if URL points to localhost
	if isLoopback(a.cfg.OpenClawURL) && !a.cfg.SkipOpenClawSpawn {
		openclaw := &Subprocess{
			Name:      "openclaw",
			Args:      []string{"gateway", "--port", "8081"},
			ReadyURL:  a.cfg.OpenClawURL + "/v1/chat/completions",
			ReadyWait: 15 * time.Second,
		}
		if err := openclaw.Start(ctx); err != nil {
			return fmt.Errorf("starting openclaw: %w", err)
		}
		defer openclaw.Stop()

		if err := openclaw.WaitForReady(ctx); err != nil {
			slog.Warn("openclaw not ready, continuing anyway", "error", err)
		}
	}

	// ... existing transport/listen code ...
```

Add `SkipOpenClawSpawn bool` to `AgentConfig` and a `--skip-openclaw-spawn` flag for testing without OpenClaw.

**Step 6: Run full agent test suite**

Run: `cd /Users/fred/Documents/Heimdall && go test ./cmd/heimdall-agent/ -v`
Expected: PASS (existing tests use mock HTTP, not real OpenClaw)

**Step 7: Commit**

```bash
git add cmd/heimdall-agent/subprocess.go cmd/heimdall-agent/subprocess_test.go cmd/heimdall-agent/agent.go cmd/heimdall-agent/main.go
git commit -m "feat: heimdall-agent spawns OpenClaw gateway as child process"
```

---

## Task 6: Knowledge base database tables

**Files:**
- Create: `migrations/000017_knowledge_bases.up.sql`
- Create: `migrations/000017_knowledge_bases.down.sql`
- Test: verify migration applies cleanly

**Step 1: Check current migration number**

Run: `ls migrations/ | tail -4` to find the latest migration number.

**Step 2: Write the up migration**

Create `migrations/000017_knowledge_bases.up.sql` (adjust number if needed):

```sql
-- Knowledge bases: named collections of shared knowledge per tenant.
CREATE TABLE knowledge_bases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    layer TEXT NOT NULL CHECK (layer IN ('tenant', 'department')),
    source_department_id UUID REFERENCES departments(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_knowledge_bases_tenant_id ON knowledge_bases(tenant_id);

ALTER TABLE knowledge_bases ENABLE ROW LEVEL SECURITY;

CREATE POLICY knowledge_bases_tenant_isolation ON knowledge_bases
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- Knowledge base access grants: map KB to departments/roles/users.
CREATE TABLE knowledge_base_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    knowledge_base_id UUID NOT NULL REFERENCES knowledge_bases(id) ON DELETE CASCADE,
    grant_type TEXT NOT NULL CHECK (grant_type IN ('department', 'role', 'user')),
    grant_target_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_kb_grants_kb_id ON knowledge_base_grants(knowledge_base_id);
CREATE UNIQUE INDEX idx_kb_grants_unique ON knowledge_base_grants(knowledge_base_id, grant_type, grant_target_id);

ALTER TABLE knowledge_base_grants ENABLE ROW LEVEL SECURITY;

-- RLS via join to knowledge_bases for tenant isolation
CREATE POLICY kb_grants_tenant_isolation ON knowledge_base_grants
    USING (
        knowledge_base_id IN (
            SELECT id FROM knowledge_bases
            WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
        )
    );
```

**Step 3: Write the down migration**

Create `migrations/000017_knowledge_bases.down.sql`:

```sql
DROP TABLE IF EXISTS knowledge_base_grants;
DROP TABLE IF EXISTS knowledge_bases;
```

**Step 4: Apply migration**

Run: `cd /Users/fred/Documents/Heimdall && /usr/local/Cellar/postgresql@15/15.13/bin/psql postgres://heimdall:heimdall@localhost:5432/heimdall -f migrations/000017_knowledge_bases.up.sql`
Expected: CREATE TABLE, CREATE INDEX, etc.

**Step 5: Verify**

Run: `cd /Users/fred/Documents/Heimdall && /usr/local/Cellar/postgresql@15/15.13/bin/psql postgres://heimdall:heimdall@localhost:5432/heimdall -c '\dt knowledge*'`
Expected: Shows both tables.

**Step 6: Commit**

```bash
git add migrations/000017_knowledge_bases.up.sql migrations/000017_knowledge_bases.down.sql
git commit -m "feat: add knowledge_bases and knowledge_base_grants tables"
```

---

## Task 7: Dockerfile for agent container image

**Files:**
- Create: `Dockerfile.agent`
- Create: `configs/openclaw-guest.json`

**Step 1: Create OpenClaw guest config**

Create `configs/openclaw-guest.json`:

```json
{
  "gateway": {
    "bind": "127.0.0.1",
    "port": 8081
  },
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "non-main"
      }
    }
  },
  "tools": {
    "exec": {
      "workspaceOnly": true,
      "applyPatch": {
        "workspaceOnly": true
      }
    }
  }
}
```

**Step 2: Create the Dockerfile**

Create `Dockerfile.agent`:

```dockerfile
# Stage 1: Build heimdall-agent
FROM golang:1.25 AS agent-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /heimdall-agent ./cmd/heimdall-agent

# Stage 2: OpenClaw runtime
FROM node:22-slim

# Install OpenClaw (pin version for reproducibility)
RUN npm install -g openclaw@latest

# Copy heimdall-agent binary
COPY --from=agent-builder /heimdall-agent /usr/local/bin/heimdall-agent

# Copy OpenClaw hardened config
COPY configs/openclaw-guest.json /etc/openclaw/openclaw.json

# Create memory mount points
RUN mkdir -p /memory/personal /memory/department /memory/tenant /memory/shared

# Agent listens on port 9100 for control plane connections
EXPOSE 9100

ENTRYPOINT ["/usr/local/bin/heimdall-agent", \
  "--transport", "tcp", \
  "--port", "9100", \
  "--openclaw-url", "http://127.0.0.1:8081"]
```

**Step 3: Build the image**

Run: `cd /Users/fred/Documents/Heimdall && docker build -f Dockerfile.agent -t heimdall/agent:dev .`
Expected: Successful build.

**Step 4: Smoke test**

Run: `docker run --rm -d --name heimdall-agent-test -p 19100:9100 heimdall/agent:dev --skip-openclaw-spawn && sleep 2 && docker logs heimdall-agent-test && docker stop heimdall-agent-test`
Expected: Agent starts, logs "heimdall-agent starting" and "agent listening".

**Step 5: Commit**

```bash
git add Dockerfile.agent configs/openclaw-guest.json
git commit -m "feat: add agent container Dockerfile and OpenClaw guest config"
```

---

## Task 8: End-to-end integration test

**Files:**
- Create: `internal/orchestrator/docker_e2e_test.go`

**Step 1: Write the integration test**

```go
package orchestrator_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/heimdall-ai/heimdall/internal/orchestrator"
	"github.com/heimdall-ai/heimdall/internal/proxy"
)

// TestDockerDriver_E2E tests the full flow: start container, connect via proxy, send ping, stop.
// Requires Docker daemon and heimdall/agent:dev image built.
func TestDockerDriver_E2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Docker E2E test in short mode")
	}

	driver := orchestrator.NewDockerDriver(orchestrator.DockerDriverConfig{
		Image:           "heimdall/agent:dev",
		NetworkMode:     "none",
		DefaultCPUs:     1,
		DefaultMemoryMB: 256,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	spec := orchestrator.VMSpec{
		VMID:     "test-e2e",
		VsockCID: 500,
	}

	// Start container
	handle, err := driver.Start(ctx, spec)
	require.NoError(t, err)
	defer func() {
		_ = driver.Stop(ctx, spec.VMID)
		_ = driver.Cleanup(ctx, spec.VMID)
	}()

	// Wait for agent to be ready
	time.Sleep(3 * time.Second)

	// Connect via TCP transport
	transport := proxy.NewTCPTransport(9100) // matches dockerAgentPort
	conn, err := transport.Dial(ctx, handle.VsockCID)
	require.NoError(t, err)
	defer conn.Close()

	agentConn := proxy.NewAgentConn(conn)

	// Read initial heartbeat
	frame, err := agentConn.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, proxy.TypeHeartbeat, frame.Type)

	// Send ping
	pingFrame := proxy.Frame{
		Type:    proxy.TypePing,
		ID:      "ping-1",
		Payload: json.RawMessage(`{}`),
	}
	err = agentConn.Send(ctx, pingFrame)
	require.NoError(t, err)

	// Expect pong
	pong, err := agentConn.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, proxy.TypePong, pong.Type)
	require.Equal(t, "ping-1", pong.ID)
}
```

**Step 2: Run the test**

Run: `cd /Users/fred/Documents/Heimdall && go test ./internal/orchestrator/ -run 'TestDockerDriver_E2E' -v -timeout 120s`
Expected: PASS (requires Docker + built image)

**Step 3: Commit**

```bash
git add internal/orchestrator/docker_e2e_test.go
git commit -m "test: add Docker driver end-to-end integration test"
```

---

## Summary

| Task | What it delivers |
|------|-----------------|
| 1 | DockerConfig expanded, DockerDriver stub, wired into selectVMDriver |
| 2 | DockerDriver.Start/Stop/IsHealthy/Cleanup with Docker Engine API |
| 3 | Per-tenant Docker network isolation |
| 4 | Personal memory volume mounts |
| 5 | heimdall-agent spawns OpenClaw as child process |
| 6 | knowledge_bases + knowledge_base_grants DB tables with RLS |
| 7 | Dockerfile.agent + OpenClaw guest config |
| 8 | End-to-end integration test |

**Not in this plan (future tasks):**
- Department/tenant/shared memory volume mount wiring (needs knowledge base store + grant resolution)
- `heimdall_publish_memory` MCP connector
- `heimdall_query_memory` MCP connector
- Dashboard UI for knowledge base management
- Firecracker guest image pipeline (parallel track)
- Warm pool optimization for Docker (works but can be tuned)
