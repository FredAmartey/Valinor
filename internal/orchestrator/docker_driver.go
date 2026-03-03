package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
	dockerContainerLabel = "valinor.agent"
	dockerTenantLabel    = "valinor.tenant"
	dockerStopTimeout    = 10 // seconds
)

// DockerDriverConfig holds configuration for the Docker-based VM driver.
type DockerDriverConfig struct {
	Image            string
	NetworkMode      string   // "none", "per-tenant", "bridge"
	DefaultCPUs      int
	DefaultMemoryMB  int
	MemoryBasePath   string
	WorkspaceQuotaMB int
	Cmd              []string // optional command override (default: use image ENTRYPOINT/CMD)
}

// DockerDriver manages agent containers via the Docker Engine API.
type DockerDriver struct {
	cfg     DockerDriverConfig
	cli     *client.Client
	mu      sync.Mutex
	initMu  sync.Once
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

	containerName := fmt.Sprintf("valinor-%s", spec.VMID)
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
		Cmd: d.cfg.Cmd,
	}

	// Memory volume mounts: create host-side personal dir and bind mount it.
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
		RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyDisabled},
		Mounts:        mounts,
	}

	netCfg := &network.NetworkingConfig{}

	// Per-tenant network isolation: create/reuse an internal bridge network per tenant.
	if d.cfg.NetworkMode == "per-tenant" && spec.TenantID != "" {
		containerCfg.Labels[dockerTenantLabel] = spec.TenantID
		netID, netErr := d.ensureTenantNetwork(ctx, spec.TenantID)
		if netErr != nil {
			return VMHandle{}, netErr
		}
		netCfg.EndpointsConfig = map[string]*network.EndpointSettings{
			fmt.Sprintf("valinor-net-%s", spec.TenantID): {NetworkID: netID},
		}
	}

	resp, err := d.cli.ContainerCreate(ctx, containerCfg, hostCfg, netCfg, nil, containerName)
	if err != nil {
		return VMHandle{}, fmt.Errorf("creating container %s: %w", containerName, err)
	}

	if err := d.cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
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

	containerName := fmt.Sprintf("valinor-%s", id)
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

	containerName := fmt.Sprintf("valinor-%s", id)
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

	containerName := fmt.Sprintf("valinor-%s", id)
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

// ensureTenantNetwork creates an internal Docker bridge network for the tenant
// if it doesn't already exist. Returns the network ID.
func (d *DockerDriver) ensureTenantNetwork(ctx context.Context, tenantID string) (string, error) {
	networkName := fmt.Sprintf("valinor-net-%s", tenantID)

	networks, err := d.cli.NetworkList(ctx, network.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("listing networks: %w", err)
	}
	for _, n := range networks {
		if n.Name == networkName {
			return n.ID, nil
		}
	}

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
