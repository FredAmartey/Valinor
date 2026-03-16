package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
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
	WorkspaceQuotaMB int      // reserved for future --storage-opt support; not yet enforced
	Cmd              []string // optional command override (default: use image ENTRYPOINT/CMD)
}

// DockerDriver manages agent containers via the Docker Engine API.
type DockerDriver struct {
	cfg     DockerDriverConfig
	cli     *client.Client
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

	containerName := fmt.Sprintf("heimdall-%s", spec.VMID)
	hostPortNum := dockerAgentPort + int(spec.VsockCID)
	if hostPortNum < 1024 || hostPortNum > 65535 {
		return VMHandle{}, fmt.Errorf("computed host port %d out of valid range for CID %d", hostPortNum, spec.VsockCID)
	}
	hostPort := strconv.Itoa(hostPortNum)
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

	// Memory volume mounts: personal (rw), department (ro), tenant (ro), shared (ro per KB).
	var mounts []mount.Mount
	if d.cfg.MemoryBasePath != "" {
		cleanBase := filepath.Clean(d.cfg.MemoryBasePath)

		addMount := func(subpath, target string, readOnly bool) error {
			hostDir := filepath.Join(d.cfg.MemoryBasePath, subpath)
			if !strings.HasPrefix(filepath.Clean(hostDir), cleanBase+string(filepath.Separator)) {
				return fmt.Errorf("memory path %q escapes base %q", hostDir, cleanBase)
			}
			if err := os.MkdirAll(hostDir, 0o750); err != nil {
				return fmt.Errorf("creating memory dir %s: %w", target, err)
			}
			mounts = append(mounts, mount.Mount{
				Type:     mount.TypeBind,
				Source:   hostDir,
				Target:   target,
				ReadOnly: readOnly,
			})
			return nil
		}

		// Personal: per-VM, read-write
		if err := addMount(filepath.Join(spec.VMID, "personal"), "/memory/personal", false); err != nil {
			return VMHandle{}, err
		}

		// Department: shared across dept agents, read-only
		if spec.DepartmentID != "" {
			if err := addMount(filepath.Join("departments", spec.DepartmentID), "/memory/department", true); err != nil {
				return VMHandle{}, err
			}
		}

		// Tenant: shared across tenant agents, read-only
		if spec.TenantID != "" {
			if err := addMount(filepath.Join("tenants", spec.TenantID), "/memory/tenant", true); err != nil {
				return VMHandle{}, err
			}
		}

		// Shared: one read-only mount per granted knowledge base
		for _, kb := range spec.KnowledgeBases {
			if strings.ContainsAny(kb.Name, "/\\") || kb.Name == ".." || kb.Name == "." || kb.Name == "" {
				return VMHandle{}, fmt.Errorf("invalid knowledge base name %q: must not contain path separators", kb.Name)
			}
			target := fmt.Sprintf("/memory/shared/%s", kb.Name)
			if err := addMount(filepath.Join("kbs", kb.ID), target, true); err != nil {
				return VMHandle{}, err
			}
		}
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
			fmt.Sprintf("heimdall-net-%s", spec.TenantID): {NetworkID: netID},
		}
	}

	resp, err := d.cli.ContainerCreate(ctx, containerCfg, hostCfg, netCfg, nil, containerName)
	if err != nil {
		return VMHandle{}, fmt.Errorf("creating container %s: %w", containerName, err)
	}

	if startErr := d.cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); startErr != nil {
		_ = d.cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})
		return VMHandle{}, fmt.Errorf("starting container %s: %w", containerName, startErr)
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

	// Inspect before removal to capture the tenant label for network cleanup.
	var tenantID string
	info, inspectErr := d.cli.ContainerInspect(ctx, containerName)
	if inspectErr == nil {
		tenantID = info.Config.Labels[dockerTenantLabel]
	}

	err := d.cli.ContainerRemove(ctx, containerName, container.RemoveOptions{
		RemoveVolumes: true,
		Force:         true,
	})
	if err != nil {
		return fmt.Errorf("removing container %s: %w", containerName, err)
	}

	slog.Info("docker container cleaned up", "container", containerName)

	// Remove the tenant network if no other Heimdall containers use it.
	if tenantID != "" {
		d.cleanupTenantNetwork(ctx, tenantID)
	}
	return nil
}

// cleanupTenantNetwork removes the tenant's Docker network if no Heimdall
// containers are still connected to it. Best-effort; errors are logged, not returned.
func (d *DockerDriver) cleanupTenantNetwork(ctx context.Context, tenantID string) {
	networkName := fmt.Sprintf("heimdall-net-%s", tenantID)

	// List only Heimdall containers that belong to this tenant.
	tenantFilter := filters.NewArgs(
		filters.Arg("label", fmt.Sprintf("%s=%s", dockerTenantLabel, tenantID)),
	)
	containers, err := d.cli.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: tenantFilter,
	})
	if err != nil {
		slog.Warn("failed to list tenant containers for network cleanup", "tenant", tenantID, "error", err)
		return
	}
	if len(containers) > 0 {
		return // other containers still using this network
	}

	if removeErr := d.cli.NetworkRemove(ctx, networkName); removeErr != nil {
		slog.Warn("failed to remove tenant network", "network", networkName, "error", removeErr)
		return
	}
	slog.Info("removed orphaned tenant network", "network", networkName)
}

// ensureTenantNetwork creates an internal Docker bridge network for the tenant
// if it doesn't already exist. Returns the network ID.
func (d *DockerDriver) ensureTenantNetwork(ctx context.Context, tenantID string) (string, error) {
	networkName := fmt.Sprintf("heimdall-net-%s", tenantID)

	labelFilter := filters.NewArgs(
		filters.Arg("label", fmt.Sprintf("%s=%s", dockerTenantLabel, tenantID)),
	)
	networks, err := d.cli.NetworkList(ctx, network.ListOptions{Filters: labelFilter})
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
		// Handle TOCTOU race: another goroutine may have created the network
		// between our list and create calls.
		if strings.Contains(err.Error(), "already exists") {
			networks, listErr := d.cli.NetworkList(ctx, network.ListOptions{Filters: labelFilter})
			if listErr != nil {
				return "", fmt.Errorf("re-listing networks after race: %w", listErr)
			}
			for _, n := range networks {
				if n.Name == networkName {
					return n.ID, nil
				}
			}
		}
		return "", fmt.Errorf("creating network %s: %w", networkName, err)
	}

	slog.Info("created tenant network", "network", networkName, "id", resp.ID[:12])
	return resp.ID, nil
}
