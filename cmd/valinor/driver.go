package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/platform/config"
)

// selectVMDriver resolves the VM driver from config and enforces safe defaults.
func selectVMDriver(cfg config.OrchestratorConfig, devMode bool) (orchestrator.VMDriver, error) {
	driver := strings.ToLower(strings.TrimSpace(cfg.Driver))
	if driver == "" {
		driver = "mock"
	}

	switch driver {
	case "mock":
		if !devMode {
			return nil, fmt.Errorf("orchestrator driver %q is only allowed in dev mode", driver)
		}
		return orchestrator.NewMockDriver(), nil

	case "firecracker":
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("orchestrator driver %q requires linux host", driver)
		}
		if strings.TrimSpace(cfg.Firecracker.KernelPath) == "" {
			return nil, fmt.Errorf("firecracker kernel_path is required")
		}
		if strings.TrimSpace(cfg.Firecracker.RootDrive) == "" {
			return nil, fmt.Errorf("firecracker root_drive is required")
		}
		jailerCfg, err := validateFirecrackerPrereqs(cfg.Firecracker)
		if err != nil {
			return nil, err
		}
		return orchestrator.NewFirecrackerDriverWithConfig(
			cfg.Firecracker.KernelPath,
			cfg.Firecracker.RootDrive,
			jailerCfg,
		), nil

	default:
		return nil, fmt.Errorf("unsupported orchestrator driver %q", cfg.Driver)
	}
}

func validateFirecrackerPrereqs(cfg config.FirecrackerConfig) (orchestrator.FirecrackerJailerConfig, error) {
	var jailerCfg orchestrator.FirecrackerJailerConfig
	if err := requireFilePath(cfg.KernelPath, "firecracker kernel_path"); err != nil {
		return jailerCfg, err
	}
	if err := requireFilePath(cfg.RootDrive, "firecracker root_drive"); err != nil {
		return jailerCfg, err
	}

	binary := strings.TrimSpace(os.Getenv("VALINOR_FIRECRACKER_BIN"))
	if binary == "" {
		binary = "firecracker"
	}
	if _, err := exec.LookPath(binary); err != nil {
		return jailerCfg, fmt.Errorf("firecracker binary %q not found in PATH (set VALINOR_FIRECRACKER_BIN to override)", binary)
	}

	jailerEnabled := cfg.Jailer.Enabled || strings.TrimSpace(cfg.JailerPath) != ""
	if !jailerEnabled {
		return jailerCfg, nil
	}

	jailerBinary := strings.TrimSpace(cfg.Jailer.BinaryPath)
	if jailerBinary == "" {
		jailerBinary = strings.TrimSpace(cfg.JailerPath)
	}
	if jailerBinary == "" {
		jailerBinary = "jailer"
	}
	if _, err := exec.LookPath(jailerBinary); err != nil {
		return jailerCfg, fmt.Errorf("jailer binary %q not found in PATH", jailerBinary)
	}

	chrootBase := strings.TrimSpace(cfg.Jailer.ChrootBaseDir)
	if chrootBase == "" {
		return jailerCfg, fmt.Errorf("firecracker jailer chroot_base_dir is required when jailer is enabled")
	}
	if !filepath.IsAbs(chrootBase) {
		return jailerCfg, fmt.Errorf("firecracker jailer chroot_base_dir %q must be an absolute path", chrootBase)
	}
	if cfg.Jailer.UID < 0 {
		return jailerCfg, fmt.Errorf("firecracker jailer uid must be >= 0")
	}
	if cfg.Jailer.GID < 0 {
		return jailerCfg, fmt.Errorf("firecracker jailer gid must be >= 0")
	}
	if strings.TrimSpace(cfg.Jailer.NetNSPath) != "" && !filepath.IsAbs(cfg.Jailer.NetNSPath) {
		return jailerCfg, fmt.Errorf("firecracker jailer netns_path %q must be an absolute path", cfg.Jailer.NetNSPath)
	}

	jailerCfg = orchestrator.FirecrackerJailerConfig{
		Enabled:       true,
		BinaryPath:    jailerBinary,
		ChrootBaseDir: chrootBase,
		UID:           cfg.Jailer.UID,
		GID:           cfg.Jailer.GID,
		NetNSPath:     strings.TrimSpace(cfg.Jailer.NetNSPath),
		Daemonize:     cfg.Jailer.Daemonize,
	}

	return jailerCfg, nil
}

func requireFilePath(path, label string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s %q must be an absolute path", label, path)
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s %q does not exist", label, path)
		}
		return fmt.Errorf("%s %q cannot be read: %w", label, path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s %q must be a file, got directory", label, path)
	}
	return nil
}
