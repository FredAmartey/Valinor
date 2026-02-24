//go:build linux

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultFirecrackerBinary      = "firecracker"
	defaultJailerBinary           = "jailer"
	defaultFirecrackerStateSubdir = "valinor-firecracker"
	defaultFirecrackerBootArgs    = "console=ttyS0 reboot=k panic=1 pci=off"
	defaultFirecrackerVCPUs       = 1
	defaultFirecrackerMemoryMB    = 512
	defaultSocketWaitTimeout      = 5 * time.Second
	defaultStopTimeout            = 5 * time.Second
	defaultJailerPIDFileName      = ".pid"
	defaultVMStateFileName        = "vm-state.json"
	defaultDataDriveFileName      = "data.ext4"
	maxDataDriveQuotaMB           = 1 << 20 // 1 TiB
)

var vmIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

type firecrackerVM struct {
	cmd            *exec.Cmd
	stateDir       string
	jailerDir      string
	apiSock        string
	firecrackerPID int
	daemonized     bool
	waitCh         chan struct{}
	waitErr        error
}

type firecrackerVMPersistedState struct {
	VMID           string `json:"vm_id"`
	StateDir       string `json:"state_dir"`
	JailerDir      string `json:"jailer_dir,omitempty"`
	APISock        string `json:"api_sock"`
	FirecrackerPID int    `json:"firecracker_pid"`
	Daemonized     bool   `json:"daemonized"`
}

// FirecrackerDriver manages Firecracker MicroVMs on Linux hosts.
// It launches one firecracker process per VM and configures it through
// the local API socket.
type FirecrackerDriver struct {
	kernelPath string
	rootDrive  string
	jailer     FirecrackerJailerConfig

	binaryPath string
	stateRoot  string

	socketWaitTimeout time.Duration
	stopTimeout       time.Duration

	mu       sync.Mutex
	vms      map[string]*firecrackerVM
	starting map[string]struct{}
}

// NewFirecrackerDriver creates a new FirecrackerDriver.
func NewFirecrackerDriver(kernelPath, rootDrive, jailerPath string) *FirecrackerDriver {
	jailerCfg := FirecrackerJailerConfig{}
	if strings.TrimSpace(jailerPath) != "" {
		jailerCfg = FirecrackerJailerConfig{
			Enabled:       true,
			BinaryPath:    strings.TrimSpace(jailerPath),
			ChrootBaseDir: filepath.Join(os.TempDir(), "valinor-jailer"),
			// Require explicit jailer UID/GID in production config.
			UID: -1,
			GID: -1,
		}
	}
	return NewFirecrackerDriverWithConfig(kernelPath, rootDrive, jailerCfg)
}

// NewFirecrackerDriverWithConfig creates a FirecrackerDriver with optional jailer settings.
func NewFirecrackerDriverWithConfig(kernelPath, rootDrive string, jailerCfg FirecrackerJailerConfig) *FirecrackerDriver {
	binaryPath := strings.TrimSpace(os.Getenv("VALINOR_FIRECRACKER_BIN"))
	if binaryPath == "" {
		binaryPath = defaultFirecrackerBinary
	}
	binaryPath = resolveExecutablePath(binaryPath)
	if strings.TrimSpace(jailerCfg.BinaryPath) == "" {
		jailerCfg.BinaryPath = defaultJailerBinary
	}
	jailerCfg.BinaryPath = resolveExecutablePath(jailerCfg.BinaryPath)

	return &FirecrackerDriver{
		kernelPath:        kernelPath,
		rootDrive:         rootDrive,
		jailer:            jailerCfg,
		binaryPath:        binaryPath,
		stateRoot:         filepath.Join(os.TempDir(), defaultFirecrackerStateSubdir),
		socketWaitTimeout: defaultSocketWaitTimeout,
		stopTimeout:       defaultStopTimeout,
		vms:               make(map[string]*firecrackerVM),
		starting:          make(map[string]struct{}),
	}
}

func (d *FirecrackerDriver) Start(ctx context.Context, spec VMSpec) (VMHandle, error) {
	vmID, vmIDErr := normalizeVMID(spec.VMID)
	if vmIDErr != nil {
		return VMHandle{}, fmt.Errorf("%w: %v", ErrDriverFailure, vmIDErr)
	}
	if spec.VsockCID == 0 {
		return VMHandle{}, fmt.Errorf("%w: vsock CID is required", ErrDriverFailure)
	}
	if d.jailer.Enabled {
		if d.jailer.UID < 0 {
			return VMHandle{}, fmt.Errorf("%w: jailer uid must be >= 0", ErrDriverFailure)
		}
		if d.jailer.GID < 0 {
			return VMHandle{}, fmt.Errorf("%w: jailer gid must be >= 0", ErrDriverFailure)
		}
	}

	kernelPath := strings.TrimSpace(spec.KernelPath)
	if kernelPath == "" {
		kernelPath = strings.TrimSpace(d.kernelPath)
	}
	if kernelPath == "" {
		return VMHandle{}, fmt.Errorf("%w: kernel path is required", ErrDriverFailure)
	}
	if pathErr := requireAbsoluteFilePath(kernelPath, "kernel path"); pathErr != nil {
		return VMHandle{}, fmt.Errorf("%w: %v", ErrDriverFailure, pathErr)
	}

	rootDrive := strings.TrimSpace(spec.RootDrive)
	if rootDrive == "" {
		rootDrive = strings.TrimSpace(d.rootDrive)
	}
	if rootDrive == "" {
		return VMHandle{}, fmt.Errorf("%w: root drive is required", ErrDriverFailure)
	}
	if pathErr := requireAbsoluteFilePath(rootDrive, "root drive path"); pathErr != nil {
		return VMHandle{}, fmt.Errorf("%w: %v", ErrDriverFailure, pathErr)
	}
	dataDrive := strings.TrimSpace(spec.DataDrive)
	if dataDrive != "" {
		if pathErr := requireAbsoluteFilePath(dataDrive, "data drive path"); pathErr != nil {
			return VMHandle{}, fmt.Errorf("%w: %v", ErrDriverFailure, pathErr)
		}
	}
	if spec.DataDriveQuotaMB < 0 {
		return VMHandle{}, fmt.Errorf("%w: data drive quota must be >= 0", ErrDriverFailure)
	}
	if spec.UseJailer || strings.TrimSpace(spec.JailerPath) != "" {
		return VMHandle{}, fmt.Errorf("%w: per-request jailer override is not supported", ErrDriverFailure)
	}

	bootArgs := strings.TrimSpace(spec.KernelArgs)
	if bootArgs == "" {
		bootArgs = defaultFirecrackerBootArgs
	}

	vcpus := spec.VCPUs
	if vcpus <= 0 {
		vcpus = defaultFirecrackerVCPUs
	}
	memMB := spec.MemoryMB
	if memMB <= 0 {
		memMB = defaultFirecrackerMemoryMB
	}

	resolvedFirecrackerBinary, err := resolveAndValidateExecutable(d.binaryPath, defaultFirecrackerBinary)
	if err != nil {
		return VMHandle{}, fmt.Errorf("%w: %v", ErrDriverFailure, err)
	}

	stateDir := filepath.Join(d.stateRoot, vmID)
	apiSock := filepath.Join(stateDir, "api.sock")
	vsockSock := filepath.Join(stateDir, "vsock.sock")
	logPath := filepath.Join(stateDir, "firecracker.log")
	firecrackerKernelPath := kernelPath
	firecrackerRootDrive := rootDrive
	firecrackerDataDrive := dataDrive
	vsockUDSPath := vsockSock
	launchBinaryPath := resolvedFirecrackerBinary
	launchArgs := []string{"--api-sock", apiSock}
	jailerDir := ""
	firecrackerPID := 0
	daemonized := false

	d.mu.Lock()
	if d.starting == nil {
		d.starting = make(map[string]struct{})
	}
	if _, exists := d.vms[vmID]; exists {
		d.mu.Unlock()
		return VMHandle{}, fmt.Errorf("%w: vm already exists: %s", ErrDriverFailure, vmID)
	}
	if _, exists := d.starting[vmID]; exists {
		d.mu.Unlock()
		return VMHandle{}, fmt.Errorf("%w: vm startup already in progress: %s", ErrDriverFailure, vmID)
	}
	d.starting[vmID] = struct{}{}
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.starting, vmID)
		d.mu.Unlock()
	}()

	if mkdirErr := os.MkdirAll(stateDir, 0o750); mkdirErr != nil {
		return VMHandle{}, fmt.Errorf("%w: creating state dir: %v", ErrDriverFailure, mkdirErr)
	}
	if dataDrive == "" && spec.DataDriveQuotaMB > 0 {
		autoDataDrivePath := filepath.Join(stateDir, defaultDataDriveFileName)
		if createErr := createSparseDataDrive(autoDataDrivePath, spec.DataDriveQuotaMB); createErr != nil {
			_ = os.RemoveAll(stateDir)
			return VMHandle{}, fmt.Errorf("%w: creating data drive: %v", ErrDriverFailure, createErr)
		}
		dataDrive = autoDataDrivePath
	}

	if d.jailer.Enabled {
		resolvedJailerBinary, binaryErr := resolveAndValidateExecutable(d.jailer.BinaryPath, defaultJailerBinary)
		if binaryErr != nil {
			return VMHandle{}, fmt.Errorf("%w: %v", ErrDriverFailure, binaryErr)
		}
		var prepErr error
		jailerDir, apiSock, firecrackerKernelPath, firecrackerRootDrive, firecrackerDataDrive, prepErr = d.prepareJailerLayout(vmID, kernelPath, rootDrive, dataDrive)
		if prepErr != nil {
			_ = os.RemoveAll(stateDir)
			return VMHandle{}, fmt.Errorf("%w: preparing jailer layout: %v", ErrDriverFailure, prepErr)
		}
		vsockUDSPath = "/run/vsock.sock"
		logPath = filepath.Join(stateDir, "jailer.log")
		launchBinaryPath = resolvedJailerBinary
		launchArgs = buildJailerCommandArgs(vmID, resolvedFirecrackerBinary, d.jailer, "/run/firecracker.socket")
		daemonized = d.jailer.Daemonize
	}

	// #nosec G304 -- logPath is derived from trusted stateRoot/vmID and fixed filenames.
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		_ = os.RemoveAll(stateDir)
		if jailerDir != "" {
			_ = os.RemoveAll(jailerDir)
		}
		return VMHandle{}, fmt.Errorf("%w: opening log file: %v", ErrDriverFailure, err)
	}
	defer logFile.Close()

	// #nosec G204 -- command name is static and launchArgs are internally constructed from validated paths/IDs.
	cmd := exec.CommandContext(context.Background(), "/bin/true", launchArgs...)
	cmd.Path = launchBinaryPath
	cmd.Args[0] = launchBinaryPath
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Dir = stateDir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(stateDir)
		if jailerDir != "" {
			_ = os.RemoveAll(jailerDir)
		}
		return VMHandle{}, fmt.Errorf("%w: starting firecracker process: %v", ErrDriverFailure, err)
	}
	firecrackerPID = cmd.Process.Pid

	vm := &firecrackerVM{
		cmd:            cmd,
		stateDir:       stateDir,
		jailerDir:      jailerDir,
		apiSock:        apiSock,
		firecrackerPID: firecrackerPID,
		daemonized:     daemonized,
		waitCh:         make(chan struct{}),
	}
	go func() {
		vm.waitErr = cmd.Wait()
		close(vm.waitCh)
	}()

	waitCtx, cancel := context.WithTimeout(ctx, d.socketWaitTimeout)
	defer cancel()
	if err := waitForSocket(waitCtx, apiSock); err != nil {
		_ = d.stopProcess(vm)
		_ = os.RemoveAll(stateDir)
		if jailerDir != "" {
			_ = os.RemoveAll(jailerDir)
		}
		return VMHandle{}, fmt.Errorf("%w: waiting for api socket: %v", ErrDriverFailure, err)
	}

	if daemonized && jailerDir != "" {
		// Daemonized jailer startup currently has two sequential waits:
		// API socket and PID file. The combined startup budget can reach
		// roughly 2*socketWaitTimeout in the worst case.
		pidPath := filepath.Join(jailerDir, "root", defaultJailerPIDFileName)
		pidCtx, cancelPID := context.WithTimeout(ctx, d.socketWaitTimeout)
		pid, pidErr := waitForPIDFile(pidCtx, pidPath)
		cancelPID()
		if pidErr != nil {
			_ = d.stopProcess(vm)
			_ = os.RemoveAll(stateDir)
			_ = os.RemoveAll(jailerDir)
			return VMHandle{}, fmt.Errorf("%w: reading jailer pid file: %v", ErrDriverFailure, pidErr)
		}
		firecrackerPID = pid
		vm.firecrackerPID = pid
	}

	client := newFirecrackerClient(apiSock)
	if err := configureMachine(ctx, client, vcpus, memMB); err != nil {
		_ = d.stopProcess(vm)
		_ = os.RemoveAll(stateDir)
		if jailerDir != "" {
			_ = os.RemoveAll(jailerDir)
		}
		return VMHandle{}, fmt.Errorf("%w: configuring machine: %v", ErrDriverFailure, err)
	}

	if err := client.putJSON(ctx, "/boot-source", map[string]any{
		"kernel_image_path": firecrackerKernelPath,
		"boot_args":         bootArgs,
	}); err != nil {
		_ = d.stopProcess(vm)
		_ = os.RemoveAll(stateDir)
		if jailerDir != "" {
			_ = os.RemoveAll(jailerDir)
		}
		return VMHandle{}, fmt.Errorf("%w: configuring boot source: %v", ErrDriverFailure, err)
	}

	// Rootfs is mounted read-only for safer multi-tenant baseline.
	if err := client.putJSON(ctx, "/drives/rootfs", map[string]any{
		"drive_id":       "rootfs",
		"path_on_host":   firecrackerRootDrive,
		"is_root_device": true,
		"is_read_only":   true,
	}); err != nil {
		_ = d.stopProcess(vm)
		_ = os.RemoveAll(stateDir)
		if jailerDir != "" {
			_ = os.RemoveAll(jailerDir)
		}
		return VMHandle{}, fmt.Errorf("%w: configuring root drive: %v", ErrDriverFailure, err)
	}

	if firecrackerDataDrive != "" {
		if err := client.putJSON(ctx, "/drives/data", map[string]any{
			"drive_id":       "data",
			"path_on_host":   firecrackerDataDrive,
			"is_root_device": false,
			"is_read_only":   false,
		}); err != nil {
			_ = d.stopProcess(vm)
			_ = os.RemoveAll(stateDir)
			if jailerDir != "" {
				_ = os.RemoveAll(jailerDir)
			}
			return VMHandle{}, fmt.Errorf("%w: configuring data drive: %v", ErrDriverFailure, err)
		}
	}

	if err := client.putJSON(ctx, "/vsock", map[string]any{
		"vsock_id":  "vsock0",
		"guest_cid": spec.VsockCID,
		"uds_path":  vsockUDSPath,
	}); err != nil {
		_ = d.stopProcess(vm)
		_ = os.RemoveAll(stateDir)
		if jailerDir != "" {
			_ = os.RemoveAll(jailerDir)
		}
		return VMHandle{}, fmt.Errorf("%w: configuring vsock: %v", ErrDriverFailure, err)
	}

	if err := client.putJSON(ctx, "/actions", map[string]any{
		"action_type": "InstanceStart",
	}); err != nil {
		_ = d.stopProcess(vm)
		_ = os.RemoveAll(stateDir)
		if jailerDir != "" {
			_ = os.RemoveAll(jailerDir)
		}
		return VMHandle{}, fmt.Errorf("%w: starting instance: %v", ErrDriverFailure, err)
	}

	if err := d.persistVMState(vmID, vm); err != nil {
		_ = d.stopProcess(vm)
		_ = os.RemoveAll(stateDir)
		if jailerDir != "" {
			_ = os.RemoveAll(jailerDir)
		}
		return VMHandle{}, fmt.Errorf("%w: persisting vm state: %v", ErrDriverFailure, err)
	}

	d.mu.Lock()
	d.vms[vmID] = vm
	d.mu.Unlock()

	return VMHandle{
		ID:        vmID,
		PID:       firecrackerPID,
		VsockCID:  spec.VsockCID,
		StartedAt: time.Now(),
	}, nil
}

func (d *FirecrackerDriver) Stop(_ context.Context, id string) error {
	vm, err := d.getVM(id)
	if err != nil {
		return err
	}
	return d.stopProcess(vm)
}

func (d *FirecrackerDriver) IsHealthy(ctx context.Context, id string) (bool, error) {
	vm, err := d.getVM(id)
	if err != nil {
		return false, err
	}

	if vm.daemonized {
		alive, err := processAlive(vm.firecrackerPID)
		if err != nil {
			return false, fmt.Errorf("%w: checking process health: %v", ErrDriverFailure, err)
		}
		if !alive {
			return false, fmt.Errorf("%w: process exited", ErrDriverFailure)
		}
	} else {
		select {
		case <-vm.waitCh:
			return false, fmt.Errorf("%w: process exited", ErrDriverFailure)
		default:
		}
	}

	client := newFirecrackerClient(vm.apiSock)
	if err := client.get(ctx, "/machine-config"); err != nil {
		return false, fmt.Errorf("%w: health check call failed: %v", ErrDriverFailure, err)
	}
	return true, nil
}

func (d *FirecrackerDriver) Cleanup(_ context.Context, id string) error {
	vmID, err := normalizeVMID(id)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDriverFailure, err)
	}

	d.mu.Lock()
	vm, ok := d.vms[vmID]
	if ok {
		delete(d.vms, vmID)
	}
	d.mu.Unlock()

	if !ok {
		var loadErr error
		vm, ok, loadErr = d.loadVMForCleanup(vmID)
		if loadErr != nil {
			return loadErr
		}
		if !ok {
			return nil
		}
	}

	_ = d.stopProcess(vm)
	if err := os.RemoveAll(vm.stateDir); err != nil {
		return fmt.Errorf("%w: cleanup state dir: %v", ErrDriverFailure, err)
	}
	if vm.jailerDir != "" {
		if err := os.RemoveAll(vm.jailerDir); err != nil {
			return fmt.Errorf("%w: cleanup jailer dir: %v", ErrDriverFailure, err)
		}
	}
	return nil
}

func (d *FirecrackerDriver) stopProcess(vm *firecrackerVM) error {
	if vm.daemonized {
		return terminatePID(vm.firecrackerPID, d.stopTimeout)
	}

	if vm.waitCh == nil {
		return nil
	}

	select {
	case <-vm.waitCh:
		return nil
	default:
	}

	if vm.cmd == nil || vm.cmd.Process == nil {
		return nil
	}
	if err := vm.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("%w: stopping process: %v", ErrDriverFailure, err)
	}

	timer := time.NewTimer(d.stopTimeout)
	defer timer.Stop()

	select {
	case <-vm.waitCh:
		return nil
	case <-timer.C:
		_ = vm.cmd.Process.Kill()
		<-vm.waitCh
		return nil
	}
}

func (d *FirecrackerDriver) getVM(id string) (*firecrackerVM, error) {
	vmID, err := normalizeVMID(id)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDriverFailure, err)
	}

	d.mu.Lock()
	vm, ok := d.vms[vmID]
	d.mu.Unlock()
	if ok {
		return vm, nil
	}

	vm, ok, err = d.loadPersistedVM(vmID)
	if err != nil {
		return nil, err
	}
	if !ok || !vm.daemonized || vm.firecrackerPID <= 0 {
		return nil, fmt.Errorf("%w: %s", ErrVMNotFound, vmID)
	}

	alive, err := processAlive(vm.firecrackerPID)
	if err != nil {
		return nil, fmt.Errorf("%w: checking process health: %v", ErrDriverFailure, err)
	}
	if !alive {
		return nil, fmt.Errorf("%w: %s", ErrVMNotFound, vmID)
	}

	d.mu.Lock()
	if existing, exists := d.vms[vmID]; exists {
		d.mu.Unlock()
		return existing, nil
	}
	d.vms[vmID] = vm
	d.mu.Unlock()
	return vm, nil
}

func (d *FirecrackerDriver) loadVMForCleanup(id string) (*firecrackerVM, bool, error) {
	vmID, err := normalizeVMID(id)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrDriverFailure, err)
	}

	vm, ok, err := d.loadPersistedVM(vmID)
	if err != nil {
		return nil, false, err
	}
	if ok {
		return vm, true, nil
	}

	stateDir := filepath.Join(d.stateRoot, vmID)
	if _, err := os.Stat(stateDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("%w: checking state dir: %v", ErrDriverFailure, err)
	}

	vm = &firecrackerVM{
		stateDir:   stateDir,
		jailerDir:  d.inferJailerDir(vmID),
		daemonized: false,
	}
	return vm, true, nil
}

func configureMachine(ctx context.Context, client *firecrackerClient, vcpus, memMB int) error {
	modernPayload := map[string]any{
		"vcpu_count":   vcpus,
		"mem_size_mib": memMB,
		"smt":          false,
	}
	err := client.putJSON(ctx, "/machine-config", modernPayload)
	if err == nil {
		return nil
	}

	httpErr, ok := err.(*firecrackerHTTPError)
	if !ok || httpErr.StatusCode != http.StatusBadRequest {
		return err
	}

	legacyPayload := map[string]any{
		"vcpu_count":   vcpus,
		"mem_size_mib": memMB,
		"ht_enabled":   false,
	}
	legacyErr := client.putJSON(ctx, "/machine-config", legacyPayload)
	if legacyErr == nil {
		return nil
	}
	return fmt.Errorf("machine-config smt mode failed (%v); ht_enabled fallback failed (%v)", err, legacyErr)
}

func normalizeVMID(raw string) (string, error) {
	vmID := strings.TrimSpace(raw)
	if vmID == "" {
		return "", fmt.Errorf("vm id is required")
	}
	if !vmIDPattern.MatchString(vmID) {
		return "", fmt.Errorf("invalid vm id %q: allowed pattern %q", vmID, vmIDPattern.String())
	}
	return vmID, nil
}

func requireAbsoluteFilePath(path, label string) error {
	candidate := strings.TrimSpace(path)
	if candidate == "" {
		return fmt.Errorf("%s is required", label)
	}
	if !filepath.IsAbs(candidate) {
		return fmt.Errorf("%s must be an absolute file path", label)
	}
	info, err := os.Stat(candidate)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s %q does not exist", label, candidate)
		}
		return fmt.Errorf("%s %q cannot be read: %w", label, candidate, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s %q must be a file, got directory", label, candidate)
	}
	return nil
}

func createSparseDataDrive(path string, quotaMB int) error {
	if quotaMB <= 0 {
		return fmt.Errorf("data drive quota must be > 0")
	}
	if quotaMB > maxDataDriveQuotaMB {
		return fmt.Errorf("data drive quota must be <= %d MB", maxDataDriveQuotaMB)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("data drive path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	// #nosec G304 -- path is validated absolute and derived from driver-managed state dir.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	sizeBytes := int64(quotaMB) * 1024 * 1024
	if sizeBytes <= 0 {
		return fmt.Errorf("data drive size overflow for quota %d MB", quotaMB)
	}
	if err := f.Truncate(sizeBytes); err != nil {
		return err
	}
	return nil
}

func resolveAndValidateExecutable(binary, defaultName string) (string, error) {
	candidate := strings.TrimSpace(binary)
	if candidate == "" {
		candidate = defaultName
	}
	resolved, err := exec.LookPath(candidate)
	if err != nil {
		return "", fmt.Errorf("executable %q not found in PATH", candidate)
	}
	absPath, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolving executable %q: %w", resolved, err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return "", fmt.Errorf("checking executable %q: %w", absPath, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("executable %q is a directory", absPath)
	}
	mode := info.Mode().Perm()
	if mode&0o111 == 0 {
		return "", fmt.Errorf("executable %q is not marked executable", absPath)
	}
	if mode&0o022 != 0 {
		return "", fmt.Errorf("executable %q must not be group/world writable", absPath)
	}
	return absPath, nil
}

func (d *FirecrackerDriver) inferJailerDir(id string) string {
	if !d.jailer.Enabled {
		return ""
	}
	if strings.TrimSpace(d.jailer.ChrootBaseDir) == "" {
		return ""
	}
	execName := filepath.Base(d.binaryPath)
	return filepath.Join(d.jailer.ChrootBaseDir, execName, id)
}

func (d *FirecrackerDriver) persistVMState(vmID string, vm *firecrackerVM) error {
	if strings.TrimSpace(vm.stateDir) == "" {
		return fmt.Errorf("state dir is required")
	}

	state := firecrackerVMPersistedState{
		VMID:           vmID,
		StateDir:       vm.stateDir,
		JailerDir:      vm.jailerDir,
		APISock:        vm.apiSock,
		FirecrackerPID: 0,
		Daemonized:     vm.daemonized,
	}
	if vm.daemonized {
		state.FirecrackerPID = vm.firecrackerPID
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}

	statePath := filepath.Join(vm.stateDir, defaultVMStateFileName)
	tmpPath := statePath + ".tmp"
	if err := os.WriteFile(tmpPath, encoded, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, statePath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func (d *FirecrackerDriver) loadPersistedVM(id string) (*firecrackerVM, bool, error) {
	vmID, err := normalizeVMID(id)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrDriverFailure, err)
	}

	statePath := filepath.Join(d.stateRoot, vmID, defaultVMStateFileName)
	// #nosec G304 -- statePath is generated from internal state root and vm ID.
	encoded, err := os.ReadFile(statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("%w: reading vm state for %s: %v", ErrDriverFailure, vmID, err)
	}

	var state firecrackerVMPersistedState
	if err := json.Unmarshal(encoded, &state); err != nil {
		return nil, false, fmt.Errorf("%w: decoding vm state for %s: %v", ErrDriverFailure, vmID, err)
	}

	if persistedID := strings.TrimSpace(state.VMID); persistedID != "" && persistedID != vmID {
		return nil, false, fmt.Errorf("%w: vm state mismatch: expected %s got %s", ErrDriverFailure, vmID, persistedID)
	}

	stateDir := strings.TrimSpace(state.StateDir)
	if stateDir == "" {
		stateDir = filepath.Join(d.stateRoot, vmID)
	}
	apiSock := strings.TrimSpace(state.APISock)
	if apiSock == "" {
		return nil, false, fmt.Errorf("%w: vm state missing api socket for %s", ErrDriverFailure, vmID)
	}

	vm := &firecrackerVM{
		stateDir:       stateDir,
		jailerDir:      strings.TrimSpace(state.JailerDir),
		apiSock:        apiSock,
		firecrackerPID: state.FirecrackerPID,
		daemonized:     state.Daemonized,
		waitCh:         make(chan struct{}),
	}
	close(vm.waitCh)
	return vm, true, nil
}

func waitForSocket(ctx context.Context, socketPath string) error {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	dialer := &net.Dialer{}

	for {
		conn, err := dialer.DialContext(ctx, "unix", socketPath)
		if err == nil {
			_ = conn.Close()
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func waitForPIDFile(ctx context.Context, pidPath string) (int, error) {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

	for {
		// #nosec G304 -- pidPath points to jailer-owned .pid under internal jail dir.
		pidBytes, err := os.ReadFile(pidPath)
		if err == nil {
			pidStr := strings.TrimSpace(string(pidBytes))
			if pidStr == "" {
				select {
				case <-ctx.Done():
					return 0, ctx.Err()
				case <-ticker.C:
					continue
				}
			}
			pid, convErr := strconv.Atoi(pidStr)
			if convErr != nil {
				select {
				case <-ctx.Done():
					return 0, fmt.Errorf("parsing pid file %s: %w", pidPath, convErr)
				case <-ticker.C:
					continue
				}
			}
			if pid <= 0 {
				select {
				case <-ctx.Done():
					return 0, fmt.Errorf("pid file %s contains invalid pid %d", pidPath, pid)
				case <-ticker.C:
					continue
				}
			}
			return pid, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}

		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ticker.C:
		}
	}
}

func terminatePID(pid int, timeout time.Duration) error {
	if pid <= 0 {
		return nil
	}

	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("%w: signaling pid %d: %v", ErrDriverFailure, pid, err)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

	for {
		alive, err := processAlive(pid)
		if err != nil {
			return fmt.Errorf("%w: checking pid %d: %v", ErrDriverFailure, pid, err)
		}
		if !alive {
			return nil
		}

		select {
		case <-timer.C:
			if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("%w: force killing pid %d: %v", ErrDriverFailure, pid, err)
			}
			return nil
		case <-ticker.C:
		}
	}
}

func processAlive(pid int) (bool, error) {
	if pid <= 0 {
		return false, nil
	}

	err := syscall.Kill(pid, 0)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	if errors.Is(err, syscall.EPERM) {
		return true, nil
	}
	return false, err
}

func resolveExecutablePath(binary string) string {
	candidate := strings.TrimSpace(binary)
	if candidate == "" {
		return candidate
	}

	// Preserve unresolved command names; startup will report a clear error.
	if !strings.Contains(candidate, "/") {
		resolved, err := exec.LookPath(candidate)
		if err != nil {
			return candidate
		}
		candidate = resolved
	}

	absPath, err := filepath.Abs(candidate)
	if err != nil {
		return candidate
	}
	return absPath
}

func buildJailerCommandArgs(vmID, firecrackerBinary string, cfg FirecrackerJailerConfig, apiSockInJail string) []string {
	args := []string{
		"--id", vmID,
		"--exec-file", firecrackerBinary,
		"--uid", strconv.Itoa(cfg.UID),
		"--gid", strconv.Itoa(cfg.GID),
		"--chroot-base-dir", cfg.ChrootBaseDir,
	}
	if strings.TrimSpace(cfg.NetNSPath) != "" {
		args = append(args, "--netns", cfg.NetNSPath)
	}
	if cfg.Daemonize {
		args = append(args, "--daemonize")
	}
	args = append(args, "--", "--api-sock", apiSockInJail)
	return args
}

func (d *FirecrackerDriver) prepareJailerLayout(vmID, kernelPath, rootDrive, dataDrive string) (jailerDir, apiSock, kernelInVM, rootInVM, dataInVM string, err error) {
	execName := filepath.Base(d.binaryPath)
	jailerDir = filepath.Join(d.jailer.ChrootBaseDir, execName, vmID)
	jailRoot := filepath.Join(jailerDir, "root")
	runDir := filepath.Join(jailRoot, "run")
	if err := os.MkdirAll(runDir, 0o750); err != nil {
		return "", "", "", "", "", err
	}

	kernelDst := filepath.Join(jailRoot, "kernel")
	rootDst := filepath.Join(jailRoot, "rootfs.ext4")
	if err := linkOrCopyFile(kernelPath, kernelDst); err != nil {
		return "", "", "", "", "", fmt.Errorf("staging kernel: %w", err)
	}
	if err := linkOrCopyFile(rootDrive, rootDst); err != nil {
		return "", "", "", "", "", fmt.Errorf("staging root drive: %w", err)
	}

	apiSock = filepath.Join(runDir, "firecracker.socket")
	kernelInVM = "/kernel"
	rootInVM = "/rootfs.ext4"
	dataInVM = ""
	if strings.TrimSpace(dataDrive) != "" {
		dataDst := filepath.Join(jailRoot, "data.ext4")
		if err := linkOrCopyFile(dataDrive, dataDst); err != nil {
			return "", "", "", "", "", fmt.Errorf("staging data drive: %w", err)
		}
		dataInVM = "/data.ext4"
	}

	return jailerDir, apiSock, kernelInVM, rootInVM, dataInVM, nil
}

func linkOrCopyFile(src, dst string) error {
	if err := requireAbsoluteFilePath(src, "source path"); err != nil {
		return err
	}
	if !filepath.IsAbs(dst) {
		return fmt.Errorf("destination path must be an absolute file path")
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	_ = os.Remove(dst)
	if err := os.Link(src, dst); err == nil {
		return nil
	}

	// #nosec G304 -- src comes from validated kernel/root/data paths controlled by config/spec.
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// #nosec G304 -- dst is generated under internal jail root.
	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}
	return nil
}

type firecrackerClient struct {
	client *http.Client
}

type firecrackerHTTPError struct {
	StatusCode int
	Body       string
}

func (e *firecrackerHTTPError) Error() string {
	if strings.TrimSpace(e.Body) == "" {
		return fmt.Sprintf("status %d", e.StatusCode)
	}
	return fmt.Sprintf("status %d: %s", e.StatusCode, strings.TrimSpace(e.Body))
}

func newFirecrackerClient(socketPath string) *firecrackerClient {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	return &firecrackerClient{
		client: &http.Client{Transport: transport},
	}
}

func (c *firecrackerClient) putJSON(ctx context.Context, path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://localhost"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &firecrackerHTTPError{
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
	}
	return nil
}

func (c *firecrackerClient) get(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost"+path, nil)
	if err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &firecrackerHTTPError{
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
	}
	return nil
}
