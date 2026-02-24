# Firecracker Build and Test Runbook

This runbook defines the practical path to build and validate Firecracker support in Valinor.

## 0) Linux KVM host prerequisites

Ubuntu/Debian example:

```bash
sudo apt-get update
sudo apt-get install -y qemu-kvm e2fsprogs squashfs-tools curl tar openssl python3
```

Then verify KVM:

```bash
./scripts/firecracker/check-kvm.sh
```

## 1) Bootstrap Firecracker + kernel/rootfs artifacts (Linux)

Use a pinned Firecracker release tag for repeatability:

```bash
./scripts/firecracker/bootstrap-linux-kvm.sh v1.11.0 /var/lib/valinor
```

This will:
- verify `/dev/kvm` access
- install `firecracker` + `jailer` binaries
- fetch matching CI kernel/rootfs artifacts
- install pinned guest runtime versions:
  - Node.js `v22.22.0` (verified by SHA-256)
  - OpenClaw `2026.2.23` (verified by npm `sha512-...` integrity)
- build `/var/lib/valinor/rootfs.ext4`
- write `/var/lib/valinor/runtime-versions.json`

Runtime override knobs (must provide matching verification values):

```bash
VALINOR_GUEST_NODE_VERSION=v22.22.0
VALINOR_GUEST_NODE_SHA256=<sha256-for-arch>
VALINOR_GUEST_OPENCLAW_VERSION=2026.2.23
VALINOR_GUEST_OPENCLAW_INTEGRITY=sha512-...
```

If you want individual steps:

```bash
./scripts/firecracker/check-kvm.sh
./scripts/firecracker/install-firecracker.sh v1.11.0
./scripts/firecracker/fetch-ci-artifacts.sh v1.11.0 /var/lib/valinor
```

Inspect pinned runtime manifest:

```bash
cat /var/lib/valinor/runtime-versions.json
```

## 2) Fast local verification (any OS)

These checks prove code compiles and non-Linux fallback behavior remains stable:

```bash
go test ./cmd/valinor -v
go test ./internal/orchestrator -run TestMockDriver -v
go build ./...
```

## 3) Linux compile check for Linux-only tests (without running them)

Use this on macOS/Windows to ensure Linux-only Firecracker test code compiles:

```bash
GOOS=linux GOARCH=amd64 go test ./cmd/valinor -c -o /tmp/valinor_cmd_linux.test
GOOS=linux GOARCH=amd64 go test ./internal/orchestrator -c -o /tmp/valinor_orchestrator_linux.test
```

## 4) Linux CI-level behavior tests (fake Firecracker helper)

On a Linux host, these tests validate the Firecracker driver lifecycle without requiring nested virtualization:

```bash
go test ./internal/orchestrator -run 'TestFirecrackerDriver_' -v
```

What this covers:
- process launch wiring (`firecracker --api-sock`)
- jailer launch wiring (`jailer --id ... --exec-file ... -- --api-sock ...`)
- API socket waiting
- machine/boot/drive/vsock config sequence
- instance start action
- stop + cleanup behavior

## 5) Real Firecracker end-to-end test (Linux, opt-in)

This uses the actual Firecracker binary and assets. Required environment:
- `VALINOR_FIRECRACKER_E2E=1`
- `VALINOR_FIRECRACKER_KERNEL_PATH=/absolute/path/to/vmlinux`
- `VALINOR_FIRECRACKER_ROOT_DRIVE=/absolute/path/to/rootfs.ext4`
- optional `VALINOR_FIRECRACKER_BIN=/absolute/path/to/firecracker`

Before running e2e:

```bash
./scripts/firecracker/check-kvm.sh
```

Run:

```bash
VALINOR_FIRECRACKER_E2E=1 \
VALINOR_FIRECRACKER_KERNEL_PATH=/var/lib/valinor/vmlinux \
VALINOR_FIRECRACKER_ROOT_DRIVE=/var/lib/valinor/rootfs.ext4 \
go test ./internal/orchestrator -run TestFirecrackerDriver_RealBinaryLifecycle -v
```

## 6) Start Valinor with Firecracker driver

Example config (no jailer):

```yaml
orchestrator:
  driver: "firecracker"
  warm_pool_size: 2
  health_interval_secs: 10
  reconcile_interval_secs: 30
  max_consecutive_failures: 3
  firecracker:
    kernel_path: "/var/lib/valinor/vmlinux"
    root_drive: "/var/lib/valinor/rootfs.ext4"
    jailer_path: ""
    workspace:
      enabled: true
      quotamb: 2048
    network:
      policy: "isolated" # dev-only
```

Example config (phase-1 jailer mode):

```yaml
orchestrator:
  driver: "firecracker"
  firecracker:
    kernel_path: "/var/lib/valinor/vmlinux"
    root_drive: "/var/lib/valinor/rootfs.ext4"
    jailer:
      enabled: true
      binary_path: "/usr/local/bin/jailer"
      chroot_base_dir: "/srv/jailer"
      uid: 1001
      gid: 1001
      netns_path: "/var/run/netns/valinor-egress"
      daemonize: false
    workspace:
      enabled: true
      quotamb: 2048
    network:
      policy: "outbound_only"
```

Set `daemonize: true` if you want detached jailer execution. Valinor now supervises the daemonized Firecracker process using the jailer `.pid` file under the jail root.
Valinor also persists per-VM metadata to `<stateRoot>/<vmID>/vm-state.json`, so daemonized VMs can be reattached after a Valinor process restart for health, stop, and cleanup operations.

Startup preflight now fails early if:
- `kernel_path` or `root_drive` is missing or not an absolute file path
- configured Firecracker binary is not found in `PATH`
- jailer is enabled but `chroot_base_dir` is missing/relative
- jailer binary is not found in `PATH`
- jailer `uid`/`gid` is invalid (<0)
- workspace is enabled with non-positive `workspace.quotamb`
- network policy is `outbound_only` without jailer enabled and `jailer.netns_path`
- non-dev mode uses `network.policy=isolated`

This avoids deferred runtime failures on first VM provisioning.

## 7) Linux/KVM verification checklist (copy/paste)

Run this on a Linux host with KVM:

```bash
set -euo pipefail

cd /path/to/Valinor

# Host capability
./scripts/firecracker/check-kvm.sh

# Baseline compile + non-Linux fallback behavior
go test ./cmd/valinor -v
go test ./internal/orchestrator -run TestMockDriver -v
go build ./...

# Linux Firecracker helper lifecycle tests (includes jailer daemonize + reattach tests)
go test ./internal/orchestrator -run 'TestFirecrackerDriver_(Start|Reattach|Cleanup)' -v

# Real Firecracker e2e
VALINOR_FIRECRACKER_E2E=1 \
VALINOR_FIRECRACKER_KERNEL_PATH=/var/lib/valinor/vmlinux \
VALINOR_FIRECRACKER_ROOT_DRIVE=/var/lib/valinor/rootfs.ext4 \
go test ./internal/orchestrator -run TestFirecrackerDriver_RealBinaryLifecycle -v
```

Expected result:
- all commands exit `0`
- helper tests include:
  - `TestFirecrackerDriver_StartStopCleanup_WithJailerDaemonize`
  - `TestFirecrackerDriver_ReattachDaemonizedJailerAfterDriverRestart`
  - `TestFirecrackerDriver_CleanupDaemonizedJailerAfterDriverRestart`
