# Firecracker Real Jailer Flow Design

**Date:** 2026-02-22  
**Status:** Proposed

## Goal

Implement real Firecracker jailer mode in Valinor so each MicroVM runs in a dedicated chroot with constrained privileges and cgroups.

## Current State

- Linux Firecracker driver exists and manages VM lifecycle via API socket.
- `jailer_path` is currently rejected at startup (fail-fast).
- No chroot, cgroup, or jailer PID/signal management is implemented yet.

## Why This Matters

`jailer` is part of Firecracker's hardening model: it sets up chroot, drops privileges (`uid`/`gid`), and can attach cgroups before launching Firecracker.

## Proposed Runtime Model

### Configuration changes

Replace single `jailer_path` toggle with explicit jailer config:

```yaml
orchestrator:
  firecracker:
    kernel_path: /var/lib/valinor/vmlinux
    root_drive: /var/lib/valinor/rootfs.ext4
    jailer:
      enabled: true
      binary_path: /usr/local/bin/jailer
      chroot_base_dir: /srv/jailer
      uid: 1001
      gid: 1001
      netns_path: ""
      daemonize: true
      cgroup_version: "2"
      cgroups:
        cpuset.cpus: "0"
        cpu.max: "100000 200000"
        memory.max: "536870912"
```

### Driver state additions

Track jailer-specific paths per VM:
- jail root (`<chroot_base>/<exec_file>/<vmid>/root`)
- jailed API socket host path (`<jail_root>/run/firecracker.socket`)
- jailer process PID (if daemonized, read from pid file)

## Start Flow (Jailer Mode)

1. Validate jailer config (`uid/gid/chroot_base_dir/binary_path`).
2. Build per-VM bundle directory and stage artifacts:
   - kernel
   - rootfs
   - optional writable data drive
3. Pre-create `run/` inside jail root so API socket path is deterministic.
4. Start jailer with:
   - `--id`
   - `--exec-file`
   - `--uid` / `--gid`
   - `--chroot-base-dir`
   - optional `--netns`
   - optional cgroup flags
   - `-- --api-sock /run/firecracker.socket`
5. Wait for jailed API socket at host path.
6. Run existing Firecracker API configuration sequence.
7. Persist PID/socket/chroot metadata in in-memory VM map.

## Stop/Cleanup Flow

1. Try graceful shutdown via API action (if available), then SIGTERM fallback.
2. Stop jailer process if still alive.
3. Remove VM state dir and jail root.
4. Ensure cgroup paths are removed or reclaimed.

## Testing Strategy

1. Unit tests for command construction and validation paths.
2. Linux helper integration test with fake `jailer` binary:
   - assert jailer args include `--id`, `--uid`, `--gid`, `--chroot-base-dir`.
   - assert API socket path switches to jailed host path.
3. Opt-in real e2e test on Linux KVM host with real jailer enabled.
4. CI keeps helper-based tests always on Linux; real-jailer e2e remains gated by env flag.

## Rollout

1. Introduce new config schema while keeping current non-jailer mode default.
2. Implement jailer mode behind `jailer.enabled`.
3. Run canary in a single environment with strict audit logging.
4. Promote after repeated lifecycle stability and cleanup checks.

## Non-Goals (This iteration)

- Full seccomp profile customization
- Snapshot/restore with jailer
- Cross-host live migration
