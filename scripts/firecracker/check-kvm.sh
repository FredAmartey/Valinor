#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[firecracker-check] %s\n' "$*"
}

warn() {
  printf '[firecracker-check] WARN: %s\n' "$*" >&2
}

die() {
  printf '[firecracker-check] ERROR: %s\n' "$*" >&2
  exit 1
}

if [[ "$(uname -s)" != "Linux" ]]; then
  die "Linux host required."
fi

if ! grep -Eq '(vmx|svm)' /proc/cpuinfo; then
  warn "CPU virtualization flags (vmx/svm) not detected in /proc/cpuinfo."
fi

if ! lsmod | grep -Eq '^kvm'; then
  warn "KVM module not shown in lsmod output."
fi

if [[ ! -e /dev/kvm ]]; then
  die "/dev/kvm is missing. Ensure KVM is enabled in BIOS/UEFI and kernel modules are loaded."
fi

if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  kvm_group="$(stat -c '%G' /dev/kvm 2>/dev/null || echo kvm)"
  die "Current user lacks read/write on /dev/kvm. Add user to '${kvm_group}' group or grant ACL."
fi

log "KVM device access looks good."
log "Result: PASS"
