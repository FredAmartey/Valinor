#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  fetch-ci-artifacts.sh <release-tag> [output-dir]

Examples:
  fetch-ci-artifacts.sh v1.11.0
  fetch-ci-artifacts.sh v1.11.0 /var/lib/valinor

Outputs:
  <output-dir>/vmlinux
  <output-dir>/rootfs.ext4
  <output-dir>/runtime-versions.json

Environment:
  VALINOR_GUEST_NODE_VERSION
  VALINOR_GUEST_NODE_SHA256
  VALINOR_GUEST_OPENCLAW_VERSION
  VALINOR_GUEST_OPENCLAW_INTEGRITY
EOF
}

log() {
  printf '[firecracker-assets] %s\n' "$*"
}

die() {
  printf '[firecracker-assets] ERROR: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

run_root() {
  if (( EUID == 0 )); then
    "$@"
    return
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo "$@"
    return
  fi
  die "Root privileges required for: $*"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

release_tag="${1:-}"
output_dir="${2:-/var/lib/valinor}"
if [[ -z "${release_tag}" ]]; then
  usage
  exit 1
fi

arch="$(uname -m)"
case "${arch}" in
  x86_64|amd64)
    arch="x86_64"
    ;;
  aarch64|arm64)
    arch="aarch64"
    ;;
  *)
    die "Unsupported architecture: ${arch}"
    ;;
esac

need_cmd curl
need_cmd grep
need_cmd sort
need_cmd tail
need_cmd unsquashfs
need_cmd mkfs.ext4
need_cmd truncate

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ci_version="${release_tag%.*}"
prefix="firecracker-ci/${ci_version}/${arch}"
# Use path-style S3 listing to avoid TLS hostname mismatch on dotted bucket names
# like spec.ccfc.min.s3.amazonaws.com.
list_url="https://s3.amazonaws.com/spec.ccfc.min/?prefix="

kernel_manifest_url="${list_url}${prefix}/vmlinux-&list-type=2"
ubuntu_manifest_url="${list_url}${prefix}/ubuntu-&list-type=2"

log "Resolving latest CI kernel for ${prefix}"
kernel_key="$(curl -fsSL "${kernel_manifest_url}" \
  | grep -oE "${prefix}/vmlinux-[0-9]+\.[0-9]+\.[0-9]{1,3}" \
  | sort -V \
  | tail -1)"
[[ -n "${kernel_key}" ]] || die "Unable to resolve kernel key for ${prefix}"

log "Resolving latest CI ubuntu rootfs for ${prefix}"
ubuntu_key="$(curl -fsSL "${ubuntu_manifest_url}" \
  | grep -oE "${prefix}/ubuntu-[0-9]+\.[0-9]+\.squashfs" \
  | sort -V \
  | tail -1)"
[[ -n "${ubuntu_key}" ]] || die "Unable to resolve ubuntu squashfs key for ${prefix}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

kernel_tmp="${tmp_dir}/vmlinux"
squashfs_tmp="${tmp_dir}/rootfs.squashfs"
rootfs_tree="${tmp_dir}/rootfs-tree"
rootfs_img="${tmp_dir}/rootfs.ext4"

log "Downloading kernel: ${kernel_key}"
curl -fsSL "https://s3.amazonaws.com/spec.ccfc.min/${kernel_key}" -o "${kernel_tmp}"

log "Downloading squashfs rootfs: ${ubuntu_key}"
curl -fsSL "https://s3.amazonaws.com/spec.ccfc.min/${ubuntu_key}" -o "${squashfs_tmp}"

log "Extracting squashfs"
unsquashfs -d "${rootfs_tree}" "${squashfs_tmp}" >/dev/null

run_root chown -R root:root "${rootfs_tree}"

log "Installing pinned guest runtime (Node.js + OpenClaw)"
"${script_dir}/install-guest-runtime.sh" "${rootfs_tree}" "${arch}"

rootfs_size="${VALINOR_ROOTFS_SIZE:-2G}"
truncate -s "${rootfs_size}" "${rootfs_img}"

log "Building ext4 rootfs image (${rootfs_size})"
run_root mkfs.ext4 -d "${rootfs_tree}" -F "${rootfs_img}" >/dev/null

run_root mkdir -p "${output_dir}"
run_root install -m 0644 "${kernel_tmp}" "${output_dir}/vmlinux"
run_root install -m 0644 "${rootfs_img}" "${output_dir}/rootfs.ext4"
run_root install -m 0644 "${rootfs_tree}/etc/valinor/runtime-versions.json" "${output_dir}/runtime-versions.json"

log "Artifacts written:"
log "  ${output_dir}/vmlinux"
log "  ${output_dir}/rootfs.ext4"
log "  ${output_dir}/runtime-versions.json"
log "Result: PASS"
