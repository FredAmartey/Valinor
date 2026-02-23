#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  install-firecracker.sh <release-tag> [install-dir]

Examples:
  install-firecracker.sh v1.11.0
  install-firecracker.sh v1.11.0 /usr/local/bin
EOF
}

log() {
  printf '[firecracker-install] %s\n' "$*"
}

warn() {
  printf '[firecracker-install] WARN: %s\n' "$*" >&2
}

die() {
  printf '[firecracker-install] ERROR: %s\n' "$*" >&2
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
install_dir="${2:-/usr/local/bin}"
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
need_cmd tar
need_cmd install

artifact="firecracker-${release_tag}-${arch}.tgz"
base_url="https://github.com/firecracker-microvm/firecracker/releases/download/${release_tag}"
artifact_url="${base_url}/${artifact}"
checksum_url="${artifact_url}.sha256.txt"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

log "Downloading ${artifact_url}"
curl -fsSL "${artifact_url}" -o "${tmp_dir}/${artifact}"

if curl -fsSL "${checksum_url}" -o "${tmp_dir}/${artifact}.sha256.txt"; then
  log "Verifying archive checksum"
  (
    cd "${tmp_dir}"
    sha256sum -c "${artifact}.sha256.txt"
  )
else
  warn "Checksum file unavailable at ${checksum_url}; skipping checksum verification"
fi

tar -xzf "${tmp_dir}/${artifact}" -C "${tmp_dir}"

release_dir="${tmp_dir}/release-${release_tag}-${arch}"
firecracker_src="${release_dir}/firecracker-${release_tag}-${arch}"
jailer_src="${release_dir}/jailer-${release_tag}-${arch}"

[[ -x "${firecracker_src}" ]] || die "firecracker binary not found in extracted release"
[[ -x "${jailer_src}" ]] || die "jailer binary not found in extracted release"

run_root mkdir -p "${install_dir}"
run_root install -m 0755 "${firecracker_src}" "${install_dir}/firecracker"
run_root install -m 0755 "${jailer_src}" "${install_dir}/jailer"

log "Installed firecracker and jailer to ${install_dir}"
log "Result: PASS"
