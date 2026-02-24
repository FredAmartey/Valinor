#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  install-guest-runtime.sh <rootfs-tree> [arch]

Examples:
  install-guest-runtime.sh /tmp/rootfs-tree
  install-guest-runtime.sh /tmp/rootfs-tree x86_64

Environment:
  VALINOR_GUEST_NODE_VERSION            default: v22.22.0
  VALINOR_GUEST_NODE_SHA256             required when node version overridden
  VALINOR_GUEST_OPENCLAW_VERSION        default: 2026.2.23
  VALINOR_GUEST_OPENCLAW_INTEGRITY      required when openclaw version overridden
EOF
}

log() {
  printf '[guest-runtime] %s\n' "$*"
}

die() {
  printf '[guest-runtime] ERROR: %s\n' "$*" >&2
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

rootfs_tree="${1:-}"
arch_raw="${2:-$(uname -m)}"

[[ -n "${rootfs_tree}" ]] || {
  usage
  exit 1
}
[[ -d "${rootfs_tree}" ]] || die "rootfs-tree directory does not exist: ${rootfs_tree}"
[[ -d "${rootfs_tree}/etc" ]] || die "rootfs-tree does not look like a Linux rootfs: ${rootfs_tree}"

case "${arch_raw}" in
  x86_64|amd64)
    arch="x86_64"
    node_arch="x64"
    ;;
  aarch64|arm64)
    arch="aarch64"
    node_arch="arm64"
    ;;
  *)
    die "Unsupported architecture: ${arch_raw}"
    ;;
esac

need_cmd curl
need_cmd tar
need_cmd sha256sum
need_cmd openssl
need_cmd install
need_cmd rm
need_cmd mv
need_cmd ln
need_cmd date
need_cmd python3

default_node_version="v22.22.0"
default_node_sha256_x86_64="9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37"
default_node_sha256_aarch64="1bf1eb9ee63ffc4e5d324c0b9b62cf4a289f44332dfef9607cea1a0d9596ba6f"
default_openclaw_version="2026.2.23"
default_openclaw_integrity="sha512-7I7G898212v3OzUidgM8kZdZYAziT78Dc5zgeqsV2tfCbINtHK0Pdc2rg2eDLoDYAcheLh0fvH5qn/15Yu9q7A=="

node_version="${VALINOR_GUEST_NODE_VERSION:-${default_node_version}}"
node_sha256="${VALINOR_GUEST_NODE_SHA256:-}"
openclaw_version="${VALINOR_GUEST_OPENCLAW_VERSION:-${default_openclaw_version}}"
openclaw_integrity="${VALINOR_GUEST_OPENCLAW_INTEGRITY:-}"

if [[ -z "${node_sha256}" ]]; then
  if [[ "${node_version}" == "${default_node_version}" ]]; then
    case "${arch}" in
      x86_64)
        node_sha256="${default_node_sha256_x86_64}"
        ;;
      aarch64)
        node_sha256="${default_node_sha256_aarch64}"
        ;;
      *)
        die "No default node sha256 for architecture: ${arch}"
        ;;
    esac
  else
    die "VALINOR_GUEST_NODE_SHA256 is required when VALINOR_GUEST_NODE_VERSION is overridden"
  fi
fi

if [[ -z "${openclaw_integrity}" ]]; then
  if [[ "${openclaw_version}" == "${default_openclaw_version}" ]]; then
    openclaw_integrity="${default_openclaw_integrity}"
  else
    die "VALINOR_GUEST_OPENCLAW_INTEGRITY is required when VALINOR_GUEST_OPENCLAW_VERSION is overridden"
  fi
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

node_archive="node-${node_version}-linux-${node_arch}.tar.xz"
node_url="https://nodejs.org/dist/${node_version}/${node_archive}"
node_tmp="${tmp_dir}/${node_archive}"

log "Downloading Node.js runtime: ${node_url}"
curl -fsSL "${node_url}" -o "${node_tmp}"

actual_node_sha256="$(sha256sum "${node_tmp}" | awk '{print $1}')"
if [[ "${actual_node_sha256}" != "${node_sha256}" ]]; then
  die "Node.js checksum mismatch for ${node_archive}: expected ${node_sha256}, got ${actual_node_sha256}"
fi

log "Verified Node.js checksum (${node_version})"
tar -xJf "${node_tmp}" -C "${tmp_dir}"

node_src_dir="${tmp_dir}/node-${node_version}-linux-${node_arch}"
[[ -x "${node_src_dir}/bin/node" ]] || die "Node binary missing after extraction"
[[ -x "${node_src_dir}/bin/npm" ]] || die "npm binary missing after extraction"

node_dst_dir="${rootfs_tree}/opt/valinor/node"
run_root mkdir -p "${rootfs_tree}/opt/valinor"
run_root rm -rf "${node_dst_dir}"
run_root mv "${node_src_dir}" "${node_dst_dir}"

openclaw_tarball_url="https://registry.npmjs.org/openclaw/-/openclaw-${openclaw_version}.tgz"
openclaw_tmp="${tmp_dir}/openclaw-${openclaw_version}.tgz"

log "Downloading OpenClaw package: ${openclaw_tarball_url}"
curl -fsSL "${openclaw_tarball_url}" -o "${openclaw_tmp}"

actual_openclaw_integrity="sha512-$(openssl dgst -sha512 -binary "${openclaw_tmp}" | openssl base64 -A)"
if [[ "${actual_openclaw_integrity}" != "${openclaw_integrity}" ]]; then
  die "OpenClaw integrity mismatch for version ${openclaw_version}: expected ${openclaw_integrity}, got ${actual_openclaw_integrity}"
fi

log "Verified OpenClaw integrity (${openclaw_version})"

openclaw_prefix="${rootfs_tree}/opt/valinor/openclaw"
run_root rm -rf "${openclaw_prefix}"
run_root mkdir -p "${openclaw_prefix}"

log "Installing OpenClaw into rootfs"
run_root env \
  HOME="${tmp_dir}/npm-home" \
  npm_config_update_notifier=false \
  npm_config_fund=false \
  npm_config_audit=false \
  "${node_dst_dir}/bin/node" "${node_dst_dir}/lib/node_modules/npm/bin/npm-cli.js" install --global --prefix "${openclaw_prefix}" --ignore-scripts "${openclaw_tmp}" >/dev/null

openclaw_package_json="${openclaw_prefix}/lib/node_modules/openclaw/package.json"
[[ -f "${openclaw_package_json}" ]] || die "OpenClaw package.json missing after install"
[[ -x "${openclaw_prefix}/bin/openclaw" ]] || die "OpenClaw CLI missing after install"

installed_openclaw_version="$(python3 -c "import json; print(json.load(open('${openclaw_package_json}'))['version'])")"
if [[ "${installed_openclaw_version}" != "${openclaw_version}" ]]; then
  die "Installed OpenClaw version mismatch: expected ${openclaw_version}, got ${installed_openclaw_version}"
fi

run_root mkdir -p "${rootfs_tree}/usr/local/bin"
run_root ln -sfn /opt/valinor/node/bin/node "${rootfs_tree}/usr/local/bin/node"
run_root ln -sfn /opt/valinor/node/bin/npm "${rootfs_tree}/usr/local/bin/npm"
run_root ln -sfn /opt/valinor/openclaw/bin/openclaw "${rootfs_tree}/usr/local/bin/openclaw"

runtime_manifest="${tmp_dir}/runtime-versions.json"
cat >"${runtime_manifest}" <<EOF
{
  "node": {
    "version": "${node_version}",
    "sha256": "${node_sha256}"
  },
  "openclaw": {
    "version": "${openclaw_version}",
    "integrity": "${openclaw_integrity}"
  },
  "generated_at_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF

run_root mkdir -p "${rootfs_tree}/etc/valinor"
run_root install -m 0644 "${runtime_manifest}" "${rootfs_tree}/etc/valinor/runtime-versions.json"

log "Guest runtime install complete"
log "  Node.js: ${node_version}"
log "  OpenClaw: ${openclaw_version}"
log "  Manifest: ${rootfs_tree}/etc/valinor/runtime-versions.json"
log "Result: PASS"
