#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bootstrap-linux-kvm.sh <release-tag> [artifact-dir]

Examples:
  bootstrap-linux-kvm.sh v1.11.0
  bootstrap-linux-kvm.sh v1.11.0 /var/lib/heimdall
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

release_tag="${1:-}"
artifact_dir="${2:-/var/lib/heimdall}"
if [[ -z "${release_tag}" ]]; then
  usage
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${script_dir}/check-kvm.sh"
"${script_dir}/install-firecracker.sh" "${release_tag}"
"${script_dir}/fetch-ci-artifacts.sh" "${release_tag}" "${artifact_dir}"

cat <<EOF

Bootstrap complete.

Use these settings in Heimdall:
  orchestrator.driver=firecracker
  orchestrator.firecracker.kernel_path=${artifact_dir}/vmlinux
  orchestrator.firecracker.root_drive=${artifact_dir}/rootfs.ext4
  orchestrator.firecracker.jailer.enabled=false

Pinned guest runtime manifest:
  ${artifact_dir}/runtime-versions.json

Quick e2e test:
  HEIMDALL_FIRECRACKER_E2E=1 \\
  HEIMDALL_FIRECRACKER_KERNEL_PATH=${artifact_dir}/vmlinux \\
  HEIMDALL_FIRECRACKER_ROOT_DRIVE=${artifact_dir}/rootfs.ext4 \\
  go test ./internal/orchestrator -run TestFirecrackerDriver_RealBinaryLifecycle -v
EOF
