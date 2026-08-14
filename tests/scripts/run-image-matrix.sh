#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

usage() {
  echo "usage: run-image-matrix.sh --plan <json> --platform <linux/arch> --output-dir <dir> [--qemu-mode rootless]" >&2
}

plan=
platform=
output_dir=
qemu_mode=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --plan) plan=${2-}; shift 2 ;;
    --platform) platform=${2-}; shift 2 ;;
    --output-dir) output_dir=${2-}; shift 2 ;;
    --qemu-mode) qemu_mode=${2-}; shift 2 ;;
    --help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
if [ -z "${plan}" ] || [ -z "${platform}" ] || [ -z "${output_dir}" ]; then
  usage
  exit 2
fi

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
case "${plan}" in /*) ;; *) plan="${PWD}/${plan}" ;; esac
mkdir -p "${output_dir}"
output_dir=$(CDPATH='' cd -- "${output_dir}" && pwd)

for command in docker jq node python3 sha256sum trivy; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "missing required command: ${command}" >&2
    exit 1
  }
done
if [ ! -f "${repo_root}/devops/dist/cli.js" ]; then
  echo "devops CLI is not built; run pnpm --filter @filebelt/devops build" >&2
  exit 1
fi
node "${repo_root}/devops/dist/cli.js" validate-image-plan --input "${plan}"
if ! trivy --version | grep -Eq '^Version: 0\.74\.0$'; then
  echo "Phase 1 requires Trivy 0.74.0" >&2
  exit 1
fi

case "${platform}" in
  linux/amd64) artifact_arch=amd64 ;;
  linux/arm64) artifact_arch=arm64 ;;
  linux/riscv64) artifact_arch=riscv64 ;;
  *) echo "unsupported platform: ${platform}" >&2; exit 1 ;;
esac

for role in $(jq -er '.images[].role' "${plan}"); do
  archive=$(
    "${repo_root}/tests/scripts/build-docker-image-artifact.sh" \
      --plan "${plan}" --role "${role}" --platform "${platform}" --output-dir "${output_dir}"
  )
  validation="${output_dir}/${role}-${artifact_arch}.validation.json"
  evidence="${output_dir}/${role}-${artifact_arch}.evidence.json"
  metadata="${output_dir}/${role}-${artifact_arch}.build.json"
  checksum="${archive}.sha256"
  smoke="${output_dir}/${role}-${artifact_arch}.smoke.json"
  raw_sbom="${output_dir}/${role}-${artifact_arch}.trivy.cdx.json"
  sbom="${output_dir}/${role}-${artifact_arch}.cdx.json"
  runtime_sbom="${output_dir}/${role}-${artifact_arch}.runtime.cdx.json"
  vulnerabilities="${output_dir}/${role}-${artifact_arch}.trivy.json"
  decision="${output_dir}/${role}-${artifact_arch}.vulnerability-decision.json"

  python3 "${repo_root}/tests/scripts/validate-image-evidence.py" \
    --plan "${plan}" --role "${role}" --platform "${platform}" \
    --archive "${archive}" --metadata "${metadata}" --checksum "${checksum}" \
    --output "${evidence}"
  python3 "${repo_root}/tests/scripts/validate-image.py" \
    --plan "${plan}" --role "${role}" --platform "${platform}" \
    --archive "${archive}" --output "${validation}"
  "${repo_root}/tests/scripts/smoke-image-artifact.sh" \
    --plan "${plan}" --role "${role}" --platform "${platform}" \
    --archive "${archive}" --output "${smoke}" ${qemu_mode:+--qemu-mode "${qemu_mode}"}
  trivy image --input "${archive}" --format cyclonedx --output "${raw_sbom}"
  python3 "${repo_root}/tests/scripts/normalize-cyclonedx.py" \
    --plan "${plan}" --role "${role}" --platform "${platform}" \
    --input "${raw_sbom}" --output "${sbom}" --runtime-output "${runtime_sbom}"
  trivy sbom --format json --output "${vulnerabilities}" "${runtime_sbom}"
  node "${repo_root}/devops/dist/cli.js" evaluate-vulnerabilities \
    --trivy "${vulnerabilities}" \
    --policy "${repo_root}/supply-chain/image-vulnerability-exceptions.json" \
    --role "${role}" --platform "${platform}" --as-of "$(date -u +%F)" --output "${decision}"
done
