#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

usage() {
  echo "usage: verify-image-rebuild.sh --plan <json> --platform <linux/arch> --output-dir <dir>" >&2
}

plan=
platform=
output_dir=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --plan) plan=${2-}; shift 2 ;;
    --platform) platform=${2-}; shift 2 ;;
    --output-dir) output_dir=${2-}; shift 2 ;;
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
for command in docker jq node python3 trivy; do
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
mkdir -p "${output_dir}/first" "${output_dir}/second" "${output_dir}/comparisons"
case "${platform}" in
  linux/amd64)
    artifact_arch=amd64
    "${repo_root}/tests/scripts/check-amd64-v3-host.sh" \
      >"${output_dir}/amd64-v3-host-preflight.json"
    ;;
  linux/arm64) artifact_arch=arm64 ;;
  linux/riscv64) artifact_arch=riscv64 ;;
  *) echo "unsupported platform: ${platform}" >&2; exit 1 ;;
esac

for role in $(jq -er '.images[].role' "${plan}"); do
  first=$(
    "${repo_root}/tests/scripts/build-docker-image-artifact.sh" \
      --plan "${plan}" --role "${role}" --platform "${platform}" --output-dir "${output_dir}/first"
  )
  second=$(
    "${repo_root}/tests/scripts/build-docker-image-artifact.sh" \
      --plan "${plan}" --role "${role}" --platform "${platform}" \
      --output-dir "${output_dir}/second" --no-cache
  )
  first_metadata="${output_dir}/first/${role}-${artifact_arch}.build.json"
  second_metadata="${output_dir}/second/${role}-${artifact_arch}.build.json"
  first_evidence="${output_dir}/first/${role}-${artifact_arch}.evidence.json"
  second_evidence="${output_dir}/second/${role}-${artifact_arch}.evidence.json"
  python3 "${repo_root}/tests/scripts/validate-image-evidence.py" \
    --plan "${plan}" --role "${role}" --platform "${platform}" \
    --archive "${first}" --metadata "${first_metadata}" --checksum "${first}.sha256" \
    --output "${first_evidence}"
  python3 "${repo_root}/tests/scripts/validate-image-evidence.py" \
    --plan "${plan}" --role "${role}" --platform "${platform}" \
    --archive "${second}" --metadata "${second_metadata}" --checksum "${second}.sha256" \
    --output "${second_evidence}"
  first_sbom="${output_dir}/first/${role}-${artifact_arch}.cdx.json"
  second_sbom="${output_dir}/second/${role}-${artifact_arch}.cdx.json"
  first_raw_sbom="${output_dir}/first/${role}-${artifact_arch}.trivy.cdx.json"
  second_raw_sbom="${output_dir}/second/${role}-${artifact_arch}.trivy.cdx.json"
  trivy image --input "${first}" --format cyclonedx --output "${first_raw_sbom}"
  trivy image --input "${second}" --format cyclonedx --output "${second_raw_sbom}"
  python3 "${repo_root}/tests/scripts/normalize-cyclonedx.py" \
    --plan "${plan}" --role "${role}" --platform "${platform}" \
    --input "${first_raw_sbom}" --output "${first_sbom}"
  python3 "${repo_root}/tests/scripts/normalize-cyclonedx.py" \
    --plan "${plan}" --role "${role}" --platform "${platform}" \
    --input "${second_raw_sbom}" --output "${second_sbom}"
  python3 "${repo_root}/tests/scripts/compare-image-artifacts.py" \
    --first-archive "${first}" --second-archive "${second}" \
    --first-sbom "${first_sbom}" --second-sbom "${second_sbom}" \
    --output "${output_dir}/comparisons/${role}-${artifact_arch}.json"
done
