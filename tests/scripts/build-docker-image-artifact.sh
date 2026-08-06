#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

usage() {
  echo "usage: build-docker-image-artifact.sh --plan <json> --role <role> --platform <linux/arch> --output-dir <dir> [--no-cache]" >&2
}

plan=
role=
platform=
output_dir=
no_cache=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --plan) plan=${2-}; shift 2 ;;
    --role) role=${2-}; shift 2 ;;
    --platform) platform=${2-}; shift 2 ;;
    --output-dir) output_dir=${2-}; shift 2 ;;
    --no-cache) no_cache=true; shift ;;
    --help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

if [ -z "${plan}" ] || [ -z "${role}" ] || [ -z "${platform}" ] || [ -z "${output_dir}" ]; then
  usage
  exit 2
fi

for command in docker jq sha256sum; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "missing required command: ${command}" >&2
    exit 1
  }
done

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
case "${plan}" in /*) ;; *) plan="${PWD}/${plan}" ;; esac
mkdir -p "${output_dir}"
output_dir=$(CDPATH='' cd -- "${output_dir}" && pwd)
plan_sha=$(sha256sum "${plan}" | awk '{print $1}')

row_count=$(jq --arg role "${role}" '[.images[] | select(.role == $role)] | length' "${plan}")
if [ "${row_count}" -ne 1 ]; then
  echo "image plan must contain exactly one ${role} row" >&2
  exit 1
fi
if ! jq -e --arg role "${role}" --arg platform "${platform}" \
  '.images[] | select(.role == $role) | .platforms | index($platform) != null' "${plan}" >/dev/null; then
  echo "${role} does not declare ${platform}" >&2
  exit 1
fi

dockerfile=$(jq -er --arg role "${role}" '.images[] | select(.role == $role) | .build.dockerfile' "${plan}")
target=$(jq -er --arg role "${role}" '.images[] | select(.role == $role) | .build.target' "${plan}")
repository=$(jq -er --arg role "${role}" '.images[] | select(.role == $role) | .repository' "${plan}")
version=$(jq -er '.version' "${plan}")
tag=$(jq -er '.tag' "${plan}")
revision=$(jq -er '.source.revision' "${plan}")
source_ref=$(jq -er '.source.ref' "${plan}")
created=$(jq -er '.source.created' "${plan}")
dirty=$(jq -er '.source.dirty | tostring' "${plan}")
kind=$(jq -er '.source.kind' "${plan}")

case "${platform}" in
  linux/amd64) artifact_arch=amd64; builder_stage=builder-native ;;
  linux/arm64) artifact_arch=arm64; builder_stage=builder-native ;;
  linux/riscv64) artifact_arch=riscv64; builder_stage=builder-riscv64 ;;
  *) echo "unsupported platform: ${platform}" >&2; exit 1 ;;
esac

archive="${output_dir}/${role}-${artifact_arch}.docker.tar"
metadata="${output_dir}/${role}-${artifact_arch}.build.json"
checksum="${archive}.sha256"
local_ref="${repository}:${tag}-${artifact_arch}"

if [ "${no_cache}" = true ]; then
  cache_argument=--no-cache
else
  cache_argument=
fi

docker buildx build \
  ${cache_argument} \
  --file "${repo_root}/${dockerfile}" \
  --target "${target}" \
  --platform "${platform}" \
  --tag "${local_ref}" \
  --provenance=false \
  --build-arg "FILEBELT_ROLE=${role}" \
  --build-arg "FILEBELT_BUILDER_STAGE=${builder_stage}" \
  --build-arg "FILEBELT_BUILD_VERSION=${version}" \
  --build-arg "FILEBELT_BUILD_REVISION=${revision}" \
  --build-arg "FILEBELT_BUILD_SOURCE_REF=${source_ref}" \
  --build-arg "FILEBELT_BUILD_DIRTY=${dirty}" \
  --build-arg "FILEBELT_BUILD_KIND=${kind}" \
  --build-arg "FILEBELT_CREATED=${created}" \
  --output "type=docker,dest=${archive}" \
  "${repo_root}"

archive_sha=$(sha256sum "${archive}" | awk '{print $1}')
printf '%s  %s\n' "${archive_sha}" "$(basename -- "${archive}")" >"${checksum}"
jq -n \
  --arg planSha256 "${plan_sha}" \
  --arg role "${role}" \
  --arg platform "${platform}" \
  --arg repository "${repository}" \
  --arg version "${version}" \
  --arg tag "${tag}" \
  --arg localRef "${local_ref}" \
  --arg sourceRevision "${revision}" \
  --arg sourceRef "${source_ref}" \
  --arg sourceCreated "${created}" \
  --argjson sourceDirty "${dirty}" \
  --arg sourceKind "${kind}" \
  --arg dockerfile "${dockerfile}" \
  --arg buildTarget "${target}" \
  --arg archive "$(basename -- "${archive}")" \
  --arg archiveSha256 "${archive_sha}" \
  '{schemaVersion:1,planSha256:$planSha256,role:$role,platform:$platform,repository:$repository,version:$version,tag:$tag,localRef:$localRef,sourceRevision:$sourceRevision,sourceRef:$sourceRef,sourceCreated:$sourceCreated,sourceDirty:$sourceDirty,sourceKind:$sourceKind,dockerfile:$dockerfile,buildTarget:$buildTarget,archive:$archive,archiveSha256:$archiveSha256}' \
  >"${metadata}"

echo "${archive}"
