#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

QEMU_IMAGE='docker.io/tonistiigi/binfmt:qemu-v10.2.3-68@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0'

usage() {
  echo "usage: smoke-image-artifact.sh --plan <json> --role <role> --platform <linux/arch> --archive <tar> --output <json> [--qemu-mode rootless]" >&2
}

plan=
role=
platform=
archive=
output=
qemu_mode=
temporary=
qemu_tag=
loaded_ref=
cleanup() {
  if [ -n "${loaded_ref}" ]; then
    docker image rm --force "${loaded_ref}" >/dev/null 2>&1 || true
  fi
  if [ -n "${qemu_tag}" ]; then
    docker image rm --force "${qemu_tag}" >/dev/null 2>&1 || true
  fi
  if [ -n "${temporary}" ]; then
    rm -rf "${temporary}"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
while [ "$#" -gt 0 ]; do
  case "$1" in
    --plan) plan=${2-}; shift 2 ;;
    --role) role=${2-}; shift 2 ;;
    --platform) platform=${2-}; shift 2 ;;
    --archive) archive=${2-}; shift 2 ;;
    --output) output=${2-}; shift 2 ;;
    --qemu-mode) qemu_mode=${2-}; shift 2 ;;
    --help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
if [ -z "${plan}" ] || [ -z "${role}" ] || [ -z "${platform}" ] || [ -z "${archive}" ] || [ -z "${output}" ]; then
  usage
  exit 2
fi
for command in docker jq python3 tar; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "missing required command: ${command}" >&2
    exit 1
  }
done

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
version=$(jq -er '.version' "${plan}")
revision=$(jq -er '.source.revision' "${plan}")
source_ref=$(jq -er '.source.ref' "${plan}")
dirty=$(jq -er '.source.dirty' "${plan}")
kind=$(jq -er '.source.kind' "${plan}")

python3 "${repo_root}/tests/scripts/validate-image.py" \
  --plan "${plan}" --role "${role}" --platform "${platform}" --archive "${archive}"

if [ "${role}" = filebelt-web ]; then
  probe_mode=static-assets
elif [ "${platform}" = linux/riscv64 ]; then
  if [ "${qemu_mode}" != rootless ]; then
    echo "RISC-V smoke requires --qemu-mode rootless" >&2
    exit 1
  fi
  temporary=$(mktemp -d)
  chmod 0755 "${temporary}"
  qemu_candidate="filebelt-qemu-riscv64-smoke:${role#filebelt-}-$$"
  if docker image inspect "${qemu_candidate}" >/dev/null 2>&1; then
    echo "temporary QEMU image tag already exists: ${qemu_candidate}" >&2
    exit 1
  fi
  qemu_tag=${qemu_candidate}
  binary=$(jq -er --arg role "${role}" '.images[] | select(.role == $role) | .artifact.binary' "${plan}")
  python3 "${repo_root}/tests/scripts/extract-image-file.py" \
    --archive "${archive}" --path "/usr/local/bin/${binary}" --output "${temporary}/probe"
  docker buildx build --platform linux/amd64 --provenance=false --load \
    --build-arg "QEMU_IMAGE=${QEMU_IMAGE}" --tag "${qemu_tag}" \
    --file "${repo_root}/tests/docker/qemu-riscv64/Dockerfile" "${temporary}"
  version_output=$(docker run --rm --platform linux/amd64 --network none --read-only \
    --user 65534:65534 "${qemu_tag}" --version)
  build_info=$(docker run --rm --platform linux/amd64 --network none --read-only \
    --user 65534:65534 "${qemu_tag}" --build-info=json)
  if docker run --rm --platform linux/amd64 --network none --read-only \
    --user 65534:65534 "${qemu_tag}"; then
    echo "${role} unexpectedly accepted an empty invocation" >&2
    exit 1
  fi
  probe_mode=rootless-qemu
else
  archive_ref=$(tar -xOf "${archive}" manifest.json | jq -er \
    'if length == 1 and (.[0].RepoTags | length) == 1 then .[0].RepoTags[0] else error("expected one image tag") end')
  if docker image inspect "${archive_ref}" >/dev/null 2>&1; then
    echo "refusing to replace existing local image tag: ${archive_ref}" >&2
    exit 1
  fi
  loaded_ref=${archive_ref}
  load_output=$(docker load --input "${archive}")
  local_ref=$(printf '%s\n' "${load_output}" | awk -F': ' '/Loaded image:/ { print $2 }' | tail -n 1)
  if [ -z "${local_ref}" ] || [ "${local_ref}" != "${archive_ref}" ]; then
    echo "loaded image reference does not match archive contract" >&2
    exit 1
  fi
  version_output=$(docker run --rm --network none --read-only --user 10001:10001 \
    "${local_ref}" --version)
  build_info=$(docker run --rm --network none --read-only --user 10001:10001 \
    "${local_ref}" --build-info=json)
  if docker run --rm --network none --read-only --user 10001:10001 "${local_ref}"; then
    echo "${role} unexpectedly accepted an empty invocation" >&2
    exit 1
  fi
  probe_mode=native-container
fi

if [ "${role}" != filebelt-web ]; then
  expected_version="${role} ${version} (${revision})"
  if [ "${version_output}" != "${expected_version}" ]; then
    echo "unexpected --version output: ${version_output}" >&2
    exit 1
  fi
  printf '%s\n' "${build_info}" | jq -e \
    --arg role "${role}" --arg version "${version}" --arg revision "${revision}" \
    --arg source_ref "${source_ref}" --arg kind "${kind}" --argjson dirty "${dirty}" \
    '. == {role:$role,version:$version,revision:$revision,source_ref:$source_ref,dirty:$dirty,kind:$kind}' >/dev/null
fi

mkdir -p "$(dirname -- "${output}")"
jq -n --arg role "${role}" --arg platform "${platform}" --arg mode "${probe_mode}" \
  --arg revision "${revision}" \
  '{schemaVersion:1,role:$role,platform:$platform,mode:$mode,sourceRevision:$revision,passed:true}' \
  >"${output}"
