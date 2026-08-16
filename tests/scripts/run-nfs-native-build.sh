#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
  echo "usage: run-nfs-native-build.sh --tag <SemVer> --platform <linux/arch> --output <path>" >&2
}

die() {
  echo "NFS native build: $*" >&2
  exit 1
}

tag=
platform=
output=
while (( $# > 0 )); do
  case "$1" in
    --tag) tag=${2:-}; shift 2 ;;
    --platform) platform=${2:-}; shift 2 ;;
    --output) output=${2:-}; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
[[ -n "${tag}" && -n "${platform}" && -n "${output}" ]] || { usage; exit 2; }
[[ "${tag}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || \
  die "signed release tag must be an exact SemVer"

repo_root=$(cd -- "$(dirname -- "$0")/../.." && pwd)
for command in awk docker find git grep jq pgrep readelf sha256sum tar; do
  command -v "${command}" >/dev/null 2>&1 || die "missing required command: ${command}"
done
case "${platform}" in
  linux/amd64) expected_machine=x86_64; architecture=amd64; amd64_isa="x86-64-v3"; target_cpu="x86-64-v3" ;;
  linux/arm64) expected_machine=aarch64; architecture=arm64; amd64_isa=; target_cpu="architecture-default" ;;
  linux/riscv64) expected_machine=riscv64; architecture=riscv64; amd64_isa=; target_cpu="architecture-default" ;;
  *) die "unsupported platform ${platform}" ;;
esac

actual_machine=$(uname -m)
[[ "${actual_machine}" == "${expected_machine}" ]] || {
  die "${platform} must build on native ${expected_machine}; runner is ${actual_machine}"
}
if [[ "${platform}" == linux/amd64 ]]; then
  mkdir -p -- "$(dirname -- "${output}")"
  "${repo_root}/tests/scripts/check-amd64-v3-host.sh" \
    >"${output}.amd64-v3-host-preflight.json"
fi
if [[ -d /proc/sys/fs/binfmt_misc ]] && find /proc/sys/fs/binfmt_misc -maxdepth 1 \
    -type f -name 'qemu-*' -print -quit | grep -q .; then
  die "QEMU binfmt registration is forbidden for native NFS qualification"
fi
if pgrep -x 'qemu-(system|x86_64|aarch64|riscv64)' >/dev/null; then
  die "QEMU processes are forbidden for native NFS qualification"
fi

"${repo_root}/tests/scripts/verify-release-tag.sh" "${tag}"
revision=$(git -C "${repo_root}" rev-parse --verify 'HEAD^{commit}')
docker_machine=$(docker info --format '{{.Architecture}}')
[[ "${docker_machine}" == "${expected_machine}" ]] || {
  die "Docker daemon must be native ${expected_machine}; observed ${docker_machine}"
}

temporary=$(mktemp -d -t filebelt-nfs-native-build-XXXXXXXX)
image="filebelt-nfs-qualification-${architecture}:${revision}"
container=
cleanup() {
  if [[ -n "${container}" ]]; then
    docker rm -f -- "${container}" >/dev/null 2>&1 || true
  fi
  docker image rm -f -- "${image}" >/dev/null 2>&1 || true
  case "${temporary}" in
    /tmp/filebelt-nfs-native-build-*) rm -rf -- "${temporary}" ;;
    *) echo "refusing unsafe temporary cleanup: ${temporary}" >&2 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

DOCKER_BUILDKIT=1 docker build \
  --platform "${platform}" \
  --build-arg "RELEASE_REVISION=${revision}" \
  --build-arg "FILEBELT_AMD64_ISA=${amd64_isa}" \
  --build-arg "FILEBELT_TARGET_CPU=${target_cpu}" \
  --file "${repo_root}/adapters/nfs/Dockerfile" \
  --tag "${image}" \
  "${repo_root}"

inspect="${temporary}/inspect.json"
docker image inspect "${image}" >"${inspect}"
label() {
  jq -er --arg key "$1" '.[0].Config.Labels[$key]' "${inspect}"
}
[[ "$(label org.opencontainers.image.revision)" == "${revision}" ]] || \
  die "image revision label does not match the signed release"
[[ "$(label org.opencontainers.image.licenses)" == "LGPL-3.0-or-later" ]] || \
  die "image license label is not LGPL-3.0-or-later"
[[ "$(label filebelt.dev.nfs-ganesha)" == "6.5-8" ]] || \
  die "image does not contain the pinned NFS-Ganesha 6.5-8 composition"
[[ "$(label filebelt.dev.fsal-api)" == "13.0" ]] || \
  die "image does not target FSAL API 13.0"
qualification=$(label filebelt.dev.qualification)
[[ "${qualification}" == qualified ]] || \
  die "image remains ${qualification}; callback, ABI, and live krb5p qualification cannot pass"
[[ "$(jq -c '.[0].Config.Entrypoint' "${inspect}")" == '["/usr/local/bin/filebelt-nfs"]' ]] || \
  die "unexpected NFS image entrypoint"
container_machine=$(docker run --rm --entrypoint /usr/bin/uname "${image}" -m)
[[ "${container_machine}" == "${expected_machine}" ]] || \
  die "built image did not execute as native ${expected_machine}"

container=$(docker create --entrypoint /bin/true "${image}")
rootfs="${temporary}/rootfs.tar"
docker export "${container}" >"${rootfs}"
fsal_paths=$(tar -tvf "${rootfs}" | awk \
  '$1 ~ /^-/ && $NF ~ /(^|\/)ganesha\/libfsalfilebelt\.so(\.6(\.5\.0)?)?$/ {print $NF}')
[[ "$(printf '%s\n' "${fsal_paths}" | sed '/^$/d' | wc -l)" -eq 1 ]] || \
  die "image must contain exactly one dynamic FileBelt FSAL"
fsal_path=$(printf '%s\n' "${fsal_paths}" | sed '/^$/d')
case "${fsal_path}" in
  /*|../*|*/../*|*/..) die "unsafe FSAL archive path" ;;
esac
tar -xf "${rootfs}" -C "${temporary}" -- "${fsal_path}"
readelf -d "${temporary}/${fsal_path}" >"${temporary}/link.txt"
grep -F 'Shared object file' "${temporary}/link.txt" >/dev/null || \
  die "FSAL is not a dynamically linked module"
grep -F 'ganesha_nfsd' "${temporary}/link.txt" >/dev/null || \
  die "FSAL does not link to the configured Ganesha library"
if readelf -Ws "${temporary}/${fsal_path}" | awk '$7 == "UND" {print $8}' | \
    grep -E '^filebelt_' >/dev/null; then
  die "FSAL contains unresolved FileBelt symbols"
fi

for required in \
  usr/share/filebelt-nfs/corresponding-source/filebelt-adapter/RELINKING.md \
  usr/share/filebelt-nfs/corresponding-source/filebelt-adapter/SOURCE_OFFER.md \
  usr/share/filebelt-nfs/corresponding-source/filebelt-adapter/THIRD_PARTY_NOTICES.md \
  usr/share/filebelt-nfs/corresponding-source/filebelt-adapter/Cargo.lock \
  usr/share/filebelt-nfs/corresponding-source/nfs-ganesha_6.5-8.dsc \
  usr/share/filebelt-nfs/corresponding-source/nfs-ganesha_6.5.orig.tar.gz \
  usr/share/filebelt-nfs/corresponding-source/nfs-ganesha_6.5-8.debian.tar.xz; do
  tar -tf "${rootfs}" | grep -Fx "${required}" >/dev/null || \
    die "image is missing corresponding-source material: ${required}"
done

mkdir -p -- "$(dirname -- "${output}")"
image_config_digest=$(jq -er '.[0].Id' "${inspect}")
jq -n \
  --arg platform "${platform}" \
  --arg runner_architecture "${actual_machine}" \
  --arg revision "${revision}" \
  --arg image_config_digest "${image_config_digest}" \
  '{
    schemaVersion: 1,
    platform: $platform,
    runnerArchitecture: $runner_architecture,
    native: true,
    emulation: "none",
    revision: $revision,
    imageConfigDigest: $image_config_digest,
    ganeshaPackage: "6.5-8",
    fsalApi: "13.0",
    configuredBuild: true,
    abiProbePassed: true,
    linkProbePassed: true,
    callbacksQualified: true,
    qualificationLabel: "qualified"
  }' >"${output}"
echo "Native NFS build qualified for ${platform}"
