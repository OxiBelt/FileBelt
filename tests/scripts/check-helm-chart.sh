#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

HELM_VERSION=v4.2.3
DIGEST=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
chart="${repo_root}/deploy/helm/filebelt"

if ! command -v helm >/dev/null 2>&1; then
  echo "missing required command: helm" >&2
  exit 1
fi
actual_version=$(helm version --template '{{ .Version }}')
if [ "${actual_version}" != "${HELM_VERSION}" ]; then
  echo "Phase 1 Helm validation requires ${HELM_VERSION}, got ${actual_version}" >&2
  exit 1
fi

temporary=$(mktemp -d)
cleanup() {
  rm -rf "${temporary}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

helm lint "${chart}" --strict
helm template filebelt "${chart}" >"${temporary}/defaults.yaml"
if grep -Eq '[^[:space:]]' "${temporary}/defaults.yaml"; then
  echo "Phase 1 chart rendered Kubernetes manifests with default values" >&2
  exit 1
fi

helm template filebelt "${chart}" \
  --set-json 'images.filebelt-api.tag=null' \
  --set-string "images.filebelt-api.digest=${DIGEST}" \
  >"${temporary}/digest.yaml"
if grep -Eq '[^[:space:]]' "${temporary}/digest.yaml"; then
  echo "Phase 1 chart rendered Kubernetes manifests with a digest override" >&2
  exit 1
fi

if helm template filebelt "${chart}" \
  --set-string "images.filebelt-api.digest=${DIGEST}" \
  >"${temporary}/tag-and-digest.log" 2>&1; then
  echo "Phase 1 chart accepted both tag and digest" >&2
  exit 1
fi

if helm template filebelt "${chart}" \
  --set-string 'images.filebelt-api.tag=1.2.3-01' \
  >"${temporary}/invalid-semver.log" 2>&1; then
  echo "Phase 1 chart accepted a non-SemVer numeric prerelease" >&2
  exit 1
fi

if helm template filebelt "${chart}" \
  --set-string 'images.unplanned.repository=oxibelt/unplanned' \
  >"${temporary}/unplanned-role.log" 2>&1; then
  echo "Phase 1 chart accepted an unplanned image role" >&2
  exit 1
fi

echo "Helm Phase 1 chart contract passed"
