#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly HELM_VERSION="v4.2.3"

repo_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
chart="${repo_root}/deploy/helm/filebelt-onlyoffice"
temporary=""

die() {
  echo "ONLYOFFICE Helm chart check: $*" >&2
  exit 1
}

cleanup() {
  local status="$?"
  set +e
  case "${temporary}" in
    "${TMPDIR:-/tmp}"/filebelt-onlyoffice-helm.*) rm -rf -- "${temporary}" ;;
    "") ;;
    *) echo "refusing to remove unexpected test directory: ${temporary}" >&2 ;;
  esac
  exit "${status}"
}
trap cleanup EXIT HUP INT TERM

for command in helm grep mktemp; do
  command -v "${command}" >/dev/null 2>&1 || die "missing required command: ${command}"
done
[[ "$(helm version --template '{{ .Version }}')" == "${HELM_VERSION}" ]] \
  || die "requires Helm ${HELM_VERSION}"

temporary="$(mktemp -d "${TMPDIR:-/tmp}/filebelt-onlyoffice-helm.XXXXXX")"
helm lint "${chart}" --strict --kube-version 1.36.0 --namespace filebelt-integrations \
  >"${temporary}/lint.log"
helm template onlyoffice "${chart}" --kube-version 1.36.0 --namespace filebelt-integrations \
  >"${temporary}/rendered.yaml"

manifest="${temporary}/rendered.yaml"
for required in \
  'kind: Deployment' \
  'replicas: 2' \
  'kind: PodDisruptionBudget' \
  'minAvailable: 1' \
  'automountServiceAccountToken: false' \
  'readOnlyRootFilesystem: true' \
  'runAsUser: 10001' \
  'runAsGroup: 10001' \
  'mountPath: /run/secrets/browser-jwt' \
  'mountPath: /run/secrets/outbox-jwt' \
  'mountPath: /run/secrets/server-tls' \
  'mountPath: /run/secrets/core-client-tls' \
  'mountPath: /run/secrets/io-client-tls' \
  'mountPath: /run/secrets/egress-client-tls' \
  'name: filebelt-onlyoffice-egress' \
  'port: 8443'; do
  grep -F -- "${required}" "${manifest}" >/dev/null || die "missing ${required}"
done
for forbidden in \
  'kind: Namespace' \
  'kind: Secret' \
  'claimName:' \
  'serviceAccountToken:' \
  'hostPath:' \
  'DocumentServer' \
  'documentserver'; do
  if grep -F -- "${forbidden}" "${manifest}" >/dev/null; then
    die "unexpected ${forbidden}"
  fi
done
if grep -F -- 'adapter-database' "${manifest}" >/dev/null; then
  die "adapter must not receive a PostgreSQL credential"
fi
if grep -F -- 'path: retiring' "${manifest}" >/dev/null; then
  die "retiring outbox key must be absent outside a rotation overlap"
fi

helm template onlyoffice "${chart}" --kube-version 1.36.0 \
  --namespace filebelt-integrations --set secrets.outboxJwt.retiringKey=previous \
  >"${temporary}/rotating.yaml"
grep -F -- 'path: retiring' "${temporary}/rotating.yaml" >/dev/null \
  || die "configured retiring outbox key was not mounted"

if helm template onlyoffice "${chart}" --kube-version 1.36.0 --namespace filebelt-core \
    >"${temporary}/wrong-namespace.log" 2>&1; then
  die "chart rendered into the core namespace"
fi
