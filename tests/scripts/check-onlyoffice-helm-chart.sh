#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly HELM_VERSION="v4.2.4"

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
readonly admitted_digest="sha256:1111111111111111111111111111111111111111111111111111111111111111"
readonly admitted_source_sha="1111111111111111111111111111111111111111111111111111111111111111"
readonly corresponding_source="https://github.com/OxiBelt/FileBelt/releases/download/0.1.0/filebelt-onlyoffice-adapter-source-0.1.0.tar.gz"
qualified=(--set image.qualification=qualified --set "image.digest=${admitted_digest}" --set "image.correspondingSourceSha256=${admitted_source_sha}")
if helm template onlyoffice "${chart}" --kube-version 1.36.0 --namespace filebelt-integrations \
    >"${temporary}/blocked.log" 2>&1; then
  die "chart rendered a blocked image"
fi
helm lint "${chart}" --strict --kube-version 1.36.0 --namespace filebelt-integrations \
  "${qualified[@]}" >"${temporary}/lint.log"
helm template onlyoffice "${chart}" --kube-version 1.36.0 --namespace filebelt-integrations \
  "${qualified[@]}" >"${temporary}/rendered.yaml"

manifest="${temporary}/rendered.yaml"
for evidence in \
  'filebelt.dev/adapter-license: "AGPL-3.0-only"' \
  "filebelt.dev/adapter-source: \"${corresponding_source}\"" \
  "filebelt.dev/adapter-source-sha256: \"${admitted_source_sha}\""; do
  [[ "$(grep -Fc -- "${evidence}" "${manifest}")" == "8" ]] \
    || die "release evidence must annotate all eight rendered metadata locations: ${evidence}"
done
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
  --namespace filebelt-integrations "${qualified[@]}" --set secrets.outboxJwt.retiringKey=previous \
  >"${temporary}/rotating.yaml"
grep -F -- 'path: retiring' "${temporary}/rotating.yaml" >/dev/null \
  || die "configured retiring outbox key was not mounted"

helm template onlyoffice-private-egress "${chart}" --kube-version 1.36.0 \
  --namespace filebelt-integrations "${qualified[@]}" \
  --set networkPolicy.privateEgress.enabled=true \
  >"${temporary}/private-egress.yaml"
grep -F -- 'mountPath: /run/secrets/private-egress-client-tls' "${temporary}/private-egress.yaml" >/dev/null \
  || die "enabled private egress did not mount its distinct client identity"
grep -F -- 'filebelt.dev/private-egress-role: onlyoffice-output' "${temporary}/private-egress.yaml" >/dev/null \
  || die "enabled private egress did not render its exact gateway peer"
if helm template onlyoffice-private-egress "${chart}" --kube-version 1.36.0 \
    --namespace filebelt-integrations "${qualified[@]}" \
    --set networkPolicy.privateEgress.enabled=true \
    --set-string secrets.privateEgressClientTls.name=filebelt-onlyoffice-egress-client-tls \
    >"${temporary}/reused-egress-identity.log" 2>&1; then
  die "private egress reused the public gateway client identity"
fi

if helm template onlyoffice "${chart}" --kube-version 1.36.0 --namespace filebelt-core \
    "${qualified[@]}" >"${temporary}/wrong-namespace.log" 2>&1; then
  die "chart rendered into the core namespace"
fi
