#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly HELM_VERSION="v4.2.3"
readonly OPERATION_ID="123e4567-e89b-42d3-a456-426614174000"

repo_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
chart="${repo_root}/deploy/helm/filebelt"
temporary=""

die() {
  echo "Helm Phase 3 chart check: $*" >&2
  exit 1
}

cleanup() {
  local status="$?"
  set +e
  case "${temporary}" in
    "${TMPDIR:-/tmp}"/filebelt-helm.*) rm -rf -- "${temporary}" ;;
    "") ;;
    *) echo "refusing to remove unexpected test directory: ${temporary}" >&2 ;;
  esac
  exit "${status}"
}
trap cleanup EXIT HUP INT TERM

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

assert_count() {
  local file="$1" pattern="$2" expected="$3" actual
  actual="$(grep -Ec -- "${pattern}" "${file}" || true)"
  [[ "${actual}" == "${expected}" ]] \
    || die "$(basename "${file}") expected ${expected} matches for ${pattern}, found ${actual}"
}

assert_contains() {
  grep -F -- "$2" "$1" >/dev/null \
    || die "$(basename "$1") is missing: $2"
}

assert_not_contains() {
  if grep -F -- "$2" "$1" >/dev/null; then
    die "$(basename "$1") unexpectedly contains: $2"
  fi
}

assert_document_contains() {
  local file="$1" kind="$2" name="$3" expected="$4"
  awk -v kind="${kind}" -v name="${name}" -v expected="${expected}" '
    BEGIN { RS="---"; found=0 }
    index($0, "kind: " kind) && index($0, "name: " name) {
      if (index($0, expected)) found=1
    }
    END { exit(found ? 0 : 1) }
  ' "${file}" || die "${kind}/${name} is missing: ${expected}"
}

assert_document_not_contains() {
  local file="$1" kind="$2" name="$3" unexpected="$4"
  if awk -v kind="${kind}" -v name="${name}" -v unexpected="${unexpected}" '
    BEGIN { RS="---"; found=0 }
    index($0, "kind: " kind) && index($0, "name: " name) && index($0, unexpected) { found=1 }
    END { exit(found ? 0 : 1) }
  ' "${file}"; then
    die "${kind}/${name} unexpectedly contains: ${unexpected}"
  fi
}

expect_failure() {
  local name="$1"
  shift
  if helm template phase3 "${chart}" --kube-version 1.34.0 "$@" \
      >"${temporary}/${name}.log" 2>&1; then
    die "${name} unexpectedly rendered successfully"
  fi
}

for command in helm grep awk mktemp; do
  require_command "${command}"
done

actual_version="$(helm version --template '{{ .Version }}')"
[[ "${actual_version}" == "${HELM_VERSION}" ]] \
  || die "requires Helm ${HELM_VERSION}, got ${actual_version}"

temporary="$(mktemp -d "${TMPDIR:-/tmp}/filebelt-helm.XXXXXX")"

for version in 1.34.0 1.35.0 1.36.0; do
  helm lint "${chart}" --strict --kube-version "${version}" \
    >"${temporary}/lint-${version}.log"
  helm template phase3 "${chart}" --kube-version "${version}" \
    >"${temporary}/render-${version}.yaml"
done

default_manifest="${temporary}/render-1.36.0.yaml"
helm lint "${chart}" --strict --kube-version 1.36.0 \
  --values "${repo_root}/tests/kubernetes/values-ci.yaml" \
  >"${temporary}/lint-ci-values.log"
helm template phase3 "${chart}" --kube-version 1.36.0 \
  --values "${repo_root}/tests/kubernetes/values-ci.yaml" \
  >"${temporary}/render-ci-values.yaml"
assert_count "${default_manifest}" '^kind: Deployment$' 4
assert_count "${default_manifest}" '^kind: Service$' 7
assert_count "${default_manifest}" '^kind: ServiceAccount$' 5
assert_count "${default_manifest}" '^kind: PodDisruptionBudget$' 3
assert_count "${default_manifest}" '^kind: ConfigMap$' 2
assert_count "${default_manifest}" '^kind: NetworkPolicy$' 9
assert_count "${default_manifest}" '^kind: Job$' 0
assert_count "${default_manifest}" '^automountServiceAccountToken: false$' 5
assert_count "${default_manifest}" '^      automountServiceAccountToken: false$' 4
assert_count "${default_manifest}" '^immutable: true$' 2
assert_count "${default_manifest}" '^          image: .+@sha256:[0-9a-f]{64}$' 4
assert_count "${default_manifest}" '^  minAvailable: 1$' 3
assert_not_contains "${default_manifest}" 'kind: StatefulSet'
assert_not_contains "${default_manifest}" 'kind: HorizontalPodAutoscaler'
assert_not_contains "${default_manifest}" 'kind: Secret'
assert_not_contains "${default_manifest}" 'kind: PersistentVolumeClaim'
assert_not_contains "${default_manifest}" 'kind: Role'
assert_not_contains "${default_manifest}" 'kind: RoleBinding'
assert_not_contains "${default_manifest}" 'kind: ClusterRole'
assert_not_contains "${default_manifest}" 'kind: Ingress'
assert_not_contains "${default_manifest}" 'filebelt-media-controller'
assert_not_contains "${default_manifest}" 'filebelt-mcp-broker'
assert_not_contains "${default_manifest}" 'serviceAccountToken:'
assert_not_contains "${default_manifest}" 'hostPath:'
assert_document_contains "${default_manifest}" Service filebelt-api 'targetPort: api'
assert_document_contains "${default_manifest}" Service filebelt-worker-io 'targetPort: io'
assert_document_not_contains "${default_manifest}" NetworkPolicy filebelt-web-egress 'port: 4318'
assert_document_contains "${temporary}/render-ci-values.yaml" NetworkPolicy filebelt-web-egress 'app.kubernetes.io/name: filebelt-ci-otel'
assert_document_contains "${temporary}/render-ci-values.yaml" NetworkPolicy filebelt-web-egress 'port: 4318'
assert_document_contains "${default_manifest}" Deployment filebelt-web 'replicas: 2'
assert_document_contains "${default_manifest}" Deployment filebelt-api 'replicas: 2'
assert_document_contains "${default_manifest}" Deployment filebelt-io 'replicas: 2'
assert_document_contains "${default_manifest}" Deployment filebelt-maintenance 'replicas: 1'
assert_document_contains "${default_manifest}" Deployment filebelt-web 'terminationGracePeriodSeconds: 45'
assert_document_contains "${default_manifest}" Deployment filebelt-api 'terminationGracePeriodSeconds: 45'
assert_document_contains "${default_manifest}" Deployment filebelt-io 'terminationGracePeriodSeconds: 75'
assert_document_contains "${default_manifest}" Deployment filebelt-maintenance 'terminationGracePeriodSeconds: 90'
assert_document_contains "${default_manifest}" Deployment filebelt-web 'cpu: 100m'
assert_document_contains "${default_manifest}" Deployment filebelt-web 'memory: 128Mi'
assert_document_contains "${default_manifest}" Deployment filebelt-api 'cpu: 250m'
assert_document_contains "${default_manifest}" Deployment filebelt-api 'memory: 256Mi'
assert_document_contains "${default_manifest}" Deployment filebelt-io 'cpu: 500m'
assert_document_contains "${default_manifest}" Deployment filebelt-io 'memory: 512Mi'
assert_document_contains "${default_manifest}" Deployment filebelt-maintenance 'cpu: 250m'
assert_document_contains "${default_manifest}" Deployment filebelt-maintenance 'memory: 256Mi'
assert_document_not_contains "${default_manifest}" Deployment filebelt-web 'claimName:'
assert_document_not_contains "${default_manifest}" Deployment filebelt-api 'claimName:'
assert_document_contains "${default_manifest}" Deployment filebelt-io 'claimName: filebelt-payloads'
assert_document_contains "${default_manifest}" Deployment filebelt-maintenance 'claimName: filebelt-payloads'
for component in web api io maintenance; do
  assert_document_contains "${default_manifest}" Deployment "filebelt-${component}" 'readOnlyRootFilesystem: true'
  assert_document_contains "${default_manifest}" Deployment "filebelt-${component}" 'drop: ["ALL"]'
  assert_document_contains "${default_manifest}" Deployment "filebelt-${component}" 'type: RuntimeDefault'
  assert_document_contains "${default_manifest}" Deployment "filebelt-${component}" 'enableServiceLinks: false'
done

helm template phase3 "${chart}" --kube-version 1.36.0 \
  --set deployment.quiesced=true >"${temporary}/quiesced.yaml"
assert_count "${temporary}/quiesced.yaml" '^  replicas: 0$' 4

helm template phase3 "${chart}" --kube-version 1.36.0 \
  --set-string operation.type=migrate \
  --set-string operation.operationId="${OPERATION_ID}" \
  >"${temporary}/migrate.yaml"
assert_count "${temporary}/migrate.yaml" '^kind: Job$' 1
assert_contains "${temporary}/migrate.yaml" 'backoffLimit: 0'
assert_contains "${temporary}/migrate.yaml" 'filebelt.dev/operation-id: "123e4567-e89b-42d3-a456-426614174000"'
assert_not_contains "${temporary}/migrate.yaml" 'helm.sh/hook'
assert_not_contains "${temporary}/migrate.yaml" 'ttlSecondsAfterFinished'
assert_document_not_contains "${temporary}/migrate.yaml" Job filebelt-migrate-123e4567-e89 'claimName:'

helm template phase3 "${chart}" --kube-version 1.36.0 \
  --set-string operation.type=storage-probe \
  --set-string operation.operationId="${OPERATION_ID}" \
  >"${temporary}/storage.yaml"
assert_document_contains "${temporary}/storage.yaml" Job filebelt-storage-probe-123e4567-e89 'claimName: filebelt-payloads'
assert_document_not_contains "${temporary}/storage.yaml" Job filebelt-storage-probe-123e4567-e89 'secretName: filebelt-migrator-database'
assert_document_contains "${temporary}/storage.yaml" NetworkPolicy filebelt-operation-egress 'egress: []'

helm template phase3 "${chart}" --kube-version 1.36.0 \
  --set-string operation.type=storage-scrub-start \
  --set-string operation.operationId="${OPERATION_ID}" \
  --set-string operation.payloadId=123e4567-e89b-42d3-a456-426614174001 \
  >"${temporary}/targeted-scrub.yaml"
assert_document_contains "${temporary}/targeted-scrub.yaml" Job filebelt-storage-scrub-start-123e4567-e89 '--payload-id'
assert_document_not_contains "${temporary}/targeted-scrub.yaml" Job filebelt-storage-scrub-start-123e4567-e89 '--confirm-tenant'
assert_document_not_contains "${temporary}/targeted-scrub.yaml" Job filebelt-storage-scrub-start-123e4567-e89 'claimName:'

helm template phase3 "${chart}" --kube-version 1.36.0 \
  --set deployment.quiesced=true \
  --set-string operation.type=recovery-checkpoint \
  --set-string operation.operationId="${OPERATION_ID}" \
  >"${temporary}/recovery.yaml"
assert_document_not_contains "${temporary}/recovery.yaml" Job filebelt-recovery-checkpoint-123e4567-e89 'claimName:'

helm template phase3 "${chart}" --kube-version 1.36.0 \
  --set deployment.quiesced=true \
  --set-string operation.type=recovery-verify \
  --set-string operation.operationId="${OPERATION_ID}" \
  --set-string operation.checkpoint.secretName=filebelt-checkpoint-ci \
  >"${temporary}/recovery-verify.yaml"
assert_document_contains "${temporary}/recovery-verify.yaml" Job filebelt-recovery-verify-123e4567-e89 'secretName: filebelt-checkpoint-ci'
assert_document_contains "${temporary}/recovery-verify.yaml" Job filebelt-recovery-verify-123e4567-e89 'items: [{key: checkpoint.json, path: checkpoint.json}]'
assert_document_not_contains "${temporary}/recovery-verify.yaml" Job filebelt-recovery-verify-123e4567-e89 'claimName:'

helm template phase3 "${chart}" --kube-version 1.36.0 \
  --api-versions monitoring.coreos.com/v1/ServiceMonitor \
  --api-versions monitoring.coreos.com/v1/PrometheusRule \
  --set monitoring.serviceMonitor.enabled=true \
  --set monitoring.prometheusRule.enabled=true \
  >"${temporary}/monitoring.yaml"
assert_count "${temporary}/monitoring.yaml" '^kind: ServiceMonitor$' 1
assert_count "${temporary}/monitoring.yaml" '^kind: PrometheusRule$' 1

expect_failure old_kubernetes --kube-version 1.33.9
expect_failure new_kubernetes --kube-version 1.37.0
expect_failure tag_image --set-string images.filebelt-api.tag=1.2.3
expect_failure unplanned_image --set-string images.filebelt-media-controller.repository=oxibelt/filebelt-media-controller
expect_failure invalid_uid --set global.runAsUser=0
expect_failure operation_without_id --set-string operation.type=migrate
expect_failure full_scrub_without_confirmation \
  --set-string operation.type=storage-scrub-start \
  --set-string operation.operationId="${OPERATION_ID}"
expect_failure targeted_scrub_with_confirmation \
  --set-string operation.type=storage-scrub-start \
  --set-string operation.operationId="${OPERATION_ID}" \
  --set-string operation.payloadId=123e4567-e89b-42d3-a456-426614174001 \
  --set-string operation.tenantSlugConfirmation=development
expect_failure recovery_while_live \
  --set-string operation.type=recovery-checkpoint \
  --set-string operation.operationId="${OPERATION_ID}"
expect_failure recovery_without_checkpoint \
  --set deployment.quiesced=true \
  --set-string operation.type=recovery-verify \
  --set-string operation.operationId="${OPERATION_ID}"
expect_failure unrestricted_egress --skip-schema-validation \
  --set-json 'networkPolicy.postgres.to=[{"ipBlock":{"cidr":"0.0.0.0/0"}}]'
expect_failure old_config --skip-schema-validation \
  --set-string 'configuration.filebelt=version = 1'
expect_failure monitoring_crd_absent --set monitoring.serviceMonitor.enabled=true

echo "Helm Phase 3 chart contract passed"
