#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly HELM_VERSION="v4.2.3"
readonly OPERATION_ID="123e4567-e89b-42d3-a456-426614174000"

repo_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
chart="${repo_root}/deploy/helm/filebelt"
temporary=""

die() {
  echo "Helm Phase 4 chart check: $*" >&2
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

assert_rendered_toml() {
  local file="$1" key="$2"
  python3 - "${file}" "${key}" <<'PY'
import sys
import tomllib

manifest_path, key = sys.argv[1:]
needle = f"  {key}: |"
for document in open(manifest_path, encoding="utf-8").read().split("\n---\n"):
    lines = document.splitlines()
    if "kind: ConfigMap" not in lines or needle not in lines:
        continue
    start = lines.index(needle) + 1
    rendered = []
    for line in lines[start:]:
        if line.startswith("    "):
            rendered.append(line[4:])
        elif not line:
            rendered.append("")
        else:
            break
    try:
        tomllib.loads("\n".join(rendered))
    except tomllib.TOMLDecodeError as error:
        raise SystemExit(f"{manifest_path}: rendered {key} is invalid TOML: {error}") from error
    raise SystemExit(0)

raise SystemExit(f"{manifest_path}: could not find ConfigMap data key {key}")
PY
}

expect_failure() {
  local name="$1"
  shift
  if helm template phase4 "${chart}" --kube-version 1.34.0 "$@" \
      >"${temporary}/${name}.log" 2>&1; then
    die "${name} unexpectedly rendered successfully"
  fi
}

for command in helm grep awk mktemp python3 sed sha256sum; do
  require_command "${command}"
done

actual_version="$(helm version --template '{{ .Version }}')"
[[ "${actual_version}" == "${HELM_VERSION}" ]] \
  || die "requires Helm ${HELM_VERSION}, got ${actual_version}"

temporary="$(mktemp -d "${TMPDIR:-/tmp}/filebelt-helm.XXXXXX")"

for version in 1.34.0 1.35.0 1.36.0; do
  helm lint "${chart}" --strict --kube-version "${version}" \
    >"${temporary}/lint-${version}.log"
  helm template phase4 "${chart}" --kube-version "${version}" \
    >"${temporary}/render-${version}.yaml"
done

default_manifest="${temporary}/render-1.36.0.yaml"
helm lint "${chart}" --strict --kube-version 1.36.0 \
  --values "${repo_root}/tests/kubernetes/values-ci.yaml" \
  >"${temporary}/lint-ci-values.log"
helm template phase4 "${chart}" --kube-version 1.36.0 \
  --values "${repo_root}/tests/kubernetes/values-ci.yaml" \
  >"${temporary}/render-ci-values.yaml"
assert_rendered_toml "${default_manifest}" filebelt.toml
assert_rendered_toml "${default_manifest}" oxibelt.toml
assert_rendered_toml "${temporary}/render-ci-values.yaml" filebelt.toml
assert_rendered_toml "${temporary}/render-ci-values.yaml" oxibelt.toml
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
assert_not_contains "${default_manifest}" 'filebelt-controller'
assert_not_contains "${default_manifest}" 'filebelt-mcp-runner'
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
assert_not_contains "${default_manifest}" 'filebelt-collaboration'
assert_not_contains "${default_manifest}" '/collaboration/v1/ws'
assert_not_contains "${default_manifest}" '/collaboration/v1/wt'
assert_not_contains "${default_manifest}" 'host_key_file = "/run/secrets/collaboration-quic-host-key/quic-host-key.b64"'
for component in web api io maintenance; do
  assert_document_contains "${default_manifest}" Deployment "filebelt-${component}" 'readOnlyRootFilesystem: true'
  assert_document_contains "${default_manifest}" Deployment "filebelt-${component}" 'drop: ["ALL"]'
  assert_document_contains "${default_manifest}" Deployment "filebelt-${component}" 'type: RuntimeDefault'
  assert_document_contains "${default_manifest}" Deployment "filebelt-${component}" 'enableServiceLinks: false'
done

helm template phase5 "${chart}" --kube-version 1.36.0 \
  --set collaboration.enabled=true >"${temporary}/collaboration.yaml"
assert_rendered_toml "${temporary}/collaboration.yaml" filebelt.toml
assert_rendered_toml "${temporary}/collaboration.yaml" oxibelt.toml
assert_count "${temporary}/collaboration.yaml" '^kind: Deployment$' 5
assert_count "${temporary}/collaboration.yaml" '^kind: PodDisruptionBudget$' 4
assert_count "${temporary}/collaboration.yaml" '^kind: NetworkPolicy$' 11
assert_document_contains "${temporary}/collaboration.yaml" Deployment filebelt-collaboration 'replicas: 2'
assert_document_contains "${temporary}/collaboration.yaml" Deployment filebelt-collaboration 'automountServiceAccountToken: false'
assert_document_not_contains "${temporary}/collaboration.yaml" Deployment filebelt-collaboration 'claimName:'
assert_document_contains "${temporary}/collaboration.yaml" Deployment filebelt-collaboration 'mountPath: /run/secrets/capability-public-keyset'
assert_document_contains "${temporary}/collaboration.yaml" Service filebelt-collaboration 'port: 8085'
assert_document_contains "${temporary}/collaboration.yaml" NetworkPolicy filebelt-collaboration-ingress 'port: collaboration-ws'
assert_document_contains "${temporary}/collaboration.yaml" NetworkPolicy filebelt-collaboration-egress 'port: io'
assert_contains "${temporary}/collaboration.yaml" 'path_prefix = "/collaboration/v1/ws"'
assert_contains "${temporary}/collaboration.yaml" 'protocols = ["websocket"]'
assert_not_contains "${temporary}/collaboration.yaml" 'path_prefix = "/collaboration/v1/wt"'
assert_not_contains "${temporary}/collaboration.yaml" 'host_key_file = "/run/secrets/collaboration-quic-host-key/quic-host-key.b64"'

if helm template phase5 "${chart}" --kube-version 1.36.0 \
  --set collaboration.enabled=true \
  --set collaboration.webtransport.enabled=true >"${temporary}/collaboration-webtransport.yaml" 2>/dev/null; then
  echo "the chart must reject WebTransport until the runtime listener is implemented" >&2
  exit 1
fi
preview_line=$(grep -n 'name = "filebelt-markdown-preview"' "${temporary}/collaboration.yaml" | head -n1 | cut -d: -f1)
spa_line=$(grep -n 'name = "filebelt-spa"' "${temporary}/collaboration.yaml" | head -n1 | cut -d: -f1)
if [ "${preview_line}" -ge "${spa_line}" ]; then
  echo "opaque Markdown preview route must precede the SPA catch-all" >&2
  exit 1
fi

helm template phase4 "${chart}" --kube-version 1.36.0 \
  --set deployment.quiesced=true >"${temporary}/quiesced.yaml"
assert_count "${temporary}/quiesced.yaml" '^  replicas: 0$' 4

helm template phase4 "${chart}" --kube-version 1.36.0 \
  --set-string operation.type=migrate \
  --set-string operation.operationId="${OPERATION_ID}" \
  >"${temporary}/migrate.yaml"
assert_count "${temporary}/migrate.yaml" '^kind: Job$' 1
assert_contains "${temporary}/migrate.yaml" 'backoffLimit: 0'
assert_contains "${temporary}/migrate.yaml" 'filebelt.dev/operation-id: "123e4567-e89b-42d3-a456-426614174000"'
assert_not_contains "${temporary}/migrate.yaml" 'helm.sh/hook'
assert_not_contains "${temporary}/migrate.yaml" 'ttlSecondsAfterFinished'
assert_document_not_contains "${temporary}/migrate.yaml" Job filebelt-migrate-123e4567-e89 'claimName:'

helm template phase4 "${chart}" --kube-version 1.36.0 \
  --set-string operation.type=storage-probe \
  --set-string operation.operationId="${OPERATION_ID}" \
  >"${temporary}/storage.yaml"
assert_document_contains "${temporary}/storage.yaml" Job filebelt-storage-probe-123e4567-e89 'claimName: filebelt-payloads'
assert_document_not_contains "${temporary}/storage.yaml" Job filebelt-storage-probe-123e4567-e89 'secretName: filebelt-migrator-database'
assert_document_contains "${temporary}/storage.yaml" NetworkPolicy filebelt-operation-egress 'egress: []'

helm template phase4 "${chart}" --kube-version 1.36.0 \
  --set-string operation.type=storage-scrub-start \
  --set-string operation.operationId="${OPERATION_ID}" \
  --set-string operation.payloadId=123e4567-e89b-42d3-a456-426614174001 \
  >"${temporary}/targeted-scrub.yaml"
assert_document_contains "${temporary}/targeted-scrub.yaml" Job filebelt-storage-scrub-start-123e4567-e89 '--payload-id'
assert_document_not_contains "${temporary}/targeted-scrub.yaml" Job filebelt-storage-scrub-start-123e4567-e89 '--confirm-tenant'
assert_document_not_contains "${temporary}/targeted-scrub.yaml" Job filebelt-storage-scrub-start-123e4567-e89 'claimName:'

helm template phase4 "${chart}" --kube-version 1.36.0 \
  --set deployment.quiesced=true \
  --set-string operation.type=recovery-checkpoint \
  --set-string operation.operationId="${OPERATION_ID}" \
  >"${temporary}/recovery.yaml"
assert_document_not_contains "${temporary}/recovery.yaml" Job filebelt-recovery-checkpoint-123e4567-e89 'claimName:'

helm template phase4 "${chart}" --kube-version 1.36.0 \
  --set deployment.quiesced=true \
  --set-string operation.type=recovery-verify \
  --set-string operation.operationId="${OPERATION_ID}" \
  --set-string operation.checkpoint.secretName=filebelt-checkpoint-ci \
  >"${temporary}/recovery-verify.yaml"
assert_document_contains "${temporary}/recovery-verify.yaml" Job filebelt-recovery-verify-123e4567-e89 'secretName: filebelt-checkpoint-ci'
assert_document_contains "${temporary}/recovery-verify.yaml" Job filebelt-recovery-verify-123e4567-e89 'items: [{key: checkpoint.json, path: checkpoint.json}]'
assert_document_not_contains "${temporary}/recovery-verify.yaml" Job filebelt-recovery-verify-123e4567-e89 'claimName:'

helm template phase4 "${chart}" --kube-version 1.36.0 \
  --api-versions monitoring.coreos.com/v1/ServiceMonitor \
  --api-versions monitoring.coreos.com/v1/PrometheusRule \
  --set monitoring.serviceMonitor.enabled=true \
  --set monitoring.prometheusRule.enabled=true \
  >"${temporary}/monitoring.yaml"
assert_count "${temporary}/monitoring.yaml" '^kind: ServiceMonitor$' 1
assert_count "${temporary}/monitoring.yaml" '^kind: PrometheusRule$' 1

awk '
  /^  filebelt: \|$/ { in_filebelt=1; next }
  /^  oxibelt: \|$/ { in_filebelt=0 }
  in_filebelt { sub(/^    /, ""); print }
' "${chart}/values.yaml" >"${temporary}/filebelt-mcp.toml"
cat >>"${temporary}/filebelt-mcp.toml" <<'EOF'

[backend_tls.mcp_broker]
certificate_chain_file = "/run/secrets/mcp-broker-server-tls/tls.crt"
private_key_file = "/run/secrets/mcp-broker-server-tls/tls.key"
client_ca_file = "/run/secrets/mcp-broker-server-tls/client-ca.crt"
allowed_client_uri_sans = ["spiffe://filebelt/api/mcp", "spiffe://filebelt/runner/mcp"]

[backend_tls.controller]
certificate_chain_file = "/run/secrets/controller-server-tls/tls.crt"
private_key_file = "/run/secrets/controller-server-tls/tls.key"
client_ca_file = "/run/secrets/controller-server-tls/client-ca.crt"
allowed_client_uri_sans = ["spiffe://filebelt/mcp-broker/controller"]

[mcp]
enabled = true
database_url_file = "/run/secrets/mcp-database-url"

[mcp.broker]
url = "https://filebelt-mcp-broker.default.svc:8082/"
client_certificate_chain_file = "/run/secrets/mcp-broker-client-tls/tls.crt"
client_private_key_file = "/run/secrets/mcp-broker-client-tls/tls.key"
server_ca_file = "/run/secrets/mcp-broker-client-tls/server-ca.crt"

[mcp.vault]
keyring_file = "/run/secrets/mcp-vault-keyring.json"
current_generation = 1

[mcp.egress]
gateway_url = "https://filebelt-mcp-egress.filebelt-egress.svc:8443/"
client_certificate_chain_file = "/run/secrets/mcp-gateway-tls/tls.crt"
client_private_key_file = "/run/secrets/mcp-gateway-tls/tls.key"
server_ca_file = "/run/secrets/mcp-gateway-tls/server-ca.crt"

[mcp.attachments]
io_url = "https://filebelt-worker-io:8081/"
client_certificate_chain_file = "/run/secrets/mcp-backend-tls/tls.crt"
client_private_key_file = "/run/secrets/mcp-backend-tls/tls.key"
server_ca_file = "/run/secrets/mcp-backend-tls/server-ca.crt"

[mcp.trust_profiles.public]
public_webpki = true

[mcp.runners]
enabled = true
namespace = "filebelt-mcp-runners"
catalog_file = "/etc/filebelt/mcp/catalog/catalog.json"
trusted_root_file = "/etc/filebelt/mcp/trust/trusted-root.json"
bundle_directory = "/etc/filebelt/mcp/bundles"
runner_image = "ghcr.io/oxibelt/filebelt-mcp-runner@sha256:0000000000000000000000000000000000000000000000000000000000000000"
controller_url = "https://filebelt-controller.default.svc:8083/"
controller_client_certificate_chain_file = "/run/secrets/controller-client-tls/tls.crt"
controller_client_private_key_file = "/run/secrets/controller-client-tls/tls.key"
controller_server_ca_file = "/run/secrets/controller-client-tls/server-ca.crt"
max_per_principal = 1
max_per_tenant = 8
EOF

helm template phase4 "${chart}" --kube-version 1.36.0 \
  --set mcp.enabled=true \
  --set mcp.runners.enabled=true \
  --set networkPolicy.mcpGateway.enabled=true \
  --set networkPolicy.kubernetesApi.enabled=true \
  --set-json 'networkPolicy.kubernetesApi.to=[{"ipBlock":{"cidr":"10.96.0.1/32"}}]' \
  --set-file configuration.filebelt="${temporary}/filebelt-mcp.toml" \
  >"${temporary}/mcp.yaml"
assert_count "${temporary}/mcp.yaml" '^kind: Deployment$' 6
assert_count "${temporary}/mcp.yaml" '^kind: ServiceAccount$' 8
assert_count "${temporary}/mcp.yaml" '^kind: PodDisruptionBudget$' 5
assert_count "${temporary}/mcp.yaml" '^kind: Role$' 1
assert_count "${temporary}/mcp.yaml" '^kind: RoleBinding$' 1
assert_count "${temporary}/mcp.yaml" '^kind: NetworkPolicy$' 15
assert_document_contains "${temporary}/mcp.yaml" Deployment filebelt-mcp-broker 'automountServiceAccountToken: false'
assert_document_contains "${temporary}/mcp.yaml" Deployment filebelt-controller 'automountServiceAccountToken: true'
assert_document_not_contains "${temporary}/mcp.yaml" Deployment filebelt-mcp-broker 'claimName:'
assert_document_not_contains "${temporary}/mcp.yaml" Deployment filebelt-controller 'claimName:'
assert_document_contains "${temporary}/mcp.yaml" Role filebelt-controller 'namespace: "filebelt-mcp-runners"'
assert_document_contains "${temporary}/mcp.yaml" Role filebelt-controller 'resources: ["pods"]'
assert_document_contains "${temporary}/mcp.yaml" Role filebelt-controller 'resources: ["secrets"]'
assert_document_not_contains "${temporary}/mcp.yaml" Role filebelt-controller 'watch'
assert_document_not_contains "${temporary}/mcp.yaml" Role filebelt-controller 'clusterroles'
assert_document_contains "${temporary}/mcp.yaml" RoleBinding filebelt-controller 'namespace: "filebelt-mcp-runners"'
assert_document_contains "${temporary}/mcp.yaml" ServiceAccount filebelt-mcp-runner 'namespace: "filebelt-mcp-runners"'
assert_document_contains "${temporary}/mcp.yaml" NetworkPolicy filebelt-mcp-runner-default-deny 'namespace: "filebelt-mcp-runners"'
assert_document_contains "${temporary}/mcp.yaml" NetworkPolicy filebelt-mcp-runner-egress 'component: mcp-broker'
assert_document_contains "${temporary}/mcp.yaml" NetworkPolicy filebelt-mcp-runner-egress 'kubernetes.io/metadata.name: default'
assert_document_contains "${temporary}/mcp.yaml" NetworkPolicy filebelt-mcp-runner-egress 'port: runner-relay'
assert_document_not_contains "${temporary}/mcp.yaml" NetworkPolicy filebelt-mcp-runner-egress 'port: mcp'
assert_document_not_contains "${temporary}/mcp.yaml" NetworkPolicy filebelt-mcp-runner-egress 'port: 53'
assert_document_contains "${temporary}/mcp.yaml" NetworkPolicy filebelt-mcp-runner-egress 'app.kubernetes.io/name: filebelt-mcp-egress'
assert_document_contains "${temporary}/mcp.yaml" Service filebelt-mcp-broker 'port: 8084'
assert_document_contains "${temporary}/mcp.yaml" Service filebelt-mcp-broker 'port: 8082'
assert_document_contains "${temporary}/mcp.yaml" NetworkPolicy filebelt-mcp-broker-ingress 'port: runner-relay'
assert_document_contains "${temporary}/mcp.yaml" NetworkPolicy filebelt-mcp-broker-ingress 'kubernetes.io/metadata.name: filebelt-mcp-runners'
assert_document_contains "${temporary}/mcp.yaml" Deployment filebelt-api 'checksum/mcp-client-tls:'
assert_document_not_contains "${default_manifest}" Deployment filebelt-api 'checksum/mcp-client-tls:'
assert_not_contains "${temporary}/mcp.yaml" 'kind: ClusterRole'
assert_not_contains "${temporary}/mcp.yaml" 'hostPath:'

helm template phase4 "${chart}" --kube-version 1.36.0 \
  --set mcp.enabled=true \
  --set mcp.runners.enabled=true \
  --set networkPolicy.mcpGateway.enabled=true \
  --set networkPolicy.kubernetesApi.enabled=true \
  --set-json 'networkPolicy.kubernetesApi.to=[{"ipBlock":{"cidr":"10.96.0.1/32"}}]' \
  --set-string secrets.apiMcpClientTls.generation=rotated \
  --set-file configuration.filebelt="${temporary}/filebelt-mcp.toml" \
  >"${temporary}/mcp-rotated-tls.yaml"
rotated_tls_checksum="$(printf '%s' rotated | sha256sum | awk '{print $1}')"
assert_document_contains "${temporary}/mcp-rotated-tls.yaml" Deployment filebelt-api "checksum/mcp-client-tls: \"${rotated_tls_checksum}\""

sed 's#allowed_client_uri_sans = \["spiffe://filebelt/api/mcp", "spiffe://filebelt/runner/mcp"\]#allowed_client_uri_sans = ["spiffe://filebelt/api/mcp", "spiffe://filebelt/adjacent/mcp"]#' \
  "${temporary}/filebelt-mcp.toml" >"${temporary}/filebelt-mcp-widened.toml"
expect_failure widened_mcp_broker_identity \
  --set mcp.enabled=true \
  --set mcp.runners.enabled=true \
  --set networkPolicy.mcpGateway.enabled=true \
  --set networkPolicy.kubernetesApi.enabled=true \
  --set-json 'networkPolicy.kubernetesApi.to=[{"ipBlock":{"cidr":"10.96.0.1/32"}}]' \
  --set-file configuration.filebelt="${temporary}/filebelt-mcp-widened.toml"

sed '/allowed_client_uri_sans = \["spiffe:\/\/filebelt\/api\/mcp", "spiffe:\/\/filebelt\/runner\/mcp"\]/a allowed_client_trust_domains = ["filebelt"]' \
  "${temporary}/filebelt-mcp.toml" >"${temporary}/filebelt-mcp-trust-domain.toml"
expect_failure widened_mcp_broker_trust_domain \
  --set mcp.enabled=true \
  --set mcp.runners.enabled=true \
  --set networkPolicy.mcpGateway.enabled=true \
  --set networkPolicy.kubernetesApi.enabled=true \
  --set-json 'networkPolicy.kubernetesApi.to=[{"ipBlock":{"cidr":"10.96.0.1/32"}}]' \
  --set-file configuration.filebelt="${temporary}/filebelt-mcp-trust-domain.toml"

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
expect_failure mcp_without_gateway --set mcp.enabled=true
expect_failure runners_without_kubernetes_api \
  --set mcp.enabled=true \
  --set mcp.runners.enabled=true \
  --set networkPolicy.mcpGateway.enabled=true \
  --set-file configuration.filebelt="${temporary}/filebelt-mcp.toml"
expect_failure runner_namespace_is_core \
  --set mcp.enabled=true \
  --set mcp.runners.enabled=true \
  --set mcp.runners.namespace=default \
  --set networkPolicy.mcpGateway.enabled=true \
  --set networkPolicy.kubernetesApi.enabled=true \
  --set-json 'networkPolicy.kubernetesApi.to=[{"ipBlock":{"cidr":"10.96.0.1/32"}}]' \
  --set-file configuration.filebelt="${temporary}/filebelt-mcp.toml"

echo "Helm Phase 5 chart contract passed"
