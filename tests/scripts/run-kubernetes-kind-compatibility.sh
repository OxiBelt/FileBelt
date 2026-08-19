#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

umask 077

readonly KIND_134_IMAGE="kindest/node:v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256"
readonly KIND_135_IMAGE="kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95"
readonly KIND_136_IMAGE="kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
readonly RELEASE_NAME="phase3"
readonly NAMESPACE="filebelt-kind"
readonly RUNNER_NAMESPACE="filebelt-kind-mcp-runners"
readonly ONLYOFFICE_NAMESPACE="filebelt-kind-onlyoffice"
readonly GIT_NAMESPACE="filebelt-kind-git"
readonly OPERATION_ID="123e4567-e89b-42d3-a456-426614174000"
readonly ADMITTED_ADAPTER_DIGEST="sha256:1111111111111111111111111111111111111111111111111111111111111111"
readonly ADMITTED_SOURCE_SHA="1111111111111111111111111111111111111111111111111111111111111111"

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
chart_dir="${repo_root}/deploy/helm/filebelt"
onlyoffice_chart_dir="${repo_root}/deploy/helm/filebelt-onlyoffice"
git_chart_dir="${repo_root}/deploy/helm/filebelt-git"
ci_values="${repo_root}/tests/kubernetes/values-ci.yaml"
temp_root="${TMPDIR:-/tmp}"
work_dir=""
cluster_name=""

die() {
  echo "Kubernetes Kind compatibility check: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<USAGE
usage: $0 --node-image <immutable kindest/node reference>
USAGE
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

kubectl_cmd() {
  kubectl --kubeconfig "${KUBECONFIG}" "$@"
}

diagnose() {
  set +e
  echo "--- Kind compatibility diagnostics ---" >&2
  kubectl_cmd get nodes -o wide >&2
  kubectl_cmd get all,configmap,networkpolicy,poddisruptionbudget \
    --namespace "${NAMESPACE}" -o wide >&2
  kubectl_cmd get serviceaccount,role,rolebinding,networkpolicy \
    --namespace "${RUNNER_NAMESPACE}" -o wide >&2
  kubectl_cmd get all,networkpolicy,poddisruptionbudget \
    --namespace "${ONLYOFFICE_NAMESPACE}" -o wide >&2
  kubectl_cmd get all,networkpolicy,poddisruptionbudget \
    --namespace "${GIT_NAMESPACE}" -o wide >&2
  kubectl_cmd get events --all-namespaces --sort-by=.lastTimestamp >&2
  helm --kubeconfig "${KUBECONFIG}" history "${RELEASE_NAME}" \
    --namespace "${NAMESPACE}" >&2
  kind export logs "${work_dir}/kind-logs" --name "${cluster_name}" >&2
}

cleanup() {
  local status="$?"
  set +e

  if [[ "${status}" -ne 0 && -n "${cluster_name}" ]]; then
    diagnose
  fi
  if [[ -n "${cluster_name}" ]]; then
    kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
  fi
  case "${work_dir}" in
    "${temp_root%/}"/filebelt-kind-compatibility.*)
      rm -rf -- "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected Kind work directory: ${work_dir}" >&2
      ;;
  esac
  exit "${status}"
}
trap cleanup EXIT HUP INT TERM

server_validate() {
  local operation="$1"
  shift
  local output="${work_dir}/server-${operation}.log"

  helm template "${RELEASE_NAME}" "${chart_dir}" \
    --namespace "${NAMESPACE}" \
    --values "${ci_values}" \
    --set deployment.quiesced=true \
    "$@" |
    kubectl_cmd apply --server-side --dry-run=server --field-manager=filebelt-acceptance \
      --filename - >"${output}"

  if [[ "${operation}" != "base" && "${operation}" != "mcp" && "${operation}" != "mounts" && "${operation}" != "nfs" ]]; then
    grep -E '^job\.batch/filebelt-' "${output}" >/dev/null \
      || die "${operation} did not produce an API-valid operation Job"
  fi
}

server_validate_adapter() {
  local release_name="$1"
  local adapter_chart="$2"
  local namespace="$3"
  local expected_workload="$4"
  local output="${work_dir}/server-adapter-${release_name}.log"

  helm template "${release_name}" "${adapter_chart}" \
    --namespace "${namespace}" \
    --set image.qualification=qualified \
    --set-string "image.digest=${ADMITTED_ADAPTER_DIGEST}" \
    --set-string "image.correspondingSourceSha256=${ADMITTED_SOURCE_SHA}" |
    kubectl_cmd apply --server-side --dry-run=server --field-manager=filebelt-acceptance \
      --filename - >"${output}"

  grep -E "^${expected_workload}[[:space:]]" "${output}" >/dev/null \
    || die "${release_name} did not produce an API-valid adapter workload"
}

node_image=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --node-image)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      node_image="$2"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

case "${node_image}" in
  "${KIND_134_IMAGE}"|"${KIND_135_IMAGE}"|"${KIND_136_IMAGE}")
    ;;
  *)
    die "--node-image must be one of the three reviewed Kubernetes 1.34-1.36 digests"
    ;;
esac

timeout_seconds="${FILEBELT_KUBERNETES_TIMEOUT_SECONDS:-420}"
if ! [[ "${timeout_seconds}" =~ ^[0-9]+$ ]] \
  || (( timeout_seconds < 120 || timeout_seconds > 900 )); then
  die "FILEBELT_KUBERNETES_TIMEOUT_SECONDS must be a decimal value from 120 through 900"
fi

for command in docker grep helm kind kubectl mktemp; do
  require_command "${command}"
done
[[ -f "${chart_dir}/Chart.yaml" ]] || die "chart is unavailable: ${chart_dir}"
[[ -f "${onlyoffice_chart_dir}/Chart.yaml" ]] \
  || die "chart is unavailable: ${onlyoffice_chart_dir}"
[[ -f "${git_chart_dir}/Chart.yaml" ]] || die "chart is unavailable: ${git_chart_dir}"
[[ -f "${ci_values}" ]] || die "CI values are unavailable: ${ci_values}"

work_dir="$(mktemp -d "${temp_root%/}/filebelt-kind-compatibility.XXXXXX")"
export KUBECONFIG="${work_dir}/kubeconfig"
run_id="$(date -u +%s)-$$-${RANDOM}"
cluster_name="filebelt-kind-${run_id}"

kind create cluster \
  --name "${cluster_name}" \
  --image "${node_image}" \
  --kubeconfig "${KUBECONFIG}" \
  --wait "${timeout_seconds}s"

# Kind may report node readiness just before a rootless Docker port-forward is
# observable by the client namespace. Require a stable API response instead of
# turning that short transport race into a compatibility failure.
api_ready=false
for ((attempt = 1; attempt <= 30; attempt++)); do
  if kubectl_cmd get --raw /readyz 2>/dev/null | grep -Fxq ok; then
    api_ready=true
    break
  fi
  sleep 2
done
[[ "${api_ready}" == "true" ]] || die "the Kind API server did not become reachable"
kubectl_cmd wait --for=condition=Ready node --all --timeout="${timeout_seconds}s"

expected_version="${node_image#kindest/node:}"
expected_version="${expected_version%%@*}"
actual_version="$(kubectl_cmd get --raw /version \
  | grep -Eo '"gitVersion"[[:space:]]*:[[:space:]]*"v[0-9]+\.[0-9]+\.[0-9]+' \
  | grep -Eo 'v[0-9]+\.[0-9]+\.[0-9]+' \
  | head -n 1)"
[[ "${actual_version}" == "${expected_version}" ]] \
  || die "API server version ${actual_version:-unknown} does not match ${expected_version}"

kubectl_cmd create namespace "${NAMESPACE}"
kubectl_cmd create namespace "${RUNNER_NAMESPACE}"
kubectl_cmd create namespace "${ONLYOFFICE_NAMESPACE}"
kubectl_cmd create namespace "${GIT_NAMESPACE}"
for namespace in \
  "${NAMESPACE}" \
  "${RUNNER_NAMESPACE}" \
  "${ONLYOFFICE_NAMESPACE}" \
  "${GIT_NAMESPACE}"; do
  kubectl_cmd label --overwrite namespace "${namespace}" \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/enforce-version=latest \
    pod-security.kubernetes.io/audit=restricted \
    pod-security.kubernetes.io/warn=restricted >/dev/null
done

# The restricted namespace admission path and the live API server jointly
# validate every base object before Helm records a revision.
server_validate base

# Qualified adapter renders remain read-only here: server dry-run validates
# exact release-evidence metadata and restricted workload admission without
# pulling either independently released adapter image.
server_validate_adapter onlyoffice "${onlyoffice_chart_dir}" \
  "${ONLYOFFICE_NAMESPACE}" deployment.apps/filebelt-onlyoffice
server_validate_adapter git "${git_chart_dir}" \
  "${GIT_NAMESPACE}" statefulset.apps/filebelt-git

# Submit the opt-in broker, controller, namespace RBAC, and NetworkPolicy
# topology to the live API server as well. Quiescing keeps this a pure schema
# and restricted-admission check without requiring release images or Secrets.
mcp_config="${work_dir}/filebelt-mcp.toml"
awk '
  /^  filebelt: \|$/ { in_filebelt=1; next }
  /^  oxibelt: \|$/ { in_filebelt=0 }
  in_filebelt { sub(/^    /, ""); print }
' "${chart_dir}/values.yaml" >"${mcp_config}"
cat >>"${mcp_config}" <<EOF

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
url = "https://filebelt-mcp-broker.${NAMESPACE}.svc:8082/"
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
ports = [443]

[mcp.runners]
enabled = true
namespace = "${RUNNER_NAMESPACE}"
catalog_file = "/etc/filebelt/mcp/catalog/catalog.json"
trusted_root_file = "/etc/filebelt/mcp/trust/trusted-root.json"
bundle_directory = "/etc/filebelt/mcp/bundles"
runner_image = "ghcr.io/oxibelt/filebelt-mcp-runner@sha256:0000000000000000000000000000000000000000000000000000000000000000"
controller_url = "https://filebelt-controller.${NAMESPACE}.svc:8083/"
controller_client_certificate_chain_file = "/run/secrets/controller-client-tls/tls.crt"
controller_client_private_key_file = "/run/secrets/controller-client-tls/tls.key"
controller_server_ca_file = "/run/secrets/controller-client-tls/server-ca.crt"
max_per_principal = 1
max_per_tenant = 8
EOF
api_address="$(kubectl_cmd get service kubernetes --namespace default -o jsonpath='{.spec.clusterIP}')"
if [[ "${api_address}" == *:* ]]; then api_cidr="${api_address}/128"; else api_cidr="${api_address}/32"; fi
server_validate mcp \
  --set mcp.enabled=true \
  --set mcp.runners.enabled=true \
  --set-string mcp.runners.namespace="${RUNNER_NAMESPACE}" \
  --set networkPolicy.mcpGateway.enabled=true \
  --set networkPolicy.kubernetesApi.enabled=true \
  --set-json "networkPolicy.kubernetesApi.to=[{\"ipBlock\":{\"cidr\":\"${api_cidr}\"}}]" \
  --set-file configuration.filebelt="${mcp_config}"

# Phase 6 is also a live restricted-admission check. It deliberately remains
# quiesced, so no adapter image, Headscale credential, or operator RWO claim is
# consumed; the API server still validates the StatefulSet, sidecars, Services,
# PDB, and default-deny policy topology.
server_validate mounts \
  --set mounts.smb.enabled=true \
  --set mounts.ftpFtps.enabled=true \
  --set-json 'networkPolicy.headscale.to=[{"ipBlock":{"cidr":"192.0.2.10/32"}}]' \
  --set-json 'networkPolicy.mountIngress.from=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"filebelt-tailnet"}}}]'

# NFS renders a split relay/backend topology. Keep the release quiesced so
# server-side validation proves the current Kubernetes API accepts its
# StatefulSets, fixed ClusterIP Services, and NetworkPolicies without pulling
# the unqualified Ganesha image or claiming operator-owned RWO storage.
nfs_validation_values=(
  --set mounts.nfs.enabled=true
  --set-string images.filebelt-nfs-gateway.digest=sha256:1111111111111111111111111111111111111111111111111111111111111111
  --set-string images.filebelt-nfs-relay.digest=sha256:3333333333333333333333333333333333333333333333333333333333333333
  --set-string images.tailscaled.digest=sha256:2222222222222222222222222222222222222222222222222222222222222222
  --set-string mounts.vfs.clusterIP=10.96.20.10
  --set-string mounts.nfs.backendClusterIP=10.96.20.11
  --set-string mounts.nfs.realm=EXAMPLE.TEST
  --set-string mounts.nfs.idmapDomain=example.test
  --set-string mounts.nfs.tailstateClaim=filebelt-nfs-tailstate
  --set-string mounts.nfs.recoveryClaim=filebelt-nfs-recovery
  --set-json 'mounts.nfs.ganesha.command=["/contract/ganesha"]'
  --set-json 'mounts.nfs.ganesha.healthCommand=["/contract/ganesha-health"]'
  --set-json 'mounts.nfs.ganesha.preStopCommand=["/contract/ganesha-drain"]'
  --set-string mounts.nfs.ganesha.configMap.name=filebelt-nfs-ganesha-config
  --set-json 'mounts.nfs.bridge.command=["/contract/bridge"]'
  --set-json 'mounts.nfs.bridge.healthCommand=["/contract/bridge-health"]'
  --set-json 'mounts.nfs.bridge.preStopCommand=["/contract/bridge-drain"]'
  --set-string mounts.nfs.bridge.configMap.name=filebelt-nfs-bridge-config
  --set-json 'networkPolicy.headscale.to=[{"ipBlock":{"cidr":"192.0.2.10/32"}}]'
  --set-json 'networkPolicy.mountIngress.from=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"filebelt-tailnet"}}}]'
)
server_validate nfs "${nfs_validation_values[@]}"
helm --kubeconfig "${KUBECONFIG}" upgrade --install "${RELEASE_NAME}" "${chart_dir}" \
  --namespace "${NAMESPACE}" \
  --values "${ci_values}" \
  --set deployment.quiesced=true \
  --atomic \
  --wait \
  --timeout "${timeout_seconds}s"

[[ "$(kubectl_cmd get deployment --namespace "${NAMESPACE}" -o jsonpath='{range .items[*]}{.spec.replicas}{"\n"}{end}' | sort -u)" == "0" ]] \
  || die "the compatibility release must remain quiesced"
if [[ -n "$(kubectl_cmd get pods --namespace "${NAMESPACE}" --no-headers 2>/dev/null)" ]]; then
  die "the quiesced compatibility release unexpectedly created Pods"
fi

old_config_name="$(kubectl_cmd get deployment filebelt-api --namespace "${NAMESPACE}" \
  -o jsonpath='{.spec.template.spec.volumes[?(@.name=="filebelt-config")].configMap.name}')"
old_checksum="$(kubectl_cmd get deployment filebelt-api --namespace "${NAMESPACE}" \
  -o jsonpath='{.spec.template.metadata.annotations.checksum/config}')"
[[ -n "${old_config_name}" && -n "${old_checksum}" ]] \
  || die "the initial immutable configuration identity is missing"
[[ "$(kubectl_cmd get configmap "${old_config_name}" --namespace "${NAMESPACE}" -o jsonpath='{.immutable}')" == "true" ]] \
  || die "the initial content-addressed ConfigMap is not immutable"

changed_config=$'version = 9\n\n[deployment]\nmode = "kubernetes"\n\n[keys]\ndigest_key_file = "/run/secrets/digest-key"\ndigest_key_generation = 1\n\n[keys.api_storage]\nprivate_key_file = "/run/secrets/api-storage-capability-private-key"\npublic_keyset_file = "/run/secrets/api-storage-capability-public-keyset"\ncurrent_generation = 1\n\n[media]\nenabled = false\n\n[media.capability_signing]\nprivate_key_file = "/run/secrets/media-storage-capability-private-key"\npublic_keyset_file = "/run/secrets/media-storage-capability-public-keyset"\ncurrent_generation = 1\n\n[acceptance]\nrevision = "second"'
helm --kubeconfig "${KUBECONFIG}" upgrade "${RELEASE_NAME}" "${chart_dir}" \
  --namespace "${NAMESPACE}" \
  --reuse-values \
  --set deployment.quiesced=true \
  --set-string "configuration.filebelt=${changed_config}" \
  --atomic \
  --wait \
  --timeout "${timeout_seconds}s"

new_config_name="$(kubectl_cmd get deployment filebelt-api --namespace "${NAMESPACE}" \
  -o jsonpath='{.spec.template.spec.volumes[?(@.name=="filebelt-config")].configMap.name}')"
new_checksum="$(kubectl_cmd get deployment filebelt-api --namespace "${NAMESPACE}" \
  -o jsonpath='{.spec.template.metadata.annotations.checksum/config}')"
[[ "${new_config_name}" != "${old_config_name}" ]] \
  || die "changed configuration did not select a new content-addressed ConfigMap"
[[ "${new_checksum}" != "${old_checksum}" ]] \
  || die "changed configuration did not change the Pod-template identity"
[[ "$(kubectl_cmd get configmap "${new_config_name}" --namespace "${NAMESPACE}" -o jsonpath='{.immutable}')" == "true" ]] \
  || die "the upgraded content-addressed ConfigMap is not immutable"
[[ "$(kubectl_cmd get configmap "${new_config_name}" --namespace "${NAMESPACE}" -o jsonpath='{.data.filebelt\.toml}')" == *'revision = "second"'* ]] \
  || die "the upgraded ConfigMap does not contain the second revision"

helm --kubeconfig "${KUBECONFIG}" rollback "${RELEASE_NAME}" 1 \
  --namespace "${NAMESPACE}" \
  --wait \
  --timeout "${timeout_seconds}s"
rolled_back_name="$(kubectl_cmd get deployment filebelt-api --namespace "${NAMESPACE}" \
  -o jsonpath='{.spec.template.spec.volumes[?(@.name=="filebelt-config")].configMap.name}')"
rolled_back_checksum="$(kubectl_cmd get deployment filebelt-api --namespace "${NAMESPACE}" \
  -o jsonpath='{.spec.template.metadata.annotations.checksum/config}')"
[[ "${rolled_back_name}" == "${old_config_name}" && "${rolled_back_checksum}" == "${old_checksum}" ]] \
  || die "Helm rollback did not restore the prior configuration identity"
[[ "$(kubectl_cmd get configmap "${old_config_name}" --namespace "${NAMESPACE}" -o jsonpath='{.immutable}')" == "true" ]] \
  || die "Helm rollback did not restore the prior immutable ConfigMap"

# Render each bounded administrative operation and submit it to the live API
# server under restricted Pod Security. Server dry-run proves schema and
# admission validity without executing an image or mutating operator data.
server_validate migrate \
  --set-string operation.type=migrate \
  --set-string operation.operationId="${OPERATION_ID}"
server_validate bootstrap \
  --set-string operation.type=bootstrap \
  --set-string operation.operationId="${OPERATION_ID}"
server_validate verify-grants \
  --set-string operation.type=verify-grants \
  --set-string operation.operationId="${OPERATION_ID}"
server_validate storage-probe \
  --set-string operation.type=storage-probe \
  --set-string operation.operationId="${OPERATION_ID}"
server_validate storage-scrub-start \
  --set-string operation.type=storage-scrub-start \
  --set-string operation.operationId="${OPERATION_ID}" \
  --set-string operation.payloadId=123e4567-e89b-42d3-a456-426614174001
server_validate storage-scrub-status \
  --set-string operation.type=storage-scrub-status \
  --set-string operation.operationId="${OPERATION_ID}"
server_validate storage-scrub-verify \
  --set-string operation.type=storage-scrub-verify \
  --set-string operation.operationId="${OPERATION_ID}"
server_validate recovery-checkpoint \
  --set-string operation.type=recovery-checkpoint \
  --set-string operation.operationId="${OPERATION_ID}"
server_validate recovery-verify \
  --set-string operation.type=recovery-verify \
  --set-string operation.operationId="${OPERATION_ID}" \
  --set-string operation.checkpoint.secretName=filebelt-checkpoint-ci
server_validate audit-export \
  --set-string operation.type=audit-export \
  --set-string operation.operationId="${OPERATION_ID}"
server_validate security-descendant-shares-status \
  --set-string operation.type=security-descendant-shares-status \
  --set-string operation.operationId="${OPERATION_ID}"
for security_operation in repair verify activate; do
  server_validate "security-descendant-shares-${security_operation}" \
    --set-string operation.type="security-descendant-shares-${security_operation}" \
    --set-string operation.operationId="${OPERATION_ID}" \
    --set-string operation.tenantSlugConfirmation=development \
    --set-string operation.actorPrincipalId=123e4567-e89b-42d3-a456-426614174001
done

echo "Kubernetes Kind compatibility check passed for ${expected_version}"
