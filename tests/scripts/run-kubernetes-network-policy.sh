#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

umask 077

readonly SUPPORTED_KUBERNETES_VERSION="v1.34.10"
readonly PRERELEASE_KUBERNETES_VERSION="v1.37.0-rc.0"
readonly RELEASE_NAME="network-policy"
readonly FILEBELT_NAMESPACE="filebelt-ci"
readonly CLIENT_NAMESPACE="filebelt-ci-clients"
readonly DEPENDENCY_NAMESPACE="filebelt-ci-dependencies"
readonly MONITORING_NAMESPACE="filebelt-ci-monitoring"
readonly ARBITRARY_NAMESPACE="filebelt-ci-arbitrary"
readonly AGNHOST_IMAGE="registry.k8s.io/e2e-test-images/agnhost:2.61@sha256:101f3357d1ad890c3090e78ea6c6a47dc5137cbe19836796e13d5dcb2b84d2e6"
readonly CURL_IMAGE="quay.io/cilium/alpine-curl:v1.10.0@sha256:913e8c9f3d960dde03882defa0edd3a919d529c2eb167caa7f54194528bde364"

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
chart_dir="${repo_root}/deploy/helm/filebelt"
ci_values="${repo_root}/tests/kubernetes/values-ci.yaml"
temp_root="${TMPDIR:-/tmp}"
work_dir=""
profile_name=""

die() {
  echo "Kubernetes NetworkPolicy check: $*" >&2
  exit 1
}

usage() {
  echo "usage: $0 --cni <calico|cilium> [--kubernetes-version <version>]" >&2
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

kubectl_cmd() {
  kubectl --kubeconfig "${KUBECONFIG}" "$@"
}

diagnose() {
  set +e
  echo "--- Kubernetes NetworkPolicy diagnostics (${cni:-unknown}) ---" >&2
  kubectl_cmd get nodes -o wide >&2
  kubectl_cmd get pods,service,networkpolicy --all-namespaces -o wide >&2
  kubectl_cmd get events --all-namespaces --sort-by=.lastTimestamp >&2
  if [[ "${cni:-}" == "calico" ]]; then
    kubectl_cmd logs --namespace kube-system --selector k8s-app=calico-node \
      --all-containers=true --tail=120 >&2
  elif [[ "${cni:-}" == "cilium" ]]; then
    kubectl_cmd logs --namespace kube-system --selector k8s-app=cilium \
      --all-containers=true --tail=120 >&2
  fi
}

cleanup() {
  local status="$?"
  set +e

  if [[ "${status}" -ne 0 && -n "${profile_name}" ]]; then
    diagnose
  fi
  if [[ -n "${profile_name}" ]]; then
    minikube delete --profile "${profile_name}" >/dev/null 2>&1 || true
  fi
  case "${work_dir}" in
    "${temp_root%/}"/filebelt-network-policy.*)
      rm -rf -- "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected NetworkPolicy work directory: ${work_dir}" >&2
      ;;
  esac
  exit "${status}"
}
trap cleanup EXIT HUP INT TERM

run_curl() {
  local namespace="$1"
  local pod="$2"
  local url="$3"

  kubectl_cmd exec --namespace "${namespace}" "${pod}" --container client -- \
    curl --fail --silent --show-error --connect-timeout 1 --max-time 3 "${url}" \
    >/dev/null 2>&1
}

run_dns_lookup() {
  local namespace="$1"
  local pod="$2"
  local hostname="$3"

  kubectl_cmd exec --namespace "${namespace}" "${pod}" --container client -- \
    nslookup "${hostname}" >/dev/null 2>&1
}

expect_allowed() {
  local description="$1"
  shift
  local attempt

  for attempt in {1..10}; do
    if "$@"; then
      return 0
    fi
    sleep 1
  done
  die "${description} remained unavailable"
}

expect_denied() {
  local description="$1"
  shift
  local attempt

  for attempt in 1 2 3; do
    if "$@"; then
      die "${description} unexpectedly succeeded"
    fi
    sleep 1
  done
}

wait_for_policy_denial() {
  local description="$1"
  shift
  local attempt
  local consecutive_denials=0

  for ((attempt = 1; attempt <= 20; attempt++)); do
    if "$@"; then
      consecutive_denials=0
    else
      consecutive_denials="$((consecutive_denials + 1))"
      if (( consecutive_denials == 3 )); then
        return 0
      fi
    fi
    sleep 1
  done
  die "${description} remained reachable after policy propagation"
}

cni=""
kubernetes_version="${SUPPORTED_KUBERNETES_VERSION}"
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --cni)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      cni="$2"
      shift 2
      ;;
    --kubernetes-version)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      kubernetes_version="$2"
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
case "${cni}" in
  calico|cilium)
    ;;
  *)
    die "--cni must be calico or cilium"
    ;;
esac
case "${kubernetes_version}" in
  "${SUPPORTED_KUBERNETES_VERSION}"|"${PRERELEASE_KUBERNETES_VERSION}")
    ;;
  *)
    die "--kubernetes-version must be the supported baseline or reviewed prerelease"
    ;;
esac

timeout_seconds="${FILEBELT_KUBERNETES_TIMEOUT_SECONDS:-600}"
if ! [[ "${timeout_seconds}" =~ ^[0-9]+$ ]] \
  || (( timeout_seconds < 120 || timeout_seconds > 900 )); then
  die "FILEBELT_KUBERNETES_TIMEOUT_SECONDS must be a decimal value from 120 through 900"
fi

for command in awk docker grep helm kubectl minikube mktemp; do
  require_command "${command}"
done
[[ -f "${chart_dir}/Chart.yaml" ]] || die "chart is unavailable: ${chart_dir}"
[[ -f "${ci_values}" ]] || die "CI values are unavailable: ${ci_values}"

minikube_root_compatibility=()
if [[ "${EUID}" -eq 0 ]]; then
  docker info --format '{{json .SecurityOptions}}' | grep -Fq '"name=rootless"' \
    || die "refusing the Minikube Docker-driver test as root unless Docker reports rootless mode"
  minikube_root_compatibility=(--force)
fi

work_dir="$(mktemp -d "${temp_root%/}/filebelt-network-policy.XXXXXX")"
export MINIKUBE_HOME="${work_dir}/minikube-home"
export KUBECONFIG="${work_dir}/kubeconfig"
mkdir -p "${MINIKUBE_HOME}"
run_id="$(date -u +%s)-$$-${RANDOM}"
profile_name="filebelt-np-${run_id}"

if ! minikube start \
  --profile "${profile_name}" \
  --driver=docker \
  --container-runtime=containerd \
  --cni="${cni}" \
  --kubernetes-version="${kubernetes_version}" \
  --output=json \
  --wait=all \
  --wait-timeout="${timeout_seconds}s" \
  "${minikube_root_compatibility[@]}" >"${work_dir}/minikube-start.log" 2>&1; then
  tail -n 160 "${work_dir}/minikube-start.log" >&2 || true
  die "Minikube did not start with the requested ${cni} CNI"
fi

kubectl_cmd wait --for=condition=Ready node --all --timeout="${timeout_seconds}s"
actual_version="$(kubectl_cmd get --raw /version \
  | grep -Eo '"gitVersion"[[:space:]]*:[[:space:]]*"v[^"]+' \
  | sed -E 's/^.*"(v[^"]+)$/\1/' \
  | head -n 1)"
[[ "${actual_version}" == "${kubernetes_version}" ]] \
  || die "API server version ${actual_version:-unknown} does not match ${kubernetes_version}"
if [[ "${cni}" == "calico" ]]; then
  kubectl_cmd wait --namespace kube-system --for=condition=Ready pod \
    --selector k8s-app=calico-node --timeout="${timeout_seconds}s"
else
  kubectl_cmd wait --namespace kube-system --for=condition=Ready pod \
    --selector k8s-app=cilium --timeout="${timeout_seconds}s"
fi

for namespace in \
  "${FILEBELT_NAMESPACE}" \
  "${CLIENT_NAMESPACE}" \
  "${DEPENDENCY_NAMESPACE}" \
  "${MONITORING_NAMESPACE}" \
  "${ARBITRARY_NAMESPACE}"; do
  kubectl_cmd create namespace "${namespace}"
  kubectl_cmd label --overwrite namespace "${namespace}" \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/enforce-version=latest \
    pod-security.kubernetes.io/audit=restricted \
    pod-security.kubernetes.io/warn=restricted >/dev/null
done

# The NFS chart path is intentionally tested with fixture images: Ganesha and
# the relay image have separate qualification gates, while these Pods exercise
# the exact labels, named ports, and policy selectors rendered by the chart.
nfs_policy_values=(
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
  --set-json "networkPolicy.headscale.to=[{\"namespaceSelector\":{\"matchLabels\":{\"kubernetes.io/metadata.name\":\"${DEPENDENCY_NAMESPACE}\"}},\"podSelector\":{\"matchLabels\":{\"app.kubernetes.io/name\":\"filebelt-ci-headscale\"}}}]"
  --set-json "networkPolicy.mountIngress.from=[{\"namespaceSelector\":{\"matchLabels\":{\"kubernetes.io/metadata.name\":\"${CLIENT_NAMESPACE}\"}},\"podSelector\":{\"matchLabels\":{\"app.kubernetes.io/name\":\"filebelt-ci-mount-peer\"}}}]"
)
nfs_topology_generation="$(helm template "${RELEASE_NAME}" "${chart_dir}" \
  --namespace "${FILEBELT_NAMESPACE}" \
  --values "${ci_values}" \
  --set deployment.quiesced=true \
  "${nfs_policy_values[@]}" \
  --show-only templates/mounts.yaml |
  awk -F '"' '/filebelt.dev\/nfs-topology-generation:/ && generation == "" { generation = $2 } END { print generation }')"
[[ "${nfs_topology_generation}" =~ ^[0-9a-f]{16}$ ]] \
  || die "could not derive the NFS topology generation"

# All fixtures satisfy restricted Pod Security and use immutable image
# references. The FileBelt role labels and named ports intentionally match the
# chart selectors so this exercises the rendered policy graph rather than a
# hand-written approximation.
kubectl_cmd apply --filename - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: web
  namespace: ${FILEBELT_NAMESPACE}
  labels: {app.kubernetes.io/name: filebelt, app.kubernetes.io/instance: ${RELEASE_NAME}, app.kubernetes.io/component: web}
spec:
  automountServiceAccountToken: false
  enableServiceLinks: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: https
      image: ${AGNHOST_IMAGE}
      command: [/agnhost, netexec, --http-port=8443, --udp-port=-1]
      ports: [{name: https, containerPort: 8443, protocol: TCP}]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
    - name: metrics
      image: ${AGNHOST_IMAGE}
      command: [/agnhost, netexec, --http-port=9090, --udp-port=-1]
      ports: [{name: metrics, containerPort: 9090, protocol: TCP}]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
    - name: client
      image: ${CURL_IMAGE}
      command: [/bin/sh, -c, sleep 3600]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
---
apiVersion: v1
kind: Service
metadata: {name: fixture-web, namespace: ${FILEBELT_NAMESPACE}}
spec:
  selector: {app.kubernetes.io/name: filebelt, app.kubernetes.io/instance: ${RELEASE_NAME}, app.kubernetes.io/component: web}
  ports:
    - {name: https, port: 8443, targetPort: https, protocol: TCP}
    - {name: metrics, port: 9090, targetPort: metrics, protocol: TCP}
---
apiVersion: v1
kind: Service
metadata: {name: fixture-api, namespace: ${FILEBELT_NAMESPACE}}
spec:
  selector: {app.kubernetes.io/name: filebelt, app.kubernetes.io/instance: ${RELEASE_NAME}, app.kubernetes.io/component: api}
  ports:
    - {name: api, port: 8080, targetPort: api, protocol: TCP}
    - {name: metrics, port: 9090, targetPort: operations, protocol: TCP}
---
apiVersion: v1
kind: Service
metadata: {name: fixture-io, namespace: ${FILEBELT_NAMESPACE}}
spec:
  selector: {app.kubernetes.io/name: filebelt, app.kubernetes.io/instance: ${RELEASE_NAME}, app.kubernetes.io/component: io}
  ports:
    - {name: io, port: 8081, targetPort: io, protocol: TCP}
    - {name: metrics, port: 9090, targetPort: operations, protocol: TCP}
---
apiVersion: v1
kind: Service
metadata: {name: fixture-maintenance, namespace: ${FILEBELT_NAMESPACE}}
spec:
  selector: {app.kubernetes.io/name: filebelt, app.kubernetes.io/instance: ${RELEASE_NAME}, app.kubernetes.io/component: maintenance}
  ports: [{name: metrics, port: 9090, targetPort: operations, protocol: TCP}]
---
apiVersion: v1
kind: Service
metadata: {name: fixture-vfs, namespace: ${FILEBELT_NAMESPACE}}
spec:
  selector: {app.kubernetes.io/name: filebelt, app.kubernetes.io/instance: ${RELEASE_NAME}, app.kubernetes.io/component: vfs}
  ports: [{name: vfs, port: 8087, targetPort: vfs, protocol: TCP}]
---
apiVersion: v1
kind: Service
metadata: {name: fixture-nfs-relay, namespace: ${FILEBELT_NAMESPACE}}
spec:
  selector: {app.kubernetes.io/name: filebelt, app.kubernetes.io/instance: ${RELEASE_NAME}, filebelt.dev/nfs-zone: relay, filebelt.dev/nfs-topology-generation: "${nfs_topology_generation}"}
  ports: [{name: nfs, port: 2049, targetPort: nfs, protocol: TCP}]
---
apiVersion: v1
kind: Service
metadata: {name: fixture-nfs-backend, namespace: ${FILEBELT_NAMESPACE}}
spec:
  selector: {app.kubernetes.io/name: filebelt, app.kubernetes.io/instance: ${RELEASE_NAME}, filebelt.dev/nfs-zone: backend, filebelt.dev/nfs-topology-generation: "${nfs_topology_generation}"}
  ports: [{name: nfs, port: 2049, targetPort: nfs, protocol: TCP}]
---
apiVersion: v1
kind: Pod
metadata:
  name: api
  namespace: ${FILEBELT_NAMESPACE}
  labels: {app.kubernetes.io/name: filebelt, app.kubernetes.io/instance: ${RELEASE_NAME}, app.kubernetes.io/component: api}
spec:
  automountServiceAccountToken: false
  enableServiceLinks: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: api
      image: ${AGNHOST_IMAGE}
      command: [/agnhost, netexec, --http-port=8080, --udp-port=-1]
      ports: [{name: api, containerPort: 8080, protocol: TCP}]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
    - name: metrics
      image: ${AGNHOST_IMAGE}
      command: [/agnhost, netexec, --http-port=9090, --udp-port=-1]
      ports: [{name: operations, containerPort: 9090, protocol: TCP}]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
    - name: client
      image: ${CURL_IMAGE}
      command: [/bin/sh, -c, sleep 3600]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
---
apiVersion: v1
kind: Pod
metadata:
  name: vfs
  namespace: ${FILEBELT_NAMESPACE}
  labels: {app.kubernetes.io/name: filebelt, app.kubernetes.io/instance: ${RELEASE_NAME}, app.kubernetes.io/component: vfs}
spec:
  automountServiceAccountToken: false
  enableServiceLinks: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: vfs
      image: ${AGNHOST_IMAGE}
      command: [/agnhost, netexec, --http-port=8087, --udp-port=-1]
      ports: [{name: vfs, containerPort: 8087, protocol: TCP}]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
---
apiVersion: v1
kind: Pod
metadata:
  name: nfs-relay
  namespace: ${FILEBELT_NAMESPACE}
  labels: {app.kubernetes.io/name: filebelt, app.kubernetes.io/instance: ${RELEASE_NAME}, app.kubernetes.io/component: nfs-relay, filebelt.dev/nfs-zone: relay, filebelt.dev/nfs-topology-generation: "${nfs_topology_generation}"}
spec:
  automountServiceAccountToken: false
  enableServiceLinks: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: nfs
      image: ${AGNHOST_IMAGE}
      command: [/agnhost, netexec, --http-port=2049, --udp-port=-1]
      ports: [{name: nfs, containerPort: 2049, protocol: TCP}]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
    - name: client
      image: ${CURL_IMAGE}
      command: [/bin/sh, -c, sleep 3600]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
---
apiVersion: v1
kind: Pod
metadata:
  name: nfs-backend
  namespace: ${FILEBELT_NAMESPACE}
  labels: {app.kubernetes.io/name: filebelt, app.kubernetes.io/instance: ${RELEASE_NAME}, app.kubernetes.io/component: nfs-gateway, filebelt.dev/nfs-zone: backend, filebelt.dev/nfs-topology-generation: "${nfs_topology_generation}"}
spec:
  automountServiceAccountToken: false
  enableServiceLinks: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: nfs
      image: ${AGNHOST_IMAGE}
      command: [/agnhost, netexec, --http-port=2049, --udp-port=-1]
      ports: [{name: nfs, containerPort: 2049, protocol: TCP}]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
    - name: client
      image: ${CURL_IMAGE}
      command: [/bin/sh, -c, sleep 3600]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
---
apiVersion: v1
kind: Pod
metadata:
  name: io
  namespace: ${FILEBELT_NAMESPACE}
  labels: {app.kubernetes.io/name: filebelt, app.kubernetes.io/instance: ${RELEASE_NAME}, app.kubernetes.io/component: io}
spec:
  automountServiceAccountToken: false
  enableServiceLinks: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: io
      image: ${AGNHOST_IMAGE}
      command: [/agnhost, netexec, --http-port=8081, --udp-port=-1]
      ports: [{name: io, containerPort: 8081, protocol: TCP}]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
    - name: metrics
      image: ${AGNHOST_IMAGE}
      command: [/agnhost, netexec, --http-port=9090, --udp-port=-1]
      ports: [{name: operations, containerPort: 9090, protocol: TCP}]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
    - name: client
      image: ${CURL_IMAGE}
      command: [/bin/sh, -c, sleep 3600]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
---
apiVersion: v1
kind: Pod
metadata:
  name: maintenance
  namespace: ${FILEBELT_NAMESPACE}
  labels: {app.kubernetes.io/name: filebelt, app.kubernetes.io/instance: ${RELEASE_NAME}, app.kubernetes.io/component: maintenance}
spec:
  automountServiceAccountToken: false
  enableServiceLinks: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: metrics
      image: ${AGNHOST_IMAGE}
      command: [/agnhost, netexec, --http-port=9090, --udp-port=-1]
      ports: [{name: operations, containerPort: 9090, protocol: TCP}]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
    - name: client
      image: ${CURL_IMAGE}
      command: [/bin/sh, -c, sleep 3600]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
---
apiVersion: v1
kind: Pod
metadata:
  name: public
  namespace: ${CLIENT_NAMESPACE}
  labels: {app.kubernetes.io/name: filebelt-ci-client}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: client
      image: ${CURL_IMAGE}
      command: [/bin/sh, -c, sleep 3600]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
---
apiVersion: v1
kind: Pod
metadata:
  name: mount-peer
  namespace: ${CLIENT_NAMESPACE}
  labels: {app.kubernetes.io/name: filebelt-ci-mount-peer}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: client
      image: ${CURL_IMAGE}
      command: [/bin/sh, -c, sleep 3600]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
---
apiVersion: v1
kind: Pod
metadata:
  name: untrusted
  namespace: ${CLIENT_NAMESPACE}
  labels: {app.kubernetes.io/name: untrusted}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: client
      image: ${CURL_IMAGE}
      command: [/bin/sh, -c, sleep 3600]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
---
apiVersion: v1
kind: Pod
metadata:
  name: monitor
  namespace: ${MONITORING_NAMESPACE}
  labels: {app.kubernetes.io/name: filebelt-ci-monitor}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: client
      image: ${CURL_IMAGE}
      command: [/bin/sh, -c, sleep 3600]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
---
apiVersion: v1
kind: Pod
metadata:
  name: postgresql
  namespace: ${DEPENDENCY_NAMESPACE}
  labels: {app.kubernetes.io/name: filebelt-ci-postgresql}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: server
      image: ${AGNHOST_IMAGE}
      command: [/agnhost, netexec, --http-port=5432, --udp-port=-1]
      ports: [{name: postgres, containerPort: 5432, protocol: TCP}]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
---
apiVersion: v1
kind: Service
metadata: {name: postgresql, namespace: ${DEPENDENCY_NAMESPACE}}
spec:
  selector: {app.kubernetes.io/name: filebelt-ci-postgresql}
  ports: [{name: postgres, port: 5432, targetPort: postgres, protocol: TCP}]
---
apiVersion: v1
kind: Pod
metadata:
  name: oidc
  namespace: ${DEPENDENCY_NAMESPACE}
  labels: {app.kubernetes.io/name: filebelt-ci-oidc-egress}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: server
      image: ${AGNHOST_IMAGE}
      command: [/agnhost, netexec, --http-port=8080, --udp-port=-1]
      ports: [{name: oidc, containerPort: 8080, protocol: TCP}]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
---
apiVersion: v1
kind: Service
metadata: {name: oidc, namespace: ${DEPENDENCY_NAMESPACE}}
spec:
  selector: {app.kubernetes.io/name: filebelt-ci-oidc-egress}
  ports: [{name: oidc, port: 8080, targetPort: oidc, protocol: TCP}]
---
apiVersion: v1
kind: Pod
metadata:
  name: headscale
  namespace: ${DEPENDENCY_NAMESPACE}
  labels: {app.kubernetes.io/name: filebelt-ci-headscale}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: server
      image: ${AGNHOST_IMAGE}
      command: [/agnhost, netexec, --http-port=443, --udp-port=-1]
      ports: [{name: https, containerPort: 443, protocol: TCP}]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL], add: [NET_BIND_SERVICE]}, readOnlyRootFilesystem: true}
---
apiVersion: v1
kind: Service
metadata: {name: headscale, namespace: ${DEPENDENCY_NAMESPACE}}
spec:
  selector: {app.kubernetes.io/name: filebelt-ci-headscale}
  ports: [{name: https, port: 443, targetPort: https, protocol: TCP}]
---
apiVersion: v1
kind: Pod
metadata:
  name: iggy
  namespace: ${DEPENDENCY_NAMESPACE}
  labels: {app.kubernetes.io/name: filebelt-ci-iggy}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: server
      image: ${AGNHOST_IMAGE}
      command: [/agnhost, netexec, --http-port=8090, --udp-port=-1]
      ports: [{name: iggy, containerPort: 8090, protocol: TCP}]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
---
apiVersion: v1
kind: Service
metadata: {name: iggy, namespace: ${DEPENDENCY_NAMESPACE}}
spec:
  selector: {app.kubernetes.io/name: filebelt-ci-iggy}
  ports: [{name: iggy, port: 8090, targetPort: iggy, protocol: TCP}]
---
apiVersion: v1
kind: Pod
metadata:
  name: otel
  namespace: ${MONITORING_NAMESPACE}
  labels: {app.kubernetes.io/name: filebelt-ci-otel}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: server
      image: ${AGNHOST_IMAGE}
      command: [/agnhost, netexec, --http-port=4318, --udp-port=-1]
      ports: [{name: otlp, containerPort: 4318, protocol: TCP}]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
---
apiVersion: v1
kind: Service
metadata: {name: otel, namespace: ${MONITORING_NAMESPACE}}
spec:
  selector: {app.kubernetes.io/name: filebelt-ci-otel}
  ports: [{name: otlp, port: 4318, targetPort: otlp, protocol: TCP}]
---
apiVersion: v1
kind: Pod
metadata:
  name: arbitrary
  namespace: ${ARBITRARY_NAMESPACE}
  labels: {app.kubernetes.io/name: arbitrary}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: server
      image: ${AGNHOST_IMAGE}
      command: [/agnhost, netexec, --http-port=8080, --udp-port=-1]
      ports: [{name: http, containerPort: 8080, protocol: TCP}]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}
---
apiVersion: v1
kind: Service
metadata: {name: arbitrary, namespace: ${ARBITRARY_NAMESPACE}}
spec:
  selector: {app.kubernetes.io/name: arbitrary}
  ports: [{name: http, port: 8080, targetPort: http, protocol: TCP}]
EOF

for namespace_pod in \
  "${FILEBELT_NAMESPACE}/web" \
  "${FILEBELT_NAMESPACE}/api" \
  "${FILEBELT_NAMESPACE}/io" \
  "${FILEBELT_NAMESPACE}/maintenance" \
  "${FILEBELT_NAMESPACE}/vfs" \
  "${FILEBELT_NAMESPACE}/nfs-relay" \
  "${FILEBELT_NAMESPACE}/nfs-backend" \
  "${CLIENT_NAMESPACE}/public" \
  "${CLIENT_NAMESPACE}/mount-peer" \
  "${CLIENT_NAMESPACE}/untrusted" \
  "${MONITORING_NAMESPACE}/monitor" \
  "${MONITORING_NAMESPACE}/otel" \
  "${DEPENDENCY_NAMESPACE}/postgresql" \
  "${DEPENDENCY_NAMESPACE}/oidc" \
  "${DEPENDENCY_NAMESPACE}/headscale" \
  "${DEPENDENCY_NAMESPACE}/iggy" \
  "${ARBITRARY_NAMESPACE}/arbitrary"; do
  namespace="${namespace_pod%%/*}"
  pod="${namespace_pod#*/}"
  kubectl_cmd wait --namespace "${namespace}" --for=condition=Ready "pod/${pod}" \
    --timeout="${timeout_seconds}s"
done

web_ip="$(kubectl_cmd get pod web --namespace "${FILEBELT_NAMESPACE}" -o jsonpath='{.status.podIP}')"
api_ip="$(kubectl_cmd get pod api --namespace "${FILEBELT_NAMESPACE}" -o jsonpath='{.status.podIP}')"
io_ip="$(kubectl_cmd get pod io --namespace "${FILEBELT_NAMESPACE}" -o jsonpath='{.status.podIP}')"
maintenance_ip="$(kubectl_cmd get pod maintenance --namespace "${FILEBELT_NAMESPACE}" -o jsonpath='{.status.podIP}')"
vfs_ip="$(kubectl_cmd get pod vfs --namespace "${FILEBELT_NAMESPACE}" -o jsonpath='{.status.podIP}')"
nfs_relay_ip="$(kubectl_cmd get pod nfs-relay --namespace "${FILEBELT_NAMESPACE}" -o jsonpath='{.status.podIP}')"
nfs_backend_ip="$(kubectl_cmd get pod nfs-backend --namespace "${FILEBELT_NAMESPACE}" -o jsonpath='{.status.podIP}')"

# Positive controls precede policy application, so later drops cannot pass
# merely because a target image, Pod, or listener failed to start.
expect_allowed "pre-policy web listener" run_curl "${CLIENT_NAMESPACE}" public "http://${web_ip}:8443/"
expect_allowed "pre-policy API listener" run_curl "${CLIENT_NAMESPACE}" public "http://${api_ip}:8080/"
expect_allowed "pre-policy I/O listener" run_curl "${CLIENT_NAMESPACE}" public "http://${io_ip}:8081/"
expect_allowed "pre-policy maintenance metrics" run_curl "${CLIENT_NAMESPACE}" public "http://${maintenance_ip}:9090/"
expect_allowed "pre-policy mount peer reaching NFS relay" \
  run_curl "${CLIENT_NAMESPACE}" mount-peer "http://${nfs_relay_ip}:2049/"
expect_allowed "pre-policy NFS relay reaching backend" \
  run_curl "${FILEBELT_NAMESPACE}" nfs-relay "http://${nfs_backend_ip}:2049/"
expect_allowed "pre-policy NFS backend reaching VFS" \
  run_curl "${FILEBELT_NAMESPACE}" nfs-backend "http://${vfs_ip}:8087/"
expect_allowed "pre-policy arbitrary service" run_curl "${CLIENT_NAMESPACE}" public \
  "http://arbitrary.${ARBITRARY_NAMESPACE}.svc.cluster.local:8080/"

helm template "${RELEASE_NAME}" "${chart_dir}" \
  --namespace "${FILEBELT_NAMESPACE}" \
  --values "${ci_values}" \
  --set deployment.quiesced=true \
  "${nfs_policy_values[@]}" \
  --show-only templates/networkpolicies.yaml |
  kubectl_cmd apply --namespace "${FILEBELT_NAMESPACE}" \
    --server-side --field-manager=filebelt-network-policy --filename -

web_host="fixture-web.${FILEBELT_NAMESPACE}.svc.cluster.local"
api_host="fixture-api.${FILEBELT_NAMESPACE}.svc.cluster.local"
io_host="fixture-io.${FILEBELT_NAMESPACE}.svc.cluster.local"
nfs_relay_host="fixture-nfs-relay.${FILEBELT_NAMESPACE}.svc.cluster.local"
postgres_host="postgresql.${DEPENDENCY_NAMESPACE}.svc.cluster.local"
oidc_host="oidc.${DEPENDENCY_NAMESPACE}.svc.cluster.local"
headscale_host="headscale.${DEPENDENCY_NAMESPACE}.svc.cluster.local"
iggy_host="iggy.${DEPENDENCY_NAMESPACE}.svc.cluster.local"
otel_host="otel.${MONITORING_NAMESPACE}.svc.cluster.local"
arbitrary_host="arbitrary.${ARBITRARY_NAMESPACE}.svc.cluster.local"

wait_for_policy_denial "public client reaching the API" \
  run_curl "${CLIENT_NAMESPACE}" public "http://${api_host}:8080/"

# Ingress boundaries: the exact public identity reaches only OxiBelt, OxiBelt
# reaches both backends, and only the monitoring identity reaches operations.
expect_allowed "public client reaching web" \
  run_curl "${CLIENT_NAMESPACE}" public "http://${web_host}:8443/"
expect_denied "untrusted client reaching web" \
  run_curl "${CLIENT_NAMESPACE}" untrusted "http://${web_host}:8443/"
expect_denied "public client reaching I/O" \
  run_curl "${CLIENT_NAMESPACE}" public "http://${io_host}:8081/"
expect_allowed "web reaching API" \
  run_curl "${FILEBELT_NAMESPACE}" web "http://${api_host}:8080/"
expect_allowed "web reaching I/O" \
  run_curl "${FILEBELT_NAMESPACE}" web "http://${io_host}:8081/"

# NFS is split at the relay/backend boundary. The tailnet peer may reach the
# relay only; only the relay reaches the backend; and only the backend reaches
# VFS. Pod IPs avoid granting the backend DNS solely for a fixture assertion.
expect_allowed "mount peer reaching the NFS relay" \
  run_curl "${CLIENT_NAMESPACE}" mount-peer "http://${nfs_relay_host}:2049/"
expect_denied "untrusted client reaching the NFS relay" \
  run_curl "${CLIENT_NAMESPACE}" untrusted "http://${nfs_relay_host}:2049/"
expect_denied "mount peer bypassing the NFS relay" \
  run_curl "${CLIENT_NAMESPACE}" mount-peer "http://${nfs_backend_ip}:2049/"
expect_allowed "NFS relay reaching backend" \
  run_curl "${FILEBELT_NAMESPACE}" nfs-relay "http://${nfs_backend_ip}:2049/"
expect_denied "NFS backend reaching relay" \
  run_curl "${FILEBELT_NAMESPACE}" nfs-backend "http://${nfs_relay_ip}:2049/"
expect_allowed "NFS backend reaching VFS" \
  run_curl "${FILEBELT_NAMESPACE}" nfs-backend "http://${vfs_ip}:8087/"
expect_denied "NFS relay bypassing backend VFS access" \
  run_curl "${FILEBELT_NAMESPACE}" nfs-relay "http://${vfs_ip}:8087/"
expect_allowed "NFS relay DNS lookup" \
  run_dns_lookup "${FILEBELT_NAMESPACE}" nfs-relay "${headscale_host}"
expect_denied "NFS backend DNS lookup" \
  run_dns_lookup "${FILEBELT_NAMESPACE}" nfs-backend "${headscale_host}"

for component in web api io maintenance; do
  expect_allowed "monitor reaching ${component} metrics" \
    run_curl "${MONITORING_NAMESPACE}" monitor \
      "http://fixture-${component}.${FILEBELT_NAMESPACE}.svc.cluster.local:9090/"
  expect_denied "public client reaching ${component} metrics" \
    run_curl "${CLIENT_NAMESPACE}" public \
      "http://fixture-${component}.${FILEBELT_NAMESPACE}.svc.cluster.local:9090/"
done

# Egress boundaries: SQL, OIDC, Iggy, and OTLP have role-specific peers. Each
# negative assertion shares a destination with a positive control above or
# below so an unavailable dependency cannot be mistaken for enforcement.
for component in api io maintenance; do
  expect_allowed "${component} reaching PostgreSQL" \
    run_curl "${FILEBELT_NAMESPACE}" "${component}" "http://${postgres_host}:5432/"
done
expect_denied "web reaching PostgreSQL" \
  run_curl "${FILEBELT_NAMESPACE}" web "http://${postgres_host}:5432/"

expect_allowed "API reaching the OIDC gateway" \
  run_curl "${FILEBELT_NAMESPACE}" api "http://${oidc_host}:8080/"
expect_denied "I/O reaching the OIDC gateway" \
  run_curl "${FILEBELT_NAMESPACE}" io "http://${oidc_host}:8080/"
expect_denied "maintenance reaching the OIDC gateway" \
  run_curl "${FILEBELT_NAMESPACE}" maintenance "http://${oidc_host}:8080/"

expect_allowed "NFS relay reaching Headscale over HTTPS" \
  run_curl "${FILEBELT_NAMESPACE}" nfs-relay "http://${headscale_host}:443/"
expect_denied "NFS backend reaching Headscale" \
  run_curl "${FILEBELT_NAMESPACE}" nfs-backend "http://${headscale_host}:443/"

expect_allowed "maintenance reaching Iggy" \
  run_curl "${FILEBELT_NAMESPACE}" maintenance "http://${iggy_host}:8090/"
expect_denied "API reaching Iggy" \
  run_curl "${FILEBELT_NAMESPACE}" api "http://${iggy_host}:8090/"
expect_denied "I/O reaching Iggy" \
  run_curl "${FILEBELT_NAMESPACE}" io "http://${iggy_host}:8090/"

for component in web api io maintenance; do
  expect_allowed "${component} reaching OTLP" \
    run_curl "${FILEBELT_NAMESPACE}" "${component}" "http://${otel_host}:4318/"
  expect_denied "${component} general egress" \
    run_curl "${FILEBELT_NAMESPACE}" "${component}" "http://${arbitrary_host}:8080/"
done
expect_denied "NFS relay general egress" \
  run_curl "${FILEBELT_NAMESPACE}" nfs-relay "http://${arbitrary_host}:8080/"
expect_denied "NFS backend general egress" \
  run_curl "${FILEBELT_NAMESPACE}" nfs-backend "http://${arbitrary_host}:8080/"

expect_denied "API lateral access to I/O" \
  run_curl "${FILEBELT_NAMESPACE}" api "http://${io_host}:8081/"
expect_denied "I/O lateral access to API" \
  run_curl "${FILEBELT_NAMESPACE}" io "http://${api_host}:8080/"
expect_denied "maintenance lateral access to API" \
  run_curl "${FILEBELT_NAMESPACE}" maintenance "http://${api_host}:8080/"

echo "Kubernetes NetworkPolicy check passed for ${cni}"
