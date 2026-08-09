#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
workflow="${repo_root}/.github/workflows/check-filebelt.yml"
kind_script="${repo_root}/tests/scripts/run-kubernetes-kind-compatibility.sh"
network_script="${repo_root}/tests/scripts/run-kubernetes-network-policy.sh"
chart_helpers="${repo_root}/deploy/helm/filebelt/templates/_helpers.tpl"
readonly FILEBELT_CONFIGURATION_VERSION="6"

die() {
  echo "Kubernetes acceptance contract: $*" >&2
  exit 1
}

assert_contains() {
  grep -F -- "$2" "$1" >/dev/null || die "$(basename -- "$1") is missing: $2"
}

for script in "${kind_script}" "${network_script}"; do
  [[ -x "${script}" ]] || die "script is not executable: ${script}"
  bash -n "${script}"
  assert_contains "${script}" "SPDX-License-Identifier: Apache-2.0"
done

assert_contains "${workflow}" "helm/kind-action@ef37e7f390d99f746eb8b610417061a60e82a6cc"
assert_contains "${workflow}" "version: v0.32.0"
assert_contains "${workflow}" "50030de23cf40a18505f20426f6a8506bedf13c6e509244bd1fa9463721b0f54"
assert_contains "${workflow}" "MINIKUBE_VERSION: v1.38.1"
assert_contains "${workflow}" "MINIKUBE_SHA256: 099477eaf248bcb5bcea8ce78a2898e93ac01461c35189da1848c3de82ecd22e"
assert_contains "${workflow}" "phase3-kind-current:"
assert_contains "${workflow}" "phase3-kind-supported:"
assert_contains "${workflow}" "phase3-network-calico:"
assert_contains "${workflow}" "phase3-network-cilium:"
assert_contains "${workflow}" "phase3-gate:"

for node_image in \
  "kindest/node:v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256" \
  "kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95" \
  "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"; do
  assert_contains "${kind_script}" "${node_image}"
  assert_contains "${workflow}" "${node_image}"
done

assert_contains "${chart_helpers}" \
  "hasPrefix \"version = ${FILEBELT_CONFIGURATION_VERSION}\""
assert_contains "${kind_script}" \
  "changed_config=\$'version = ${FILEBELT_CONFIGURATION_VERSION}\\n"

for mcp_boundary in \
  "server_validate mcp" \
  "RUNNER_NAMESPACE=\"filebelt-kind-mcp-runners\"" \
  "create namespace \"\${RUNNER_NAMESPACE}\"" \
  "mcp.runners.namespace=\"\${RUNNER_NAMESPACE}\"" \
  "namespace = \"\${RUNNER_NAMESPACE}\"" \
  "mcp.runners.enabled=true" \
  "networkPolicy.kubernetesApi.to" \
  "controller_url = \"https://filebelt-controller."; do
  assert_contains "${kind_script}" "${mcp_boundary}"
done

for mount_boundary in \
  "server_validate mounts" \
  "mounts.enabled=true" \
  "networkPolicy.headscale.to" \
  "networkPolicy.mountIngress.from" \
  "StatefulSet, sidecars"; do
  assert_contains "${kind_script}" "${mount_boundary}"
done

assert_contains "${network_script}" \
  "registry.k8s.io/e2e-test-images/agnhost:2.61@sha256:101f3357d1ad890c3090e78ea6c6a47dc5137cbe19836796e13d5dcb2b84d2e6"
assert_contains "${network_script}" \
  "quay.io/cilium/alpine-curl:v1.10.0@sha256:913e8c9f3d960dde03882defa0edd3a919d529c2eb167caa7f54194528bde364"
for trust_edge in \
  "public client reaching web" \
  "web reaching API" \
  "web reaching I/O" \
  "reaching PostgreSQL" \
  "reaching the OIDC gateway" \
  "reaching Iggy" \
  "reaching OTLP" \
  "general egress" \
  "lateral access"; do
  assert_contains "${network_script}" "${trust_edge}"
done

echo "Kubernetes acceptance contracts passed"
