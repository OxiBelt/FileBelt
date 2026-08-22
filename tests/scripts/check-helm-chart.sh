#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly HELM_VERSION="v4.2.4"
readonly OPERATION_ID="123e4567-e89b-42d3-a456-426614174000"

repo_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
chart="${repo_root}/deploy/helm/filebelt"
temporary=""

die() {
  echo "Helm chart check: $*" >&2
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

assert_container_match() {
  local file="$1" kind="$2" name="$3" container="$4" expected="$5" mode="$6"
  python3 - "${file}" "${kind}" "${name}" "${container}" "${expected}" "${mode}" <<'PY'
import sys

manifest_path, kind, name, container, expected, mode = sys.argv[1:]
for document in open(manifest_path, encoding="utf-8").read().split("\n---\n"):
    if f"kind: {kind}" not in document or f"  name: {name}" not in document:
        continue
    lines = document.splitlines()
    marker = f"        - name: {container}"
    try:
        start = lines.index(marker)
    except ValueError as error:
        raise SystemExit(f"{kind}/{name} has no container {container}") from error
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("        - name: ") or lines[index].startswith("      volumes:"):
            end = index
            break
    block = "\n".join(lines[start:end])
    found = expected in block
    if (mode == "present" and not found) or (mode == "absent" and found):
        qualifier = "missing" if mode == "present" else "unexpectedly contains"
        raise SystemExit(f"{kind}/{name} container {container} {qualifier}: {expected}")
    raise SystemExit(0)

raise SystemExit(f"missing {kind}/{name}")
PY
}

assert_container_contains() {
  assert_container_match "$1" "$2" "$3" "$4" "$5" present
}

assert_container_not_contains() {
  assert_container_match "$1" "$2" "$3" "$4" "$5" absent
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
helm template phase7 "${chart}" --kube-version 1.36.0 \
  --set documents.enabled=true \
  >"${temporary}/render-documents.yaml"
helm template phase7-recovery "${chart}" --kube-version 1.36.0 \
  --set deployment.quiesced=true \
  --set documents.enabled=true \
  --set-string operation.type=recovery-checkpoint \
  --set-string operation.operationId="${OPERATION_ID}" \
  >"${temporary}/recovery-documents.yaml"
helm template phase7-editor-override "${chart}" --kube-version 1.36.0 \
  --set documents.enabled=true \
  --set-string documents.launchAction=https://editor.example.test/onlyoffice/launch \
  --set-string documents.providerOrigin=https://provider.example.test \
  >"${temporary}/render-documents-editor-override.yaml"
helm template phase9 "${chart}" --kube-version 1.36.0 \
  --set revisions.enabled=true \
  --set-string revisions.activation.compatibilityGate=release-a-v9 \
  >"${temporary}/render-revisions.yaml"
expect_failure revisions-without-compatibility-gate --set revisions.enabled=true
expect_failure revisions-user-limit-above-global \
  --set revisions.enabled=true \
  --set-string revisions.activation.compatibilityGate=release-a-v9 \
  --set revisions.limits.globalComparisons=2 \
  --set revisions.limits.perUserComparisons=3
assert_rendered_toml "${default_manifest}" filebelt.toml
assert_rendered_toml "${default_manifest}" oxibelt.toml
assert_rendered_toml "${temporary}/render-ci-values.yaml" filebelt.toml
assert_rendered_toml "${temporary}/render-ci-values.yaml" oxibelt.toml
assert_rendered_toml "${temporary}/render-documents.yaml" filebelt.toml
assert_rendered_toml "${temporary}/render-documents.yaml" oxibelt.toml
assert_rendered_toml "${temporary}/render-documents-editor-override.yaml" filebelt.toml
assert_rendered_toml "${temporary}/render-documents-editor-override.yaml" oxibelt.toml
assert_rendered_toml "${temporary}/render-revisions.yaml" filebelt.toml
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
assert_not_contains "${default_manifest}" 'filebelt-document'
assert_not_contains "${default_manifest}" 'filebelt-mcp-broker'
assert_not_contains "${default_manifest}" 'filebelt-controller'
assert_not_contains "${default_manifest}" 'filebelt-mcp-runner'
assert_not_contains "${default_manifest}" 'filebelt-revision'
assert_document_not_contains "${default_manifest}" Deployment filebelt-vfs 'name: filebelt-vfs'
assert_document_not_contains "${default_manifest}" Deployment filebelt-headscale-sync 'name: filebelt-headscale-sync'
assert_document_not_contains "${default_manifest}" StatefulSet filebelt-smb-gateway 'name: filebelt-smb-gateway'
assert_document_not_contains "${default_manifest}" StatefulSet filebelt-ftp-ftps-gateway 'name: filebelt-ftp-ftps-gateway'
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
assert_document_contains "${temporary}/render-documents.yaml" Deployment filebelt-document 'containerPort: 8089'
assert_document_contains "${temporary}/render-documents.yaml" Deployment filebelt-document 'containerPort: 8090'
assert_document_contains "${temporary}/render-documents.yaml" Deployment filebelt-document 'mountPath: /run/secrets/document-database-url'
assert_document_not_contains "${temporary}/render-documents.yaml" Deployment filebelt-document 'claimName:'
assert_document_contains "${temporary}/render-documents.yaml" Service filebelt-document 'targetPort: document-api'
assert_document_contains "${temporary}/render-documents.yaml" Service filebelt-document 'targetPort: document-adapter'
assert_document_contains "${temporary}/render-documents.yaml" NetworkPolicy filebelt-document-ingress 'filebelt-onlyoffice'
assert_document_contains "${temporary}/render-documents.yaml" NetworkPolicy filebelt-io-ingress 'filebelt-onlyoffice'
assert_document_contains "${temporary}/render-documents.yaml" NetworkPolicy filebelt-web-egress 'filebelt-onlyoffice'
assert_document_contains "${temporary}/render-documents.yaml" Deployment filebelt-web 'mountPath: /run/secrets/onlyoffice-edge-client-tls'
assert_document_contains "${temporary}/recovery-documents.yaml" Job filebelt-recovery-checkpoint-123e4567-e89 'mountPath: /run/secrets/document-storage-capability-public-keyset'
assert_contains "${temporary}/render-documents.yaml" 'origin = "https://filebelt-onlyoffice-adapter.filebelt-integrations.svc:8089"'
assert_contains "${temporary}/render-documents.yaml" 'server_name = "filebelt-onlyoffice-adapter.filebelt-integrations.svc"'
assert_contains "${temporary}/render-documents.yaml" 'launch_action = "https://filebelt-editor.example.invalid/onlyoffice/launch"'
assert_contains "${temporary}/render-documents.yaml" 'provider_origin = "https://documentserver.example.invalid"'
assert_contains "${temporary}/render-documents.yaml" 'spiffe://filebelt/api/document'
assert_contains "${temporary}/render-documents.yaml" 'spiffe://filebelt/onlyoffice-adapter/document'
assert_contains "${temporary}/render-documents-editor-override.yaml" 'server_names = ["filebelt.example.invalid", "editor.example.test"]'
assert_contains "${temporary}/render-documents-editor-override.yaml" 'hosts = ["editor.example.test"]'
assert_contains "${temporary}/render-documents-editor-override.yaml" "form-action 'self' https://editor.example.test"
assert_document_contains "${temporary}/render-revisions.yaml" Deployment filebelt-revision 'replicas: 1'
assert_document_contains "${temporary}/render-revisions.yaml" Deployment filebelt-revision 'containerPort: 8091'
assert_container_contains "${temporary}/render-revisions.yaml" Deployment filebelt-revision revision 'args: ["serve", "--config", "/etc/filebelt/filebelt.toml"]'
assert_document_contains "${temporary}/render-revisions.yaml" Deployment filebelt-revision 'mountPath: /run/secrets/revision-database-url'
assert_document_not_contains "${temporary}/render-revisions.yaml" Deployment filebelt-revision 'mountPath: /var/lib/filebelt/payloads'
assert_document_not_contains "${temporary}/render-revisions.yaml" Deployment filebelt-revision 'mountPath: /var/lib/filebelt/git'
assert_document_contains "${temporary}/render-revisions.yaml" Service filebelt-revision 'targetPort: revision'
assert_document_contains "${temporary}/render-revisions.yaml" NetworkPolicy filebelt-revision-ingress 'component: api'
assert_document_contains "${temporary}/render-revisions.yaml" NetworkPolicy filebelt-revision-egress 'app.kubernetes.io/name: filebelt-git'
assert_document_contains "${temporary}/render-revisions.yaml" NetworkPolicy filebelt-revision-egress 'kubernetes.io/metadata.name: filebelt-git'
assert_document_contains "${temporary}/render-revisions.yaml" NetworkPolicy filebelt-api-egress 'component: revision-coordinator'
assert_document_contains "${temporary}/render-revisions.yaml" NetworkPolicy filebelt-io-ingress 'component: revision-coordinator'
assert_document_contains "${temporary}/render-revisions.yaml" Deployment filebelt-api 'mountPath: /run/secrets/revision-client-tls'
assert_document_contains "${temporary}/render-revisions.yaml" Deployment filebelt-io 'mountPath: /run/secrets/revision-storage-capability-public-keyset'
assert_contains "${temporary}/render-revisions.yaml" 'adapter_url = "https://filebelt-git.filebelt-git.svc:8092"'
assert_contains "${temporary}/render-revisions.yaml" '[revisions.limits]'
assert_contains "${temporary}/render-revisions.yaml" 'global_comparisons = 2'
assert_contains "${temporary}/render-revisions.yaml" 'per_user_comparisons = 1'
assert_contains "${temporary}/render-revisions.yaml" 'allowed_client_uri_sans = ["spiffe://filebelt/api/revision"]'
assert_contains "${temporary}/render-revisions.yaml" 'spiffe://filebelt/revision-coordinator/io'
python3 - "${temporary}/render-documents.yaml" <<'PY'
import sys
import tomllib


def oxibelt_config(manifest_path: str) -> dict:
    for document in open(manifest_path, encoding="utf-8").read().split("\n---\n"):
        lines = document.splitlines()
        if "kind: ConfigMap" not in lines or "  oxibelt.toml: |" not in lines:
            continue
        start = lines.index("  oxibelt.toml: |") + 1
        rendered = []
        for line in lines[start:]:
            if line.startswith("    "):
                rendered.append(line[4:])
            elif not line:
                rendered.append("")
            else:
                break
        return tomllib.loads("\n".join(rendered))
    raise AssertionError("missing rendered OxiBelt configuration")


config = oxibelt_config(sys.argv[1])
assert config["tls"]["server_names"] == [
    "filebelt.example.invalid",
    "filebelt-editor.example.invalid",
]
routes = {route["name"]: route for route in config["routes"]}
identity_headers = {
    "x-user", "x-group", "x-groups", "x-principal", "x-tenant",
    "x-filebelt-principal", "x-filebelt-tenant", "x-auth-request-user",
    "x-auth-request-groups", "x-remote-user", "x-remote-groups",
}
editor_routes = {
    "filebelt-onlyoffice-editor-launch": ("/onlyoffice/launch", "POST"),
    "filebelt-onlyoffice-editor-launcher": ("/onlyoffice/launcher.js", "GET"),
}
provider_routes = {
    "filebelt-onlyoffice-input": ("/onlyoffice/input/", "GET"),
    "filebelt-onlyoffice-callback": ("/onlyoffice/callback/", "POST"),
    "filebelt-onlyoffice-source": ("/onlyoffice/source", "GET"),
    "filebelt-onlyoffice-about": ("/onlyoffice/about", "GET"),
}
assert "filebelt-onlyoffice" not in routes
for name, (path, method) in editor_routes.items():
    route = routes[name]
    assert route["hosts"] == ["filebelt-editor.example.invalid"]
    assert route["path_prefix"] == path
    assert route["match"]["methods"] == [method]
    removed = set(route["actions"]["request_headers"]["remove"])
    assert {"authorization", "cookie", "x-filebelt-csrf"} | identity_headers <= removed
    csp = next(
        item["value"]
        for item in route["actions"]["response_headers"]["set"]
        if item["name"] == "Content-Security-Policy"
    )
    assert "frame-ancestors 'none'" in csp
    assert next(part.strip() for part in csp.split(";") if part.strip().startswith("sandbox ")) == (
        "sandbox allow-scripts allow-same-origin allow-forms allow-downloads allow-popups"
    )
    assert "filebelt.example.invalid" not in csp
    assert "https://documentserver.example.invalid" in csp
for name, (path, method) in provider_routes.items():
    route = routes[name]
    assert route["hosts"] == ["filebelt.example.invalid"]
    assert route["path_prefix"] == path
    assert route["match"]["methods"] == [method]
    removed = set(route["actions"]["request_headers"]["remove"])
    assert {"cookie", "x-filebelt-csrf"} | identity_headers <= removed
    assert "authorization" not in removed
assert not any(
    route["hosts"] == ["filebelt.example.invalid"]
    and route["path_prefix"] == "/onlyoffice/launch"
    for route in config["routes"]
)
spa_csp = next(
    item["value"]
    for item in routes["filebelt-spa"]["actions"]["response_headers"]["set"]
    if item["name"] == "Content-Security-Policy"
)
assert "form-action 'self' https://filebelt-editor.example.invalid" in spa_csp
PY
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
  --set collaboration.enabled=true \
  >"${temporary}/collaboration.yaml"
helm template phase5-recovery "${chart}" --kube-version 1.36.0 \
  --set deployment.quiesced=true \
  --set collaboration.enabled=true \
  --set-string operation.type=recovery-checkpoint \
  --set-string operation.operationId="${OPERATION_ID}" \
  >"${temporary}/recovery-collaboration.yaml"
assert_rendered_toml "${temporary}/collaboration.yaml" filebelt.toml
assert_rendered_toml "${temporary}/collaboration.yaml" oxibelt.toml
assert_count "${temporary}/collaboration.yaml" '^kind: Deployment$' 5
assert_count "${temporary}/collaboration.yaml" '^kind: PodDisruptionBudget$' 4
assert_count "${temporary}/collaboration.yaml" '^kind: NetworkPolicy$' 11
assert_document_contains "${temporary}/collaboration.yaml" Deployment filebelt-collaboration 'replicas: 2'
assert_document_contains "${temporary}/collaboration.yaml" Deployment filebelt-collaboration 'automountServiceAccountToken: false'
assert_document_not_contains "${temporary}/collaboration.yaml" Deployment filebelt-collaboration 'claimName:'
assert_document_contains "${temporary}/collaboration.yaml" Deployment filebelt-collaboration 'mountPath: /run/secrets/collaboration-storage-capability-public-keyset'
assert_document_contains "${temporary}/collaboration.yaml" Deployment filebelt-collaboration 'mountPath: /run/secrets/api-storage-capability-public-keyset'
assert_document_contains "${temporary}/collaboration.yaml" Deployment filebelt-collaboration 'mountPath: /run/secrets/api-collaboration-grant-capability-public-keyset'
assert_document_contains "${temporary}/recovery-collaboration.yaml" Job filebelt-recovery-checkpoint-123e4567-e89 'mountPath: /run/secrets/api-collaboration-grant-capability-public-keyset'
assert_document_contains "${temporary}/recovery-collaboration.yaml" Job filebelt-recovery-checkpoint-123e4567-e89 'mountPath: /run/secrets/collaboration-storage-capability-public-keyset'
assert_document_contains "${temporary}/collaboration.yaml" Service filebelt-collaboration 'port: 8085'
assert_document_contains "${temporary}/collaboration.yaml" NetworkPolicy filebelt-collaboration-ingress 'port: collaboration-ws'
assert_document_contains "${temporary}/collaboration.yaml" NetworkPolicy filebelt-collaboration-egress 'port: io'
assert_contains "${temporary}/collaboration.yaml" 'path_prefix = "/collaboration/v1/ws"'
assert_contains "${temporary}/collaboration.yaml" 'protocols = ["websocket"]'
assert_not_contains "${temporary}/collaboration.yaml" 'path_prefix = "/collaboration/v1/wt"'
assert_not_contains "${temporary}/collaboration.yaml" 'host_key_file = "/run/secrets/collaboration-quic-host-key/quic-host-key.b64"'

helm template phase8 "${chart}" --kube-version 1.36.0 \
  --set collaboration.enabled=true \
  --set collaboration.webtransport.enabled=true >"${temporary}/collaboration-webtransport.yaml"
assert_rendered_toml "${temporary}/collaboration-webtransport.yaml" filebelt.toml
assert_rendered_toml "${temporary}/collaboration-webtransport.yaml" oxibelt.toml
assert_document_contains "${temporary}/collaboration-webtransport.yaml" Deployment filebelt-web 'containerPort: 8443'
assert_document_contains "${temporary}/collaboration-webtransport.yaml" Deployment filebelt-collaboration 'containerPort: 8086'
assert_document_contains "${temporary}/collaboration-webtransport.yaml" Service filebelt-web 'protocol: UDP'
assert_document_contains "${temporary}/collaboration-webtransport.yaml" Service filebelt-collaboration 'protocol: UDP'
assert_contains "${temporary}/collaboration-webtransport.yaml" 'path_prefix = "/collaboration/v1/wt"'
assert_contains "${temporary}/collaboration-webtransport.yaml" 'max_http_version = "h3"'
assert_contains "${temporary}/collaboration-webtransport.yaml" 'webtransport = true'
assert_contains "${temporary}/collaboration-webtransport.yaml" 'webtransport_enabled = true'
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
  --set-string operation.type=security-descendant-shares-status \
  --set-string operation.operationId="${OPERATION_ID}" \
  >"${temporary}/security-descendant-shares-status.yaml"
assert_document_contains "${temporary}/security-descendant-shares-status.yaml" Job filebelt-security-descendant-shares-status-123e4567-e89 'security'
assert_document_contains "${temporary}/security-descendant-shares-status.yaml" Job filebelt-security-descendant-shares-status-123e4567-e89 'descendant-shares'
assert_document_contains "${temporary}/security-descendant-shares-status.yaml" Job filebelt-security-descendant-shares-status-123e4567-e89 'status'
assert_document_contains "${temporary}/security-descendant-shares-status.yaml" Job filebelt-security-descendant-shares-status-123e4567-e89 'secretName: filebelt-recovery-database'
assert_document_not_contains "${temporary}/security-descendant-shares-status.yaml" Job filebelt-security-descendant-shares-status-123e4567-e89 'claimName:'
assert_document_not_contains "${temporary}/security-descendant-shares-status.yaml" Job filebelt-security-descendant-shares-status-123e4567-e89 'automountServiceAccountToken: true'

for security_operation in repair verify activate; do
  helm template phase4 "${chart}" --kube-version 1.36.0 \
    --set-string operation.type="security-descendant-shares-${security_operation}" \
    --set-string operation.operationId="${OPERATION_ID}" \
    --set-string operation.tenantSlugConfirmation=development \
    --set-string operation.actorPrincipalId=123e4567-e89b-42d3-a456-426614174001 \
    >"${temporary}/security-descendant-shares-${security_operation}.yaml"
  assert_document_contains "${temporary}/security-descendant-shares-${security_operation}.yaml" Job "filebelt-security-descendant-shares-${security_operation}-123e4567-e89" "${security_operation}"
  assert_document_contains "${temporary}/security-descendant-shares-${security_operation}.yaml" Job "filebelt-security-descendant-shares-${security_operation}-123e4567-e89" '--confirm-tenant'
  assert_document_contains "${temporary}/security-descendant-shares-${security_operation}.yaml" Job "filebelt-security-descendant-shares-${security_operation}-123e4567-e89" '--actor-principal-id'
  assert_document_contains "${temporary}/security-descendant-shares-${security_operation}.yaml" Job "filebelt-security-descendant-shares-${security_operation}-123e4567-e89" 'secretName: filebelt-recovery-database'
  assert_document_not_contains "${temporary}/security-descendant-shares-${security_operation}.yaml" Job "filebelt-security-descendant-shares-${security_operation}-123e4567-e89" 'claimName:'
done

helm template phase4 "${chart}" --kube-version 1.36.0 \
  --set deployment.quiesced=true \
  --set-string operation.type=recovery-checkpoint \
  --set-string operation.operationId="${OPERATION_ID}" \
  >"${temporary}/recovery.yaml"
assert_document_not_contains "${temporary}/recovery.yaml" Job filebelt-recovery-checkpoint-123e4567-e89 'claimName:'
assert_document_contains "${temporary}/recovery.yaml" Job filebelt-recovery-checkpoint-123e4567-e89 'mountPath: /run/secrets/api-storage-capability-public-keyset'
assert_document_contains "${temporary}/recovery.yaml" Job filebelt-recovery-checkpoint-123e4567-e89 'mountPath: /run/secrets/media-storage-capability-public-keyset'
assert_document_not_contains "${temporary}/recovery.yaml" Job filebelt-recovery-checkpoint-123e4567-e89 'mountPath: /run/secrets/api-collaboration-grant-capability-public-keyset'
assert_document_not_contains "${temporary}/recovery.yaml" Job filebelt-recovery-checkpoint-123e4567-e89 'mountPath: /run/secrets/collaboration-storage-capability-public-keyset'
assert_document_not_contains "${temporary}/recovery.yaml" Job filebelt-recovery-checkpoint-123e4567-e89 'mountPath: /run/secrets/api-mcp-delegation-capability-public-keyset'
assert_document_not_contains "${temporary}/recovery.yaml" Job filebelt-recovery-checkpoint-123e4567-e89 'mountPath: /run/secrets/document-storage-capability-public-keyset'
assert_document_not_contains "${temporary}/recovery.yaml" Job filebelt-recovery-checkpoint-123e4567-e89 'mountPath: /run/secrets/mount-storage-capability-public-keyset'

helm template phase4 "${chart}" --kube-version 1.36.0 \
  --set deployment.quiesced=true \
  --set-string operation.type=keys-audit \
  --set-string operation.operationId="${OPERATION_ID}" \
  >"${temporary}/keys-audit.yaml"
assert_document_not_contains "${temporary}/keys-audit.yaml" Job filebelt-keys-audit-123e4567-e89 'name: database'
assert_document_contains "${temporary}/keys-audit.yaml" Job filebelt-keys-audit-123e4567-e89 'mountPath: /run/secrets/api-storage-capability-public-keyset'
assert_document_contains "${temporary}/keys-audit.yaml" Job filebelt-keys-audit-123e4567-e89 'mountPath: /run/secrets/media-storage-capability-public-keyset'
assert_document_not_contains "${temporary}/keys-audit.yaml" Job filebelt-keys-audit-123e4567-e89 'capability-private-key'
assert_document_contains "${temporary}/keys-audit.yaml" NetworkPolicy filebelt-operation-egress 'egress: []'

helm template phase4 "${chart}" --kube-version 1.36.0 \
  --set deployment.quiesced=true \
  --set-string operation.type=recovery-verify \
  --set-string operation.operationId="${OPERATION_ID}" \
  --set-string operation.checkpoint.secretName=filebelt-checkpoint-ci \
  >"${temporary}/recovery-verify.yaml"
assert_document_contains "${temporary}/recovery-verify.yaml" Job filebelt-recovery-verify-123e4567-e89 'secretName: filebelt-checkpoint-ci'
assert_document_contains "${temporary}/recovery-verify.yaml" Job filebelt-recovery-verify-123e4567-e89 'items: [{key: checkpoint.json, path: checkpoint.json}]'
assert_document_not_contains "${temporary}/recovery-verify.yaml" Job filebelt-recovery-verify-123e4567-e89 'claimName:'
assert_document_contains "${temporary}/recovery-verify.yaml" Job filebelt-recovery-verify-123e4567-e89 'mountPath: /run/secrets/api-storage-capability-public-keyset'
assert_document_contains "${temporary}/recovery-verify.yaml" Job filebelt-recovery-verify-123e4567-e89 'mountPath: /run/secrets/media-storage-capability-public-keyset'

helm template phase4 "${chart}" --kube-version 1.36.0 \
  --api-versions monitoring.coreos.com/v1/ServiceMonitor \
  --api-versions monitoring.coreos.com/v1/PrometheusRule \
  --set monitoring.serviceMonitor.enabled=true \
  --set monitoring.prometheusRule.enabled=true \
  >"${temporary}/monitoring.yaml"
assert_count "${temporary}/monitoring.yaml" '^kind: ServiceMonitor$' 1
assert_count "${temporary}/monitoring.yaml" '^kind: PrometheusRule$' 1
assert_not_contains "${temporary}/monitoring.yaml" 'FileBeltRevisionComparisonAdmissionSustained'
helm template phase9 "${chart}" --kube-version 1.36.0 \
  --api-versions monitoring.coreos.com/v1/PrometheusRule \
  --set monitoring.prometheusRule.enabled=true \
  --set revisions.enabled=true \
  --set-string revisions.activation.compatibilityGate=release-a-v9 \
  >"${temporary}/monitoring-revisions.yaml"
assert_contains "${temporary}/monitoring-revisions.yaml" 'FileBeltRevisionComparisonAdmissionSustained'
assert_contains "${temporary}/monitoring-revisions.yaml" 'filebelt_revision_comparison_admission_rejections_total[10m]'

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
helm template phase4-recovery "${chart}" --kube-version 1.36.0 \
  --set deployment.quiesced=true \
  --set mcp.enabled=true \
  --set mcp.runners.enabled=true \
  --set networkPolicy.mcpGateway.enabled=true \
  --set networkPolicy.kubernetesApi.enabled=true \
  --set-json 'networkPolicy.kubernetesApi.to=[{"ipBlock":{"cidr":"10.96.0.1/32"}}]' \
  --set-string operation.type=recovery-checkpoint \
  --set-string operation.operationId="${OPERATION_ID}" \
  --set-file configuration.filebelt="${temporary}/filebelt-mcp.toml" \
  >"${temporary}/recovery-mcp.yaml"
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
assert_document_contains "${temporary}/mcp.yaml" Deployment filebelt-mcp-broker 'mountPath: /run/secrets/api-mcp-delegation-capability-public-keyset'
assert_document_contains "${temporary}/recovery-mcp.yaml" Job filebelt-recovery-checkpoint-123e4567-e89 'mountPath: /run/secrets/api-mcp-delegation-capability-public-keyset'
assert_document_not_contains "${default_manifest}" Deployment filebelt-api 'checksum/mcp-client-tls:'
assert_not_contains "${temporary}/mcp.yaml" 'kind: ClusterRole'
assert_not_contains "${temporary}/mcp.yaml" 'hostPath:'

helm template phase4-private-egress "${chart}" --kube-version 1.36.0 \
  --set mcp.enabled=true \
  --set mcp.runners.enabled=true \
  --set mcp.privateEgress.enabled=true \
  --set networkPolicy.mcpGateway.enabled=true \
  --set networkPolicy.mcpPrivateEgress.enabled=true \
  --set networkPolicy.kubernetesApi.enabled=true \
  --set-json 'networkPolicy.kubernetesApi.to=[{"ipBlock":{"cidr":"10.96.0.1/32"}}]' \
  --set-file configuration.filebelt="${temporary}/filebelt-mcp.toml" \
  >"${temporary}/mcp-private-egress.yaml"
assert_rendered_toml "${temporary}/mcp-private-egress.yaml" filebelt.toml
assert_contains "${temporary}/mcp-private-egress.yaml" '[mcp.gateways.private-llm]'
assert_document_contains "${temporary}/mcp-private-egress.yaml" Deployment filebelt-mcp-broker 'mountPath: /run/secrets/mcp-private-egress-tls'
assert_document_contains "${temporary}/mcp-private-egress.yaml" NetworkPolicy filebelt-mcp-broker-egress 'filebelt.dev/private-egress-role: mcp'

# MCP remains independently operable: its API delegation purpose does not
# depend on collaboration being enabled or on collaboration Secret projections.
helm template phase4 "${chart}" --kube-version 1.36.0 \
  --set mcp.enabled=true \
  --set mcp.runners.enabled=true \
  --set collaboration.enabled=false \
  --set networkPolicy.mcpGateway.enabled=true \
  --set networkPolicy.kubernetesApi.enabled=true \
  --set-json 'networkPolicy.kubernetesApi.to=[{"ipBlock":{"cidr":"10.96.0.1/32"}}]' \
  --set-file configuration.filebelt="${temporary}/filebelt-mcp.toml" \
  >"${temporary}/mcp-without-collaboration.yaml"
assert_rendered_toml "${temporary}/mcp-without-collaboration.yaml" filebelt.toml
assert_contains "${temporary}/mcp-without-collaboration.yaml" '[keys.api_mcp_delegation]'
assert_not_contains "${temporary}/mcp-without-collaboration.yaml" '[keys.api_collaboration_grant]'
assert_document_contains "${temporary}/mcp-without-collaboration.yaml" Deployment filebelt-api 'mountPath: /run/secrets/api-mcp-delegation-capability-private-key'
assert_document_contains "${temporary}/mcp-without-collaboration.yaml" Deployment filebelt-mcp-broker 'mountPath: /run/secrets/api-mcp-delegation-capability-public-keyset'

helm template phase6 "${chart}" --kube-version 1.36.0 \
  --set mounts.smb.enabled=true \
  --set mounts.ftpFtps.enabled=true \
  --set-json 'networkPolicy.headscale.to=[{"ipBlock":{"cidr":"192.0.2.10/32"}}]' \
  --set-json 'networkPolicy.mountIngress.from=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"tailnet"}}}]' \
  >"${temporary}/mounts.yaml"
helm template phase6-recovery "${chart}" --kube-version 1.36.0 \
  --set deployment.quiesced=true \
  --set mounts.smb.enabled=true \
  --set mounts.ftpFtps.enabled=true \
  --set-json 'networkPolicy.headscale.to=[{"ipBlock":{"cidr":"192.0.2.10/32"}}]' \
  --set-json 'networkPolicy.mountIngress.from=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"tailnet"}}}]' \
  --set-string operation.type=recovery-checkpoint \
  --set-string operation.operationId="${OPERATION_ID}" \
  >"${temporary}/recovery-mounts.yaml"
assert_rendered_toml "${temporary}/mounts.yaml" filebelt.toml
assert_rendered_toml "${temporary}/recovery-mounts.yaml" filebelt.toml
assert_count "${temporary}/mounts.yaml" '^kind: Deployment$' 6
assert_count "${temporary}/mounts.yaml" '^kind: StatefulSet$' 2
assert_count "${temporary}/mounts.yaml" '^kind: PodDisruptionBudget$' 6
assert_count "${temporary}/mounts.yaml" '^kind: NetworkPolicy$' 16
assert_document_contains "${temporary}/mounts.yaml" Deployment filebelt-vfs 'image: ghcr.io/oxibelt/filebelt-vfs@sha256:'
assert_document_not_contains "${temporary}/mounts.yaml" Deployment filebelt-vfs 'name: tailscaled'
assert_document_not_contains "${temporary}/mounts.yaml" Deployment filebelt-vfs 'claimName:'
assert_document_contains "${temporary}/mounts.yaml" Deployment filebelt-vfs 'mountPath: /run/secrets/mount-database-url'
assert_document_contains "${temporary}/mounts.yaml" Deployment filebelt-vfs 'mountPath: /run/secrets/vfs-server-tls'
assert_document_contains "${temporary}/mounts.yaml" Deployment filebelt-vfs 'mountPath: /run/secrets/mount-storage-capability-public-keyset'
assert_document_contains "${temporary}/recovery-mounts.yaml" Job filebelt-recovery-checkpoint-123e4567-e89 'mountPath: /run/secrets/mount-storage-capability-public-keyset'
assert_document_not_contains "${temporary}/mounts.yaml" Deployment filebelt-headscale-sync 'name: tailscaled'
assert_document_not_contains "${temporary}/mounts.yaml" Deployment filebelt-headscale-sync 'claimName:'
assert_document_contains "${temporary}/mounts.yaml" Deployment filebelt-headscale-sync 'mountPath: /run/secrets/headscale-api-token'
assert_document_contains "${temporary}/mounts.yaml" StatefulSet filebelt-smb-gateway 'replicas: 1'
assert_document_contains "${temporary}/mounts.yaml" StatefulSet filebelt-smb-gateway 'filebelt.dev/adapter-license: "GPL-3.0-or-later"'
assert_document_contains "${temporary}/mounts.yaml" StatefulSet filebelt-smb-gateway 'claimName: filebelt-smb-tailstate'
assert_document_contains "${temporary}/mounts.yaml" PodDisruptionBudget filebelt-smb-gateway 'minAvailable: 1'
assert_document_contains "${temporary}/mounts.yaml" StatefulSet filebelt-ftp-ftps-gateway 'claimName: filebelt-ftp-ftps-tailstate'
assert_document_contains "${temporary}/mounts.yaml" Service filebelt-ftp-ftps-gateway 'port: 30000'
assert_document_contains "${temporary}/mounts.yaml" Service filebelt-ftp-ftps-gateway 'port: 30001'
assert_document_contains "${temporary}/mounts.yaml" NetworkPolicy filebelt-smb-gateway-ingress 'port: smb'
assert_document_contains "${temporary}/mounts.yaml" NetworkPolicy filebelt-ftp-ftps-gateway-ingress 'port: passive-0'
assert_document_not_contains "${temporary}/mounts.yaml" NetworkPolicy filebelt-vfs-egress 'port: 443'
assert_document_contains "${temporary}/mounts.yaml" NetworkPolicy filebelt-vfs-egress 'port: io'
assert_document_contains "${temporary}/mounts.yaml" NetworkPolicy filebelt-io-ingress 'app.kubernetes.io/component: vfs'
assert_document_contains "${temporary}/mounts.yaml" NetworkPolicy filebelt-vfs-ingress 'port: management'
assert_document_contains "${temporary}/mounts.yaml" StatefulSet filebelt-smb-gateway 'hostPath: {path: /dev/net/tun, type: CharDevice}'
assert_document_contains "${temporary}/mounts.yaml" StatefulSet filebelt-ftp-ftps-gateway 'add: ["NET_ADMIN"]'
assert_not_contains "${temporary}/mounts.yaml" 'TS_USERSPACE'

nfs_values=(
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
  --set-json 'networkPolicy.mountIngress.from=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"tailnet"}}}]'
)
helm template phase8-nfs "${chart}" --kube-version 1.36.0 \
  "${nfs_values[@]}" >"${temporary}/nfs.yaml"
assert_rendered_toml "${temporary}/nfs.yaml" filebelt.toml
assert_count "${temporary}/nfs.yaml" '^kind: Deployment$' 5
assert_count "${temporary}/nfs.yaml" '^kind: StatefulSet$' 2
assert_count "${temporary}/nfs.yaml" '^kind: PodDisruptionBudget$' 6
assert_count "${temporary}/nfs.yaml" '^kind: NetworkPolicy$' 15
assert_count "${temporary}/nfs.yaml" '^          image: ghcr.io/oxibelt/filebelt-nfs-gateway@sha256:1111111111111111111111111111111111111111111111111111111111111111$' 2
assert_document_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway 'replicas: 1'
assert_document_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway 'filebelt.dev/gateway-uri-san: "spiffe://filebelt/nfs-gateway/vfs"'
assert_document_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway 'supplementalGroups: [10001, 10003]'
assert_document_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway 'claimName: filebelt-nfs-recovery'
assert_document_not_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway 'claimName: filebelt-nfs-tailstate'
assert_document_not_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway 'name: tailscaled'
assert_document_not_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway 'hostPath: {path: /dev/net/tun, type: CharDevice}'
assert_document_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway 'filebelt.dev/nfs-zone: backend'
assert_document_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway 'hostnames: ["filebelt-vfs.default.svc"]'
assert_document_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway 'KRB5_KTNAME'
assert_document_not_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway 'nfs-handle-keyring'
assert_container_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway ganesha 'name: ganesha-keytab'
assert_container_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway ganesha 'name: recovery'
assert_container_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway ganesha '/contract/ganesha-drain'
assert_container_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway ganesha 'drop: ["ALL"]'
assert_container_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway ganesha 'runAsUser: 10002'
assert_container_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway ganesha 'runAsGroup: 10002'
assert_container_not_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway ganesha 'add: ["NET_BIND_SERVICE"]'
assert_container_not_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway ganesha 'bridge-vfs-client-tls'
assert_container_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway bridge 'name: bridge-vfs-client-tls'
assert_container_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway bridge 'FILEBELT_NFS_EXPECTED_VFS_HOSTNAME'
assert_container_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway bridge '/contract/bridge-drain'
assert_container_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway bridge 'drop: ["ALL"]'
assert_container_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway bridge 'runAsUser: 10001'
assert_container_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway bridge 'runAsGroup: 10001'
assert_container_not_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway bridge 'ganesha-keytab'
assert_container_not_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-gateway bridge 'name: recovery'
assert_document_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-relay 'filebelt.dev/nfs-zone: relay'
assert_document_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-relay 'claimName: filebelt-nfs-tailstate'
assert_document_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-relay 'hostPath: {path: /dev/net/tun, type: CharDevice}'
assert_container_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-relay relay 'ghcr.io/oxibelt/filebelt-nfs-relay@sha256:3333333333333333333333333333333333333333333333333333333333333333'
assert_container_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-relay relay '10.96.20.11:2049'
assert_container_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-relay relay '0.0.0.0:9090'
assert_container_not_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-relay relay 'TS_AUTHKEY'
assert_container_not_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-relay relay 'claimName:'
assert_container_not_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-relay relay '/dev/net/tun'
assert_container_not_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-relay relay 'ganesha-keytab'
assert_container_not_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-relay relay 'bridge-vfs-client-tls'
assert_container_not_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-relay tailscaled 'bridge-vfs-client-tls'
assert_container_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-relay tailscaled 'TS_HOSTNAME'
assert_container_contains "${temporary}/nfs.yaml" StatefulSet filebelt-nfs-relay tailscaled 'filebelt-nfs-gateway-0'
assert_document_contains "${temporary}/nfs.yaml" Deployment filebelt-vfs 'mountPath: /run/secrets/nfs-handle-keyring.json'
assert_document_not_contains "${temporary}/nfs.yaml" Deployment filebelt-headscale-sync 'name: filebelt-headscale-sync'
assert_document_not_contains "${temporary}/nfs.yaml" StatefulSet filebelt-smb-gateway 'name: filebelt-smb-gateway'
assert_document_not_contains "${temporary}/nfs.yaml" StatefulSet filebelt-ftp-ftps-gateway 'name: filebelt-ftp-ftps-gateway'
assert_document_contains "${temporary}/nfs.yaml" Service filebelt-nfs-gateway 'type: ClusterIP'
assert_document_contains "${temporary}/nfs.yaml" Service filebelt-nfs-gateway 'port: 2049'
assert_document_not_contains "${temporary}/nfs.yaml" Service filebelt-nfs-gateway 'clusterIP: None'
assert_document_contains "${temporary}/nfs.yaml" Service filebelt-nfs-gateway 'filebelt.dev/nfs-zone: relay'
assert_document_contains "${temporary}/nfs.yaml" Service filebelt-nfs-backend 'clusterIP: "10.96.20.11"'
assert_document_contains "${temporary}/nfs.yaml" Service filebelt-nfs-backend 'filebelt.dev/nfs-zone: backend'
assert_document_contains "${temporary}/nfs.yaml" Service filebelt-vfs 'clusterIP: "10.96.20.10"'
assert_document_contains "${temporary}/nfs.yaml" NetworkPolicy filebelt-nfs-gateway-ingress 'port: nfs'
assert_document_contains "${temporary}/nfs.yaml" NetworkPolicy filebelt-nfs-gateway-ingress 'filebelt.dev/nfs-zone: relay'
assert_document_contains "${temporary}/nfs.yaml" NetworkPolicy filebelt-nfs-gateway-egress 'app.kubernetes.io/component: vfs'
assert_document_not_contains "${temporary}/nfs.yaml" NetworkPolicy filebelt-nfs-gateway-egress 'port: 443'
assert_document_not_contains "${temporary}/nfs.yaml" NetworkPolicy filebelt-nfs-gateway-egress 'port: 53'
assert_document_not_contains "${temporary}/nfs.yaml" NetworkPolicy filebelt-nfs-gateway-egress 'port: 88'
assert_document_not_contains "${temporary}/nfs.yaml" NetworkPolicy filebelt-nfs-gateway-egress 'port: 464'
assert_document_contains "${temporary}/nfs.yaml" NetworkPolicy filebelt-nfs-relay-ingress 'kubernetes.io/metadata.name: tailnet'
assert_document_contains "${temporary}/nfs.yaml" NetworkPolicy filebelt-nfs-relay-egress 'port: 443'
assert_document_contains "${temporary}/nfs.yaml" NetworkPolicy filebelt-nfs-relay-egress 'port: 53'
assert_document_contains "${temporary}/nfs.yaml" NetworkPolicy filebelt-nfs-relay-egress 'filebelt.dev/nfs-zone: backend'
assert_document_not_contains "${temporary}/nfs.yaml" NetworkPolicy filebelt-nfs-relay-egress 'app.kubernetes.io/component: vfs'
assert_not_contains "${temporary}/nfs.yaml" 'kind: PersistentVolumeClaim'
python3 - "${temporary}/nfs.yaml" <<'PY'
import sys
import tomllib

for document in open(sys.argv[1], encoding="utf-8").read().split("\n---\n"):
    lines = document.splitlines()
    if "kind: ConfigMap" not in lines or "  filebelt.toml: |" not in lines:
        continue
    start = lines.index("  filebelt.toml: |") + 1
    rendered = []
    for line in lines[start:]:
        if line.startswith("    "):
            rendered.append(line[4:])
        elif not line:
            rendered.append("")
        else:
            break
    config = tomllib.loads("\n".join(rendered))
    assert config["version"] == 9
    nfs = config["mounts"]["nfs"]
    assert nfs["enabled"] is True
    assert nfs["realm"] == "EXAMPLE.TEST"
    assert nfs["idmap_domain"] == "example.test"
    assert nfs["handle_keyring_file"] == "/run/secrets/nfs-handle-keyring.json"
    assert nfs["handle_key_generation"] == 1
    assert nfs["grace_seconds"] == 90
    assert config["mounts"]["smb"]["enabled"] is False
    assert config["mounts"]["ftp_ftps"]["enabled"] is False
    assert config["mounts"]["headscale"]["enabled"] is False
    assert config["backend_tls"]["vfs"]["allowed_client_uri_sans"] == [
        "spiffe://filebelt/nfs-gateway/vfs"
    ]
    break
else:
    raise AssertionError("missing rendered FileBelt configuration")
PY

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

expect_failure documents_editor_public_host \
  --set documents.enabled=true \
  --set-string documents.launchAction=https://filebelt.example.invalid/onlyoffice/launch
expect_failure documents_editor_provider_host \
  --set documents.enabled=true \
  --set-string documents.providerOrigin=https://filebelt-editor.example.invalid
expect_failure documents_editor_port_alias \
  --set documents.enabled=true \
  --set-string documents.launchAction=https://filebelt.example.invalid:9443/onlyoffice/launch
expect_failure documents_editor_trailing_dot \
  --set documents.enabled=true \
  --set-string documents.launchAction=https://filebelt-editor.example.invalid./onlyoffice/launch
expect_failure documents_provider_trailing_dot \
  --set documents.enabled=true \
  --set-string documents.providerOrigin=https://documentserver.example.invalid.

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
expect_failure security_status_with_actor \
  --set-string operation.type=security-descendant-shares-status \
  --set-string operation.operationId="${OPERATION_ID}" \
  --set-string operation.actorPrincipalId=123e4567-e89b-42d3-a456-426614174001
expect_failure security_status_with_payload \
  --set-string operation.type=security-descendant-shares-status \
  --set-string operation.operationId="${OPERATION_ID}" \
  --set-string operation.payloadId=123e4567-e89b-42d3-a456-426614174001
expect_failure security_repair_without_confirmation \
  --set-string operation.type=security-descendant-shares-repair \
  --set-string operation.operationId="${OPERATION_ID}" \
  --set-string operation.actorPrincipalId=123e4567-e89b-42d3-a456-426614174001
expect_failure security_verify_without_actor \
  --set-string operation.type=security-descendant-shares-verify \
  --set-string operation.operationId="${OPERATION_ID}" \
  --set-string operation.tenantSlugConfirmation=development
expect_failure security_repair_with_checkpoint \
  --set-string operation.type=security-descendant-shares-repair \
  --set-string operation.operationId="${OPERATION_ID}" \
  --set-string operation.tenantSlugConfirmation=development \
  --set-string operation.actorPrincipalId=123e4567-e89b-42d3-a456-426614174001 \
  --set-string operation.checkpoint.secretName=unexpected
expect_failure security_activate_with_args \
  --set-string operation.type=security-descendant-shares-activate \
  --set-string operation.operationId="${OPERATION_ID}" \
  --set-string operation.tenantSlugConfirmation=development \
  --set-string operation.actorPrincipalId=123e4567-e89b-42d3-a456-426614174001 \
  --set-string 'operation.args[0]=--unexpected'
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
expect_failure mcp_private_egress_reuses_public_identity \
  --set mcp.enabled=true \
  --set mcp.runners.enabled=true \
  --set mcp.privateEgress.enabled=true \
  --set networkPolicy.mcpGateway.enabled=true \
  --set networkPolicy.mcpPrivateEgress.enabled=true \
  --set networkPolicy.kubernetesApi.enabled=true \
  --set-json 'networkPolicy.kubernetesApi.to=[{"ipBlock":{"cidr":"10.96.0.1/32"}}]' \
  --set-string secrets.mcpPrivateEgressClientTls.name=filebelt-mcp-gateway-client-tls \
  --set-file configuration.filebelt="${temporary}/filebelt-mcp.toml"
expect_failure legacy_mount_enabled --set mounts.enabled=true
expect_failure mounts_without_headscale --set mounts.smb.enabled=true
expect_failure disabled_smb_previous_identity \
  --set-string mounts.smb.previousGatewayUriSan=spiffe://filebelt/smb-gateway/vfs-previous
expect_failure disabled_nfs_authority --set-string mounts.nfs.realm=EXAMPLE.TEST
expect_failure nfs_without_runtime_contract --set mounts.nfs.enabled=true
expect_failure nfs_kdc_egress "${nfs_values[@]}" --set networkPolicy.headscale.port=88
expect_failure nfs_without_vfs_cluster_ip "${nfs_values[@]}" --set-string mounts.vfs.clusterIP=
expect_failure nfs_without_backend_cluster_ip "${nfs_values[@]}" --set-string mounts.nfs.backendClusterIP=
expect_failure nfs_with_shared_service_ip "${nfs_values[@]}" \
  --set-string mounts.nfs.backendClusterIP=10.96.20.10
expect_failure nfs_without_relay_image "${nfs_values[@]}" \
  --set-string images.filebelt-nfs-relay.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000
expect_failure nfs_relay_per_source_exceeds_total "${nfs_values[@]}" \
  --set mounts.nfs.relay.maxConnections=32
expect_failure nfs_relay_drain_exceeds_grace "${nfs_values[@]}" \
  --set mounts.nfs.terminationGracePeriodSeconds=180
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

echo "Helm chart contract through Phase 9 passed"
