#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
readonly HELM_VERSION="v4.2.3"
repo_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
chart="${repo_root}/deploy/helm/filebelt-git"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/filebelt-git-helm.XXXXXX")"
trap 'rm -rf -- "${temporary}"' EXIT HUP INT TERM
command -v helm >/dev/null
[[ "$(helm version --template '{{ .Version }}')" == "${HELM_VERSION}" ]]
helm lint "${chart}" --strict --kube-version 1.36.0 --namespace filebelt-git >"${temporary}/lint.log"
helm template git "${chart}" --kube-version 1.36.0 --namespace filebelt-git >"${temporary}/rendered.yaml"
manifest="${temporary}/rendered.yaml"
for required in 'kind: StatefulSet' 'replicas: 1' 'containerPort: 8092' 'containerPort: 9090' 'claimName: filebelt-git-rwx' 'mountPath: /var/lib/filebelt/git' 'automountServiceAccountToken: false' 'readOnlyRootFilesystem: true' 'kind: NetworkPolicy' 'filebelt.dev/adapter-license: "GPL-2.0-only"'; do grep -F -- "${required}" "${manifest}" >/dev/null || { echo "missing ${required}" >&2; exit 1; }; done
for forbidden in 'kind: Namespace' 'kind: Secret' 'database' 'payload' 'name: operations, port:' 'to:'; do if grep -F -- "${forbidden}" "${manifest}" >/dev/null; then echo "unexpected ${forbidden}" >&2; exit 1; fi; done
grep -F -- 'egress: []' "${manifest}" >/dev/null || { echo "adapter must have no egress" >&2; exit 1; }
if helm template git "${chart}" --kube-version 1.36.0 --namespace filebelt-core >"${temporary}/wrong-namespace.log" 2>&1; then echo "chart rendered into core namespace" >&2; exit 1; fi
