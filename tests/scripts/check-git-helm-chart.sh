#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
readonly HELM_VERSION="v4.2.4"
repo_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
chart="${repo_root}/deploy/helm/filebelt-git"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/filebelt-git-helm.XXXXXX")"
trap 'rm -rf -- "${temporary}"' EXIT HUP INT TERM
command -v helm >/dev/null
[[ "$(helm version --template '{{ .Version }}')" == "${HELM_VERSION}" ]]
helm lint "${chart}" --strict --kube-version 1.36.0 --namespace filebelt-git >"${temporary}/lint.log"
helm template git "${chart}" --kube-version 1.36.0 --namespace filebelt-git >"${temporary}/rendered.yaml"
manifest="${temporary}/rendered.yaml"
for required in 'kind: StatefulSet' 'replicas: 1' 'containerPort: 8092' 'containerPort: 9090' 'claimName: filebelt-git-rwx' 'mountPath: /var/lib/filebelt/git' 'automountServiceAccountToken: false' 'readOnlyRootFilesystem: true' 'kind: NetworkPolicy' 'filebelt.dev/adapter-license: "GPL-2.0-only"' 'args: ["serve", "--config", "/etc/filebelt-git/adapter.toml", "--max-concurrent-private-requests", "8", "--max-concurrent-git-processes", "2"]'; do grep -F -- "${required}" "${manifest}" >/dev/null || { echo "missing ${required}" >&2; exit 1; }; done
for forbidden in 'kind: Namespace' 'kind: Secret' 'database' 'payload' 'name: operations, port:' 'to:'; do if grep -F -- "${forbidden}" "${manifest}" >/dev/null; then echo "unexpected ${forbidden}" >&2; exit 1; fi; done
grep -F -- 'egress: []' "${manifest}" >/dev/null || { echo "adapter must have no egress" >&2; exit 1; }
if helm template git "${chart}" --kube-version 1.36.0 --namespace filebelt-core >"${temporary}/wrong-namespace.log" 2>&1; then echo "chart rendered into core namespace" >&2; exit 1; fi
if helm template git "${chart}" --kube-version 1.36.0 --namespace filebelt-git --set limits.maxConcurrentPrivateRequests=0 >"${temporary}/zero-private-limit.log" 2>&1; then echo "chart admitted a zero private request limit" >&2; exit 1; fi
if helm template git "${chart}" --kube-version 1.36.0 --namespace filebelt-git --set limits.maxConcurrentPrivateRequests=65 >"${temporary}/large-private-limit.log" 2>&1; then echo "chart admitted an excessive private request limit" >&2; exit 1; fi
if helm template git "${chart}" --kube-version 1.36.0 --namespace filebelt-git --set limits.maxConcurrentGitProcesses=0 >"${temporary}/zero-git-limit.log" 2>&1; then echo "chart admitted a zero Git process limit" >&2; exit 1; fi
if helm template git "${chart}" --kube-version 1.36.0 --namespace filebelt-git --set limits.maxConcurrentGitProcesses=17 >"${temporary}/large-git-limit.log" 2>&1; then echo "chart admitted an excessive Git process limit" >&2; exit 1; fi
if helm template git "${chart}" --kube-version 1.36.0 --namespace filebelt-git --set limits.maxConcurrentPrivateRequests=1 --set limits.maxConcurrentGitProcesses=2 >"${temporary}/inverted-limits.log" 2>&1; then echo "chart admitted more Git processes than private requests" >&2; exit 1; fi
