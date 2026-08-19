#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root=${1:-.}
repo_root=$(cd "${repo_root}" && pwd)
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
record=${repo_root}/supply-chain/oxibelt-admission-v2.json

command -v gh >/dev/null
command -v jq >/dev/null
trusted_root=$(
  python3 "${script_dir}/validate-oxibelt-admission.py" \
    --repo-root "${repo_root}" \
    --print-trusted-root-path
)

repository=$(jq -er '.verification.repository' "${record}")
predicate_type=$(jq -er '.verification.predicateType' "${record}")
oidc_issuer=$(jq -er '.verification.oidcIssuer' "${record}")
source_revision=$(jq -er '.source.revision' "${record}")
source_ref=$(jq -er '.source.ref' "${record}")

for kind in index platform; do
  bundle=$(jq -er --arg kind "${kind}" '.bundles[] | select(.kind == $kind) | .path' "${record}")
  subject=$(jq -er --arg kind "${kind}" '.bundles[] | select(.kind == $kind) | .subjectPath' "${record}")
  certificate_identity=$(jq -er --arg kind "${kind}" '.bundles[] | select(.kind == $kind) | .certificateIdentity' "${record}")
  gh attestation verify "${repo_root}/${subject}" \
    --repo "${repository}" \
    --bundle "${repo_root}/${bundle}" \
    --custom-trusted-root "${trusted_root}" \
    --cert-identity "${certificate_identity}" \
    --cert-oidc-issuer "${oidc_issuer}" \
    --predicate-type "${predicate_type}" \
    --source-digest "${source_revision}" \
    --source-ref "${source_ref}" \
    --deny-self-hosted-runners \
    --format json >/dev/null
done

printf '%s\n' 'OxiBelt retained attestations verified offline'
