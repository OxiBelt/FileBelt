#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root=${1:-.}
repo_root=$(cd "${repo_root}" && pwd)
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

command -v gh >/dev/null
command -v jq >/dev/null
plan=$(python3 "${script_dir}/validate-oxibelt-admission.py" \
  --repo-root "${repo_root}" \
  --print-verification-invocations)
trusted_root=$(jq -er '.trustedRoot' <<<"${plan}")

while IFS= read -r invocation; do
  repository=$(jq -er '.repository' <<<"${invocation}")
  predicate_type=$(jq -er '.predicateType' <<<"${invocation}")
  oidc_issuer=$(jq -er '.oidcIssuer' <<<"${invocation}")
  source_revision=$(jq -er '.sourceDigest' <<<"${invocation}")
  source_ref=$(jq -er '.sourceRef' <<<"${invocation}")
  bundle=$(jq -er '.bundle' <<<"${invocation}")
  subject=$(jq -er '.subject' <<<"${invocation}")
  certificate_identity=$(jq -er '.certificateIdentity' <<<"${invocation}")
  gh attestation verify "${subject}" \
    --repo "${repository}" \
    --bundle "${bundle}" \
    --custom-trusted-root "${trusted_root}" \
    --cert-identity "${certificate_identity}" \
    --cert-oidc-issuer "${oidc_issuer}" \
    --predicate-type "${predicate_type}" \
    --source-digest "${source_revision}" \
    --source-ref "${source_ref}" \
    --deny-self-hosted-runners \
    --format json >/dev/null
done < <(jq -c '.invocations[]' <<<"${plan}")

printf '%s\n' 'OxiBelt retained attestations verified offline'
