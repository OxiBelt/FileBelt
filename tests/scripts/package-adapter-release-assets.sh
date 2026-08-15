#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
  echo "usage: package-adapter-release-assets.sh --plan JSON --role ROLE --image-digest SHA256 --source-sha256 SHA256 --output-dir DIR" >&2
}

plan=
role=
image_digest=
source_sha256=
output_dir=
while (( $# > 0 )); do
  case "$1" in
    --plan) plan=${2:-}; shift 2 ;;
    --role) role=${2:-}; shift 2 ;;
    --image-digest) image_digest=${2:-}; shift 2 ;;
    --source-sha256) source_sha256=${2:-}; shift 2 ;;
    --output-dir) output_dir=${2:-}; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
[[ -n "${plan}" && -n "${role}" && -n "${image_digest}" && -n "${source_sha256}" && -n "${output_dir}" ]] || { usage; exit 2; }
[[ "${image_digest}" =~ ^sha256:[0-9a-f]{64}$ && "${image_digest}" != "sha256:$(printf '0%.0s' {1..64})" ]] || { echo "image digest must be nonzero SHA-256" >&2; exit 1; }
[[ "${source_sha256}" =~ ^[0-9a-f]{64}$ && "${source_sha256}" != "$(printf '0%.0s' {1..64})" ]] || { echo "source digest must be nonzero SHA-256" >&2; exit 1; }

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
[[ -f "${repo_root}/devops/dist/cli.js" ]] || { echo "build @filebelt/devops before packaging adapter assets" >&2; exit 1; }
node "${repo_root}/devops/dist/cli.js" validate-adapter-image-plan --input "${plan}"
version=$(jq -er --arg role "${role}" '.roles[] | select(.role == $role and .publication.state == "eligible") | .version' "${plan}")
planned_source_sha=$(jq -er --arg role "${role}" '.roles[] | select(.role == $role) | .sourceBundle.sha256' "${plan}")
planned_source_url=$(jq -er --arg role "${role}" '.roles[] | select(.role == $role) | .sourceBundle.publicUrl' "${plan}")
[[ "${planned_source_sha}" == "${source_sha256}" ]] || { echo "source digest differs from adapter plan" >&2; exit 1; }
case "${role}" in
  filebelt-git-adapter) chart_name=filebelt-git; namespace=filebelt-git ;;
  filebelt-onlyoffice-adapter) chart_name=filebelt-onlyoffice; namespace=filebelt-integrations ;;
  *) echo "no reviewed Helm chart contract for ${role}" >&2; exit 1 ;;
esac

mkdir -p "${output_dir}"
artifact="${output_dir}/${chart_name}-${version}.tgz"
[[ ! -e "${artifact}" ]] || { echo "refusing to replace adapter chart: ${artifact}" >&2; exit 1; }
temporary=$(mktemp -d "${TMPDIR:-/tmp}/filebelt-adapter-chart.XXXXXX")
cleanup() { rm -rf -- "${temporary}"; }
trap cleanup EXIT HUP INT TERM
cp -R "${repo_root}/deploy/helm/${chart_name}" "${temporary}/${chart_name}"
sed -i \
  -e "s#digest: sha256:[0-9a-f]\{64\}#digest: ${image_digest}#" \
  -e "s#correspondingSourceSha256: [0-9a-f]\{64\}#correspondingSourceSha256: ${source_sha256}#" \
  -e 's#qualification: blocked#qualification: qualified#' \
  "${temporary}/${chart_name}/values.yaml"
sed -i \
  -e "s#https://github.com/OxiBelt/FileBelt/releases/download/[^/]*/${role}-source-[^/]*\.tar\.gz#${planned_source_url}#g" \
  "${temporary}/${chart_name}/values.yaml" \
  "${temporary}/${chart_name}/values.schema.json" \
  "${temporary}/${chart_name}/Chart.yaml"
sed -i 's#filebelt.dev/qualification: blocked#filebelt.dev/qualification: qualified#' \
  "${temporary}/${chart_name}/Chart.yaml"
grep -F -- "${planned_source_url}" "${temporary}/${chart_name}/values.yaml" >/dev/null
grep -F -- "${planned_source_url}" "${temporary}/${chart_name}/values.schema.json" >/dev/null
grep -F -- "${planned_source_url}" "${temporary}/${chart_name}/Chart.yaml" >/dev/null
helm lint --strict "${temporary}/${chart_name}" --kube-version 1.36.0 --namespace "${namespace}"
helm package "${temporary}/${chart_name}" --destination "${output_dir}" \
  --version "${version}" --app-version "${version}" >/dev/null
