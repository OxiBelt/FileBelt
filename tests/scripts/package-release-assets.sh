#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
  echo "usage: package-release-assets.sh --output-dir DIR" >&2
}

output_dir=
while (( $# > 0 )); do
  case "$1" in
    --output-dir) output_dir=${2:-}; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
[[ -n "${output_dir}" ]] || { usage; exit 2; }

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
for command in gzip helm jq mktemp python3 sha256sum tar; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "required command is unavailable: ${command}" >&2
    exit 1
  }
done

node_version=$(jq -er '.version' "${repo_root}/package.json")
cargo_version=$(python3 -c \
  'import pathlib,sys,tomllib; print(tomllib.loads(pathlib.Path(sys.argv[1]).read_text())["workspace"]["package"]["version"])' \
  "${repo_root}/Cargo.toml")
chart_version=$(awk '$1 == "version:" { print $2; exit }' "${repo_root}/deploy/helm/filebelt/Chart.yaml")
app_version=$(awk '$1 == "appVersion:" { gsub(/\"/, "", $2); print $2; exit }' "${repo_root}/deploy/helm/filebelt/Chart.yaml")
version=${cargo_version}
[[ "${node_version}" == "${version}" && "${chart_version}" == "${version}" && "${app_version}" == "${version}" ]] || {
  echo "core and chart versions must use coordinated SemVer" >&2
  exit 1
}
[[ "${version}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?$ ]] || {
  echo "release version is not valid SemVer: ${version}" >&2
  exit 1
}
mkdir -p "${output_dir}"
for artifact in \
  "filebelt-${version}.tgz" \
  "filebelt-postgresql-admin-${version}.tar.gz" \
  SHA256SUMS; do
  [[ ! -e "${output_dir}/${artifact}" ]] || {
    echo "refusing to replace release asset: ${output_dir}/${artifact}" >&2
    exit 1
  }
done

temporary=$(mktemp -d)
cleanup() { rm -rf -- "${temporary}"; }
trap cleanup EXIT
cp -R "${repo_root}/deploy/helm/filebelt" "${temporary}/filebelt"
cp "${repo_root}/LICENSE" "${temporary}/filebelt/LICENSE"
helm lint --strict "${temporary}/filebelt" \
  --kube-version 1.36.0 \
  -f "${repo_root}/tests/kubernetes/values-ci.yaml"
helm package "${temporary}/filebelt" \
  --destination "${output_dir}" \
  --version "${version}" \
  --app-version "${version}" >/dev/null

mkdir -p "${temporary}/filebelt-postgresql-admin-${version}"
for source in README.md roles.sql grants.sql; do
  cp "${repo_root}/source/migrations/postgres/${source}" \
    "${temporary}/filebelt-postgresql-admin-${version}/${source}"
done
cp "${repo_root}/LICENSE" \
  "${temporary}/filebelt-postgresql-admin-${version}/LICENSE"
epoch=$(git -C "${repo_root}" show -s --format=%ct HEAD)
tar --sort=name --mtime="@${epoch}" --owner=0 --group=0 --numeric-owner \
  -C "${temporary}" -cf "${output_dir}/filebelt-postgresql-admin-${version}.tar" \
  "filebelt-postgresql-admin-${version}"
gzip -n "${output_dir}/filebelt-postgresql-admin-${version}.tar"

(
  cd "${output_dir}"
  sha256sum "filebelt-${version}.tgz" \
    "filebelt-postgresql-admin-${version}.tar.gz" >SHA256SUMS
)
