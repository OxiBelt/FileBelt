#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
  echo "usage: run-kubernetes-release-gate.sh --image-dir DIR --unit core|collaboration|mcp [--diagnostics-dir DIR]" >&2
}

image_dir=
unit=
diagnostics_dir=
while (( $# > 0 )); do
  case "$1" in
    --image-dir) image_dir=${2:-}; shift 2 ;;
    --unit) unit=${2:-}; shift 2 ;;
    --diagnostics-dir) diagnostics_dir=${2:-}; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done

[[ -d ${image_dir} ]] || { usage; exit 2; }
case ${unit} in
  core|collaboration|mcp) ;;
  *) usage; exit 2 ;;
esac

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
command=(
  python3 "${repo_root}/tests/docker/units/run-unit.py"
  --unit "${unit}"
  --image-dir "${image_dir}"
  --image-channel release
)
if [[ -n ${diagnostics_dir} ]]; then
  command+=(--diagnostics-dir "${diagnostics_dir}")
fi

exec "${command[@]}"
