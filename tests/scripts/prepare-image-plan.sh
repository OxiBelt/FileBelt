#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

usage() {
  echo "usage: prepare-image-plan.sh --channel <build|release> --output <json>" >&2
}

channel=
output=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --channel) channel=${2-}; shift 2 ;;
    --output) output=${2-}; shift 2 ;;
    --help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
if [ -z "${channel}" ] || [ -z "${output}" ]; then
  usage
  exit 2
fi
case "${channel}" in build|release) ;; *) usage; exit 2 ;; esac

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
if [ ! -f "${repo_root}/devops/dist/cli.js" ]; then
  echo "devops CLI is not built; run pnpm --filter @filebelt/devops build" >&2
  exit 1
fi

version=$(python3 -c 'import pathlib,sys,tomllib; print(tomllib.loads(pathlib.Path(sys.argv[1]).read_text())["workspace"]["package"]["version"])' "${repo_root}/Cargo.toml")
revision=$(git -C "${repo_root}" rev-parse HEAD)
created=$(git -C "${repo_root}" show -s --format=%ct HEAD | xargs -I{} date -u -d @{} +%Y-%m-%dT%H:%M:%SZ)
source_ref=${GITHUB_REF-}
if [ -z "${source_ref}" ]; then
  source_ref=$(git -C "${repo_root}" symbolic-ref -q HEAD || printf 'refs/commits/%s\n' "${revision}")
fi

dirty=false
if ! git -C "${repo_root}" diff --quiet || \
   ! git -C "${repo_root}" diff --cached --quiet || \
   [ -n "$(git -C "${repo_root}" ls-files --others --exclude-standard)" ]; then
  dirty=true
fi

if [ "${channel}" = release ]; then
  expected_ref="refs/tags/${version}"
  if [ "${source_ref}" != "${expected_ref}" ]; then
    echo "release image plan requires ${expected_ref}, got ${source_ref}" >&2
    exit 1
  fi
  if [ "${dirty}" != false ]; then
    echo "release image plan requires a clean source tree" >&2
    exit 1
  fi
  if [ "$(git -C "${repo_root}" cat-file -t "refs/tags/${version}")" != tag ]; then
    echo "release image plan requires an annotated ${version} tag" >&2
    exit 1
  fi
  "${repo_root}/tests/scripts/verify-release-tag.sh" "${version}"
  kind=release
else
  if [ "${CI-false}" = true ]; then kind=ci; else kind=local; fi
fi

mkdir -p "$(dirname -- "${output}")"
node "${repo_root}/devops/dist/cli.js" image-plan \
  --channel "${channel}" --version "${version}" --revision "${revision}" \
  --source-ref "${source_ref}" --created "${created}" --dirty "${dirty}" \
  --kind "${kind}" --output "${output}"
