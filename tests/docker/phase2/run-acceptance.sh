#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
if [ "${FILEBELT_ACCEPTANCE_SKIP_BUILD:-0}" = 1 ]; then
  exec python3 "${repo_root}/tests/docker/units/run-unit.py" --unit core --reuse-images
fi
exec python3 "${repo_root}/tests/docker/units/run-unit.py" --unit core --build
