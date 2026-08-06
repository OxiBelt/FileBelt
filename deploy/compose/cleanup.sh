#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

compose_file=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/compose.yaml

docker compose --file "${compose_file}" \
  --profile core \
  --profile iggy \
  --profile fault \
  down --volumes --remove-orphans --timeout 35

echo "removed FileBelt Phase 2 containers, networks, and named volumes"
echo "development secrets and operator-created backup files were retained"
