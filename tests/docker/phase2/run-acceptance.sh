#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
compose_file="${repo_root}/deploy/compose/compose.yaml"
local_state_dir=$(mktemp -d "${repo_root}/deploy/compose/.state.acceptance.XXXXXXXX")

# Docker-outside-of-Docker daemons resolve bind sources in the host namespace.
# Translate the repository path through the current container's longest matching
# mount when possible; native Docker environments retain their local paths.
host_repo_root=$(
  docker inspect --format '{{range .Mounts}}{{println .Source "|" .Destination}}{{end}}' "$(hostname)" 2>/dev/null |
    awk -F ' \| ' -v root="${repo_root}" '
      index(root, $2 "/") == 1 && length($2) > length(destination) {
        source = $1
        destination = $2
      }
      END {
        if (destination != "") {
          print source substr(root, length(destination) + 1)
        }
      }
    '
)
if [ -z "${host_repo_root}" ]; then
  host_repo_root=${repo_root}
fi

docker_outside_container=
acceptance_network_connected=0
if [ "${host_repo_root}" != "${repo_root}" ]; then
  docker_outside_container=$(hostname)
fi

compose_state_dir="${host_repo_root}${local_state_dir#"${repo_root}"}"
export FILEBELT_STATE_DIR=${compose_state_dir}
export FILEBELT_CONFIG_FILE="${host_repo_root}/deploy/compose/filebelt.toml"
export FILEBELT_COLLABORATION_CONFIG_FILE="${host_repo_root}/deploy/compose/filebelt-collaboration.toml"
export FILEBELT_EDGE_CONFIG_FILE="${host_repo_root}/ui/web/edge/oxibelt.acceptance.toml"
export FILEBELT_POSTGRES_ROLE_SCRIPT_FILE="${host_repo_root}/deploy/compose/postgres/bootstrap-runtime-roles.sh"
export FILEBELT_POSTGRES_ROLES_FILE="${host_repo_root}/source/migrations/postgres/roles.sql"
export FILEBELT_POSTGRES_GRANTS_FILE="${host_repo_root}/source/migrations/postgres/grants.sql"

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "${status}" -ne 0 ]; then
    docker compose --file "${compose_file}" --profile core ps --all || true
    docker compose --file "${compose_file}" --profile core logs --no-color --tail 200 || true
  fi
  if [ "${acceptance_network_connected}" -eq 1 ]; then
    docker network disconnect filebelt-phase2_edge "${docker_outside_container}" || true
  fi
  docker compose --file "${compose_file}" \
    --profile core down --volumes --remove-orphans --timeout 35 || true
  rm -rf -- "${local_state_dir}"
  exit "${status}"
}
trap cleanup EXIT HUP INT TERM

FILEBELT_STATE_DIR="${local_state_dir}" "${repo_root}/deploy/compose/prepare-state.sh"
test -s "${local_state_dir}/secrets/oidc-client-secret"
# Compose implements local secrets and configs as daemon-side bind mounts. The
# disposable fixture state is created by devcontainer root, so a rootless host
# daemon needs traverse/read access until the cleanup trap removes it.
chmod 0711 "${local_state_dir}" "${local_state_dir}/secrets" "${local_state_dir}/tls"
chmod 0644 "${local_state_dir}"/secrets/* "${local_state_dir}"/tls/*

build_option=--build
if [ "${FILEBELT_ACCEPTANCE_SKIP_BUILD:-0}" = 1 ]; then
  build_option=--no-build
fi
docker compose --file "${compose_file}" --profile core up "${build_option}" --wait
if [ -n "${docker_outside_container}" ]; then
  docker network connect filebelt-phase2_edge "${docker_outside_container}"
  acceptance_network_connected=1
  edge_address=$(
    docker inspect --format '{{(index .NetworkSettings.Networks "filebelt-phase2_edge").IPAddress}}' \
      filebelt-phase2-filebelt-web-1
  )
  test -n "${edge_address}"
  export FILEBELT_ACCEPTANCE_CONNECT_HOST=${edge_address}
fi
python3 "${repo_root}/tests/docker/phase2/acceptance.py"
