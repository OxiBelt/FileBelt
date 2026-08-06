#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

state_dir=${FILEBELT_STATE_DIR:-"$(dirname -- "$0")/.state"}
case "${state_dir}" in
  /|"${HOME:-/nonexistent}"|.)
    echo "refusing unsafe FILEBELT_STATE_DIR=${state_dir}" >&2
    exit 1
    ;;
esac

for command in base64 openssl tail tr; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "missing required command: ${command}" >&2
    exit 1
  }
done

if [ -e "${state_dir}/prepared" ]; then
  echo "state is already prepared: ${state_dir}" >&2
  exit 1
fi

umask 077
mkdir -p "${state_dir}/backup" "${state_dir}/keys" "${state_dir}/secrets" "${state_dir}/tls"

random_hex() {
  openssl rand -hex 32
}

owner_password=$(random_hex)
migrator_password=$(random_hex)
api_password=$(random_hex)
io_password=$(random_hex)
maintenance_password=$(random_hex)

printf '%s\n' "${owner_password}" >"${state_dir}/secrets/postgres-owner-password"
printf '%s\n' "${migrator_password}" >"${state_dir}/secrets/migrator-database-password"
printf '%s\n' "${api_password}" >"${state_dir}/secrets/api-database-password"
printf '%s\n' "${io_password}" >"${state_dir}/secrets/io-database-password"
printf '%s\n' "${maintenance_password}" >"${state_dir}/secrets/maintenance-database-password"
printf 'postgresql://filebelt_migrator_login:%s@postgres:5432/filebelt?sslmode=disable&options=-c%%20role%%3Dfilebelt_migrator\n' \
  "${migrator_password}" >"${state_dir}/secrets/migrator-database-url"
printf 'postgresql://filebelt_api_login:%s@postgres:5432/filebelt?sslmode=disable\n' \
  "${api_password}" >"${state_dir}/secrets/api-database-url"
printf 'postgresql://filebelt_io_login:%s@postgres:5432/filebelt?sslmode=disable\n' \
  "${io_password}" >"${state_dir}/secrets/io-database-url"
printf 'postgresql://filebelt_maintenance_login:%s@postgres:5432/filebelt?sslmode=disable\n' \
  "${maintenance_password}" >"${state_dir}/secrets/maintenance-database-url"
random_hex >"${state_dir}/secrets/oidc-client-secret"
openssl rand 32 >"${state_dir}/secrets/digest-key"

openssl genpkey -algorithm ED25519 -outform DER \
  -out "${state_dir}/secrets/capability-private-key"
public_key=$(
  openssl pkey -inform DER -in "${state_dir}/secrets/capability-private-key" \
    -pubout -outform DER |
    tail -c 32 |
    base64 |
    tr '+/' '-_' |
    tr -d '=\n'
)
printf 'filebelt-capability-keyset-v1\n1:%s\n' "${public_key}" \
  >"${state_dir}/secrets/capability-public-keyset"

openssl req -x509 -newkey rsa:3072 -nodes -days 30 \
  -subj '/CN=filebelt.localhost' \
  -addext 'subjectAltName=DNS:filebelt.localhost' \
  -keyout "${state_dir}/tls/filebelt.key" \
  -out "${state_dir}/tls/filebelt.crt" >/dev/null 2>&1
chmod 0600 "${state_dir}/tls/filebelt.key"
chmod 0644 "${state_dir}/tls/filebelt.crt" \
  "${state_dir}/secrets/capability-public-keyset"
printf 'prepared\n' >"${state_dir}/prepared"

echo "prepared development-only state in ${state_dir}"
