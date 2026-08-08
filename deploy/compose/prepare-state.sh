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
mcp_password=$(random_hex)
collaboration_password=$(random_hex)

printf '%s\n' "${owner_password}" >"${state_dir}/secrets/postgres-owner-password"
printf '%s\n' "${migrator_password}" >"${state_dir}/secrets/migrator-database-password"
printf '%s\n' "${api_password}" >"${state_dir}/secrets/api-database-password"
printf '%s\n' "${io_password}" >"${state_dir}/secrets/io-database-password"
printf '%s\n' "${maintenance_password}" >"${state_dir}/secrets/maintenance-database-password"
printf '%s\n' "${mcp_password}" >"${state_dir}/secrets/mcp-database-password"
printf '%s\n' "${collaboration_password}" >"${state_dir}/secrets/collaboration-database-password"
printf 'postgresql://filebelt_migrator_login:%s@postgres:5432/filebelt?sslmode=disable&options=-c%%20role%%3Dfilebelt_migrator\n' \
  "${migrator_password}" >"${state_dir}/secrets/migrator-database-url"
printf 'postgresql://filebelt_api_login:%s@postgres:5432/filebelt?sslmode=disable\n' \
  "${api_password}" >"${state_dir}/secrets/api-database-url"
printf 'postgresql://filebelt_io_login:%s@postgres:5432/filebelt?sslmode=disable\n' \
  "${io_password}" >"${state_dir}/secrets/io-database-url"
printf 'postgresql://filebelt_maintenance_login:%s@postgres:5432/filebelt?sslmode=disable\n' \
  "${maintenance_password}" >"${state_dir}/secrets/maintenance-database-url"
printf 'postgresql://filebelt_mcp_broker_login:%s@postgres:5432/filebelt?sslmode=disable\n' \
  "${mcp_password}" >"${state_dir}/secrets/mcp-database-url"
printf 'postgresql://filebelt_collaboration_login:%s@postgres:5432/filebelt?sslmode=disable\n' \
  "${collaboration_password}" >"${state_dir}/secrets/collaboration-database-url"
vault_key=$(openssl rand -base64 32 | tr -d '\n')
printf '{"format":"filebelt.mcp-keyring.v1","keys":[{"generation":1,"key_base64":"%s"}]}\n' \
  "${vault_key}" >"${state_dir}/secrets/mcp-vault-keyring.json"
random_hex >"${state_dir}/secrets/oidc-client-secret"
openssl rand 32 >"${state_dir}/secrets/digest-key"

openssl genpkey -algorithm ED25519 -outform DER \
  -out "${state_dir}/secrets/capability-private-key"
api_public_key=$(
  openssl pkey -inform DER -in "${state_dir}/secrets/capability-private-key" \
    -pubout -outform DER |
    tail -c 32 |
    base64 |
    tr '+/' '-_' |
    tr -d '=\n'
)
openssl genpkey -algorithm ED25519 -outform DER \
  -out "${state_dir}/secrets/collaboration-capability-private-key"
collaboration_public_key=$(
  openssl pkey -inform DER -in "${state_dir}/secrets/collaboration-capability-private-key" \
    -pubout -outform DER |
    tail -c 32 |
    base64 |
    tr '+/' '-_' |
    tr -d '=\n'
)
printf 'filebelt-capability-keyset-v1\n1:%s\n2:%s\n' "${api_public_key}" "${collaboration_public_key}" \
  >"${state_dir}/secrets/capability-public-keyset"

openssl req -x509 -newkey rsa:3072 -nodes -days 30 \
  -subj '/CN=filebelt.localhost' \
  -addext 'subjectAltName=DNS:filebelt.localhost' \
  -keyout "${state_dir}/tls/filebelt.key" \
  -out "${state_dir}/tls/filebelt.crt" >/dev/null 2>&1
chmod 0600 "${state_dir}/tls/filebelt.key"
chmod 0644 "${state_dir}/tls/filebelt.crt" \
  "${state_dir}/secrets/capability-public-keyset"

openssl req -x509 -newkey rsa:3072 -nodes -days 30 \
  -subj '/CN=FileBelt development MCP egress CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "${state_dir}/tls/mcp-egress-ca.key" \
  -out "${state_dir}/tls/mcp-egress-ca.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:3072 -nodes \
  -subj '/CN=filebelt-mcp-egress' \
  -keyout "${state_dir}/tls/mcp-egress-server.key" \
  -out "${state_dir}/tls/mcp-egress-server.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:filebelt-mcp-egress\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n' \
  >"${state_dir}/tls/mcp-egress-server.ext"
openssl x509 -req -days 30 -sha256 \
  -in "${state_dir}/tls/mcp-egress-server.csr" \
  -CA "${state_dir}/tls/mcp-egress-ca.crt" \
  -CAkey "${state_dir}/tls/mcp-egress-ca.key" \
  -CAcreateserial -extfile "${state_dir}/tls/mcp-egress-server.ext" \
  -out "${state_dir}/tls/mcp-egress-server.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:3072 -nodes \
  -subj '/CN=filebelt-mcp-broker' \
  -keyout "${state_dir}/tls/mcp-egress-client.key" \
  -out "${state_dir}/tls/mcp-egress-client.csr" >/dev/null 2>&1
printf 'subjectAltName=URI:spiffe://filebelt/development/mcp-broker\nextendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n' \
  >"${state_dir}/tls/mcp-egress-client.ext"
openssl x509 -req -days 30 -sha256 \
  -in "${state_dir}/tls/mcp-egress-client.csr" \
  -CA "${state_dir}/tls/mcp-egress-ca.crt" \
  -CAkey "${state_dir}/tls/mcp-egress-ca.key" \
  -CAcreateserial -extfile "${state_dir}/tls/mcp-egress-client.ext" \
  -out "${state_dir}/tls/mcp-egress-client.crt" >/dev/null 2>&1
rm -f -- "${state_dir}/tls/mcp-egress-server.csr" \
  "${state_dir}/tls/mcp-egress-server.ext" \
  "${state_dir}/tls/mcp-egress-client.csr" \
  "${state_dir}/tls/mcp-egress-client.ext" \
  "${state_dir}/tls/mcp-egress-ca.srl"
chmod 0600 "${state_dir}/tls/mcp-egress-ca.key" \
  "${state_dir}/tls/mcp-egress-server.key" \
  "${state_dir}/tls/mcp-egress-client.key"
chmod 0644 "${state_dir}/tls/mcp-egress-ca.crt" \
  "${state_dir}/tls/mcp-egress-server.crt" \
  "${state_dir}/tls/mcp-egress-client.crt"
printf 'prepared\n' >"${state_dir}/prepared"

echo "prepared development-only state in ${state_dir}"
