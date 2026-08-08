#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: bootstrap-runtime-roles.sh migrator|runtime" >&2
  exit 2
fi

read_hex_secret() {
  value=$(tr -d '\r\n' <"$1")
  case "${value}" in
    *[!0-9a-f]*|'')
      echo "invalid generated database password: $1" >&2
      exit 1
      ;;
  esac
  if [ "${#value}" -ne 64 ]; then
    echo "invalid generated database password length: $1" >&2
    exit 1
  fi
  printf '%s' "${value}"
}

export PGPASSWORD
PGPASSWORD=$(tr -d '\r\n' </run/secrets/postgres-owner-password)

case "$1" in
  migrator)
    migrator_password=$(read_hex_secret /run/secrets/migrator-database-password)
    psql --host postgres --username filebelt_owner --dbname filebelt --no-psqlrc \
      --file /opt/filebelt/postgres/roles.sql
    {
      printf "\\set migrator_password '%s'\n" "${migrator_password}"
      cat <<'SQL'
\set ON_ERROR_STOP on
BEGIN;
SELECT format('CREATE ROLE filebelt_migrator_login LOGIN INHERIT PASSWORD %L', :'migrator_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_migrator_login') \gexec
ALTER ROLE filebelt_migrator_login PASSWORD :'migrator_password';
GRANT filebelt_migrator TO filebelt_migrator_login;
COMMIT;
SQL
    } | psql --host postgres --username filebelt_owner --dbname filebelt --no-psqlrc
    ;;
  runtime)
    api_password=$(read_hex_secret /run/secrets/api-database-password)
    io_password=$(read_hex_secret /run/secrets/io-database-password)
    maintenance_password=$(read_hex_secret /run/secrets/maintenance-database-password)
    mcp_password=$(read_hex_secret /run/secrets/mcp-database-password)
    collaboration_password=$(read_hex_secret /run/secrets/collaboration-database-password)
    {
      printf "\\set api_password '%s'\n" "${api_password}"
      printf "\\set io_password '%s'\n" "${io_password}"
      printf "\\set maintenance_password '%s'\n" "${maintenance_password}"
      printf "\\set mcp_password '%s'\n" "${mcp_password}"
      printf "\\set collaboration_password '%s'\n" "${collaboration_password}"
      cat <<'SQL'
\set ON_ERROR_STOP on
BEGIN;
SELECT format('CREATE ROLE filebelt_api_login LOGIN INHERIT PASSWORD %L', :'api_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_api_login') \gexec
SELECT format('CREATE ROLE filebelt_io_login LOGIN INHERIT PASSWORD %L', :'io_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_io_login') \gexec
SELECT format('CREATE ROLE filebelt_maintenance_login LOGIN INHERIT PASSWORD %L', :'maintenance_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_maintenance_login') \gexec
SELECT format('CREATE ROLE filebelt_mcp_broker_login LOGIN INHERIT PASSWORD %L', :'mcp_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_mcp_broker_login') \gexec
SELECT format('CREATE ROLE filebelt_collaboration_login LOGIN INHERIT PASSWORD %L', :'collaboration_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_collaboration_login') \gexec
ALTER ROLE filebelt_api_login PASSWORD :'api_password';
ALTER ROLE filebelt_io_login PASSWORD :'io_password';
ALTER ROLE filebelt_maintenance_login PASSWORD :'maintenance_password';
ALTER ROLE filebelt_mcp_broker_login PASSWORD :'mcp_password';
ALTER ROLE filebelt_collaboration_login PASSWORD :'collaboration_password';
GRANT filebelt_api TO filebelt_api_login;
GRANT filebelt_io TO filebelt_io_login;
GRANT filebelt_maintenance TO filebelt_maintenance_login;
GRANT filebelt_mcp_broker TO filebelt_mcp_broker_login;
GRANT filebelt_collaboration TO filebelt_collaboration_login;
COMMIT;
SQL
    } | psql --host postgres --username filebelt_owner --dbname filebelt --no-psqlrc
    psql --host postgres --username filebelt_owner --dbname filebelt --no-psqlrc \
      --file /opt/filebelt/postgres/grants.sql
    ;;
  *)
    echo "unknown database-role bootstrap phase: $1" >&2
    exit 2
    ;;
esac
