-- SPDX-License-Identifier: Apache-2.0
-- Run as the database owner before migrations to create group roles and grant
-- the migrator. Run grants.sql after every migration.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_migrator') THEN
    CREATE ROLE filebelt_migrator NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_api') THEN
    CREATE ROLE filebelt_api NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_io') THEN
    CREATE ROLE filebelt_io NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_maintenance') THEN
    CREATE ROLE filebelt_maintenance NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_audit_exporter') THEN
    CREATE ROLE filebelt_audit_exporter NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_recovery') THEN
    CREATE ROLE filebelt_recovery NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_mcp_broker') THEN
    CREATE ROLE filebelt_mcp_broker NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_collaboration') THEN
    CREATE ROLE filebelt_collaboration NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_vfs') THEN
    CREATE ROLE filebelt_vfs NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_headscale_sync') THEN
    CREATE ROLE filebelt_headscale_sync NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_document') THEN
    CREATE ROLE filebelt_document NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_media') THEN
    CREATE ROLE filebelt_media NOLOGIN;
  END IF;
END
$$;

GRANT USAGE, CREATE ON SCHEMA public TO filebelt_migrator;
CREATE SCHEMA IF NOT EXISTS filebelt_mcp;
CREATE SCHEMA IF NOT EXISTS filebelt_mcp_vault;
CREATE SCHEMA IF NOT EXISTS filebelt_collaboration;
CREATE SCHEMA IF NOT EXISTS filebelt_mount;
CREATE SCHEMA IF NOT EXISTS filebelt_mount_vault;
CREATE SCHEMA IF NOT EXISTS filebelt_document;
CREATE SCHEMA IF NOT EXISTS filebelt_media;
CREATE SCHEMA IF NOT EXISTS filebelt_phase8;
CREATE SCHEMA IF NOT EXISTS filebelt_security;
REVOKE ALL ON SCHEMA filebelt_mcp, filebelt_mcp_vault, filebelt_collaboration,
  filebelt_mount, filebelt_mount_vault, filebelt_document, filebelt_media,
  filebelt_phase8, filebelt_security FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA filebelt_mcp, filebelt_mcp_vault, filebelt_collaboration,
  filebelt_mount, filebelt_mount_vault, filebelt_document, filebelt_media,
  filebelt_phase8, filebelt_security TO filebelt_migrator;
