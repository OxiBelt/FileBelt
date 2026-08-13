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
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_collaboration_definer') THEN
    CREATE ROLE filebelt_collaboration_definer NOLOGIN;
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
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'filebelt_revision') THEN
    CREATE ROLE filebelt_revision NOLOGIN;
  END IF;
END
$$;

GRANT USAGE, CREATE ON SCHEMA public TO filebelt_migrator;
-- Released migrations are immutable. Migration 000016 contains an idempotent
-- CREATE SCHEMA statement, which PostgreSQL authorizes at the database scope
-- even when the database owner already created the schema below. Grant this
-- only for the bounded migration window; grants.sql revokes it afterwards and
-- grant verification rejects retaining it.
DO $$
BEGIN
  EXECUTE format(
    'GRANT CREATE ON DATABASE %I TO filebelt_migrator',
    current_database()
  );
END
$$;
CREATE SCHEMA IF NOT EXISTS filebelt_mcp;
CREATE SCHEMA IF NOT EXISTS filebelt_mcp_vault;
CREATE SCHEMA IF NOT EXISTS filebelt_collaboration;
CREATE SCHEMA IF NOT EXISTS filebelt_mount;
CREATE SCHEMA IF NOT EXISTS filebelt_mount_vault;
CREATE SCHEMA IF NOT EXISTS filebelt_document;
CREATE SCHEMA IF NOT EXISTS filebelt_media;
CREATE SCHEMA IF NOT EXISTS filebelt_phase8;
CREATE SCHEMA IF NOT EXISTS filebelt_security;
CREATE SCHEMA IF NOT EXISTS filebelt_revision;
-- Migration 000016 also revokes PUBLIC access on this schema. Ownership lets
-- the migrator execute that immutable statement without receiving ownership
-- of the database or any role-level administration attribute.
ALTER SCHEMA filebelt_revision OWNER TO filebelt_migrator;
REVOKE ALL ON SCHEMA filebelt_mcp, filebelt_mcp_vault, filebelt_collaboration,
  filebelt_mount, filebelt_mount_vault, filebelt_document, filebelt_media,
  filebelt_phase8, filebelt_security, filebelt_revision FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA filebelt_mcp, filebelt_mcp_vault, filebelt_collaboration,
  filebelt_mount, filebelt_mount_vault, filebelt_document, filebelt_media,
  filebelt_phase8, filebelt_security, filebelt_revision TO filebelt_migrator;

-- This role owns only the fixed-shape collaboration locking and accounting
-- functions.
-- It has no login or membership and is never a runtime connection identity.
GRANT USAGE ON SCHEMA public, filebelt_collaboration
  TO filebelt_collaboration_definer;
