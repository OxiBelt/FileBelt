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
END
$$;

GRANT USAGE, CREATE ON SCHEMA public TO filebelt_migrator;
