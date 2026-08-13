-- SPDX-License-Identifier: Apache-2.0

-- Repair the shared NFS worker-authority trigger without changing migration
-- 000014's checksum. PostgreSQL may reorder boolean expressions, so guarding a
-- table-specific OLD field with an AND predicate is not sufficient for a
-- polymorphic trigger. Dispatch first, then access only fields that exist on
-- the selected trigger relation.
CREATE OR REPLACE FUNCTION filebelt_mount.protect_nfs_worker_authority()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,public,filebelt_mount
AS $$
BEGIN
  IF NOT pg_has_role(current_user,'filebelt_io','MEMBER') THEN
    RETURN NEW;
  END IF;
  IF current_user=pg_get_userbyid((
       SELECT relation.relowner FROM pg_class AS relation
       WHERE relation.oid='filebelt_mount.write_sessions'::regclass
     )) THEN
    RETURN NEW;
  END IF;

  IF TG_TABLE_SCHEMA='filebelt_mount' AND TG_TABLE_NAME='write_sessions' THEN
    IF EXISTS (
      SELECT 1 FROM filebelt_mount.sessions AS mount_session
      WHERE mount_session.tenant_id=OLD.tenant_id
        AND mount_session.id=OLD.mount_session_id
        AND mount_session.protocol='nfs'
    ) THEN
      RAISE EXCEPTION USING ERRCODE='42501',
        MESSAGE='raw NFS writer mutation is forbidden';
    END IF;
  ELSIF TG_TABLE_SCHEMA='filebelt_mount' AND TG_TABLE_NAME='write_chunks' THEN
    IF EXISTS (
      SELECT 1 FROM filebelt_mount.write_sessions AS writer
      JOIN filebelt_mount.sessions AS mount_session
        ON mount_session.tenant_id=writer.tenant_id
       AND mount_session.id=writer.mount_session_id
      WHERE writer.tenant_id=OLD.tenant_id
        AND writer.id=OLD.write_session_id
        AND mount_session.protocol='nfs'
    ) THEN
      RAISE EXCEPTION USING ERRCODE='42501',
        MESSAGE='raw NFS chunk mutation is forbidden';
    END IF;
  ELSIF TG_TABLE_SCHEMA='public' AND TG_TABLE_NAME='payload_objects' THEN
    IF EXISTS (
      SELECT 1 FROM filebelt_mount.write_sessions AS writer
      JOIN filebelt_mount.sessions AS mount_session
        ON mount_session.tenant_id=writer.tenant_id
       AND mount_session.id=writer.mount_session_id
      WHERE writer.tenant_id=OLD.tenant_id
        AND writer.staging_payload_id=OLD.id
        AND mount_session.protocol='nfs'
    ) THEN
      RAISE EXCEPTION USING ERRCODE='42501',
        MESSAGE='raw NFS payload mutation is forbidden';
    END IF;
  END IF;
  RETURN NEW;
END
$$;
