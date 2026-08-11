-- SPDX-License-Identifier: Apache-2.0

-- Common namespace metadata and transaction boundaries required by the NFS
-- projection. PostgreSQL remains authoritative: the adapter supplies neither
-- ownership nor replay state, and NFS ACL updates cannot rewrite Core rows.

-- Migration 000012 could assign more than one POSIX identity to Kerberos
-- aliases of the same FileBelt user. That ambiguity must be resolved by an
-- operator before this migration: choosing one row here would silently
-- reassign an append-only UID/name. Report every conflicting user in a stable
-- order and leave all mapping rows untouched.
DO $$
DECLARE
  v_inconsistent text;
  v_group_mismatches text;
BEGIN
  SELECT string_agg(
           format('tenant=%s principal=%s identities=%s',
             tenant_id,principal_id,identity_count),
           '; ' ORDER BY tenant_id,principal_id)
  INTO v_inconsistent
  FROM (
    SELECT tenant_id,principal_id,
           count(DISTINCT ROW(projected_uid,posix_name,posix_group_id,projected_gid))
             AS identity_count
    FROM filebelt_mount.nfs_principal_mappings
    GROUP BY tenant_id,principal_id
    HAVING count(DISTINCT ROW(
      projected_uid,posix_name,posix_group_id,projected_gid
    )) > 1
  ) AS inconsistent;
  SELECT string_agg(
           format(
             'tenant=%s principal=%s kerberos=%s mapping_gid=%s group_gid=%s',
             mapping.tenant_id,mapping.principal_id,mapping.kerberos_principal,
             mapping.projected_gid,posix_group.projected_gid
           ),
           '; ' ORDER BY mapping.tenant_id,mapping.principal_id,
                        mapping.kerberos_principal
         )
  INTO v_group_mismatches
  FROM filebelt_mount.nfs_principal_mappings AS mapping
  JOIN filebelt_mount.nfs_posix_groups AS posix_group
    ON posix_group.tenant_id=mapping.tenant_id
   AND posix_group.group_id=mapping.posix_group_id
  WHERE mapping.projected_gid IS DISTINCT FROM posix_group.projected_gid;
  v_inconsistent := nullif(concat_ws('; ',v_inconsistent,v_group_mismatches),'');
  IF v_inconsistent IS NOT NULL THEN
    RAISE EXCEPTION USING
      ERRCODE='23514',
      MESSAGE='inconsistent legacy NFS POSIX identities',
      DETAIL=v_inconsistent,
      HINT='make every Kerberos alias for a user share one UID, POSIX name, and primary group before retrying';
  END IF;
END
$$;

-- Migration 000011 changed principal invalidation to a statement trigger with
-- transition tables. Its fanout UPDATE of principals fires that same statement
-- trigger even when disabled_at did not change; issuing another zero-row UPDATE
-- from the nested invocation therefore recurses indefinitely. Return before
-- any DML when the triggering statement contains no real disable transition.
-- This keeps generation-only membership fencing safe while preserving the
-- original disable/re-enable generation, authorization, and creator-drive
-- invalidation boundary.
CREATE OR REPLACE FUNCTION filebelt_security.invalidate_principal_disable_creator_fanout()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_security
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM old_principals o
    JOIN changed_principals n ON n.tenant_id=o.tenant_id AND n.id=o.id
    WHERE o.disabled_at IS DISTINCT FROM n.disabled_at
  ) THEN
    RETURN NULL;
  END IF;
  UPDATE public.principals p SET generation=p.generation+1
  FROM (
    SELECT n.tenant_id,n.id
    FROM old_principals o
    JOIN changed_principals n ON n.tenant_id=o.tenant_id AND n.id=o.id
    WHERE o.disabled_at IS DISTINCT FROM n.disabled_at
  ) changed
  WHERE p.tenant_id=changed.tenant_id AND p.id=changed.id;
  DELETE FROM public.authorization_generations a
  USING (
    SELECT n.tenant_id,n.id
    FROM old_principals o
    JOIN changed_principals n ON n.tenant_id=o.tenant_id AND n.id=o.id
    WHERE o.disabled_at IS DISTINCT FROM n.disabled_at
  ) changed
  WHERE a.tenant_id=changed.tenant_id AND a.principal_id=changed.id;
  UPDATE public.drives d SET acl_generation=d.acl_generation+1
  FROM (
    SELECT DISTINCT s.tenant_id,s.drive_id
    FROM public.direct_shares s
    JOIN (
      SELECT n.tenant_id,n.id
      FROM old_principals o
      JOIN changed_principals n ON n.tenant_id=o.tenant_id AND n.id=o.id
      WHERE o.disabled_at IS DISTINCT FROM n.disabled_at
    ) changed ON changed.tenant_id=s.tenant_id AND changed.id=s.created_by
    WHERE s.revoked_at IS NULL AND s.inheritance='self_and_descendants'
  ) changed
  WHERE d.tenant_id=changed.tenant_id AND d.id=changed.drive_id;
  RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION filebelt_security.invalidate_principal_disable_creator_fanout()
  FROM PUBLIC;

-- One append-only registry row owns the POSIX identity for every Kerberos
-- alias of a FileBelt user. Mapping-level UID/name uniqueness would reject
-- legitimate aliases, while the registry keeps either value from ever being
-- assigned to another user. Revoked mappings and registry rows are retained,
-- so neither an alias nor its numeric identity can be reused.
ALTER TABLE filebelt_mount.nfs_posix_groups
  ADD CONSTRAINT nfs_posix_groups_group_gid_unique
  UNIQUE (tenant_id,group_id,projected_gid);

CREATE TABLE filebelt_mount.nfs_posix_users (
  tenant_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  posix_name text NOT NULL
    CHECK (posix_name ~ '^[a-z_][a-z0-9_.-]{0,254}$'),
  posix_group_id uuid NOT NULL,
  projected_uid bigint NOT NULL CHECK (
    projected_uid BETWEEN 1 AND 4294967294 AND projected_uid<>65534
  ),
  projected_gid bigint NOT NULL CHECK (
    projected_gid BETWEEN 1 AND 4294967294 AND projected_gid<>65534
  ),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,principal_id),
  UNIQUE (tenant_id,posix_name),
  UNIQUE (tenant_id,projected_uid),
  FOREIGN KEY (tenant_id,principal_id)
    REFERENCES public.principals(tenant_id,id),
  FOREIGN KEY (tenant_id,posix_group_id)
    REFERENCES filebelt_mount.nfs_posix_groups(tenant_id,group_id),
  FOREIGN KEY (tenant_id,posix_group_id,projected_gid)
    REFERENCES filebelt_mount.nfs_posix_groups(tenant_id,group_id,projected_gid)
);

INSERT INTO filebelt_mount.nfs_posix_users (
  tenant_id,principal_id,posix_name,posix_group_id,projected_uid,projected_gid,created_at
)
SELECT tenant_id,principal_id,posix_name,posix_group_id,
       projected_uid,projected_gid,created_at
FROM (
  SELECT DISTINCT ON (tenant_id,principal_id)
         tenant_id,principal_id,posix_name,posix_group_id,
         projected_uid,projected_gid,created_at
  FROM filebelt_mount.nfs_principal_mappings
  WHERE posix_name IS NOT NULL AND posix_group_id IS NOT NULL
  ORDER BY tenant_id,principal_id,created_at,kerberos_principal
) AS identity;

CREATE FUNCTION filebelt_mount.enforce_nfs_posix_user_immutability()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,filebelt_mount
AS $$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE='55000',
    MESSAGE='NFS POSIX user registry rows are immutable';
END
$$;
CREATE TRIGGER nfs_posix_user_immutable
BEFORE UPDATE OR DELETE ON filebelt_mount.nfs_posix_users
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.enforce_nfs_posix_user_immutability();
REVOKE ALL ON FUNCTION filebelt_mount.enforce_nfs_posix_user_immutability()
  FROM PUBLIC;

ALTER TABLE filebelt_mount.nfs_principal_mappings
  DROP CONSTRAINT nfs_principal_mappings_tenant_id_projected_uid_key,
  DROP CONSTRAINT nfs_principal_mappings_posix_name_key;

-- Establish or verify the shared registry identity inside the mapping write.
-- The trigger is a definer because the API deliberately has no raw write
-- grant on the immutable registry. Unique registry keys serialize concurrent
-- first-alias inserts and prevent cross-user UID/name reuse.
CREATE OR REPLACE FUNCTION filebelt_mount.enforce_nfs_mapping_projection()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_identity record;
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION USING
      ERRCODE='55000',
      MESSAGE='NFS user projection rows are immutable';
  END IF;
  IF TG_OP='UPDATE' AND (
    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.kerberos_principal IS DISTINCT FROM OLD.kerberos_principal
    OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
    OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
    OR NEW.projected_uid IS DISTINCT FROM OLD.projected_uid
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR (OLD.posix_name IS NOT NULL AND NEW.posix_name IS DISTINCT FROM OLD.posix_name)
    OR (OLD.posix_group_id IS NOT NULL
      AND NEW.posix_group_id IS DISTINCT FROM OLD.posix_group_id)
    OR (OLD.posix_name IS NOT NULL
      AND NEW.projected_gid IS DISTINCT FROM OLD.projected_gid)
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE='55000',
      MESSAGE='NFS user projection identity is immutable';
  END IF;
  IF NEW.posix_name IS NOT NULL AND NEW.posix_group_id IS NOT NULL THEN
    INSERT INTO filebelt_mount.nfs_posix_users (
      tenant_id,principal_id,posix_name,posix_group_id,projected_uid,projected_gid
    ) VALUES (
      NEW.tenant_id,NEW.principal_id,NEW.posix_name,NEW.posix_group_id,
      NEW.projected_uid,NEW.projected_gid
    ) ON CONFLICT DO NOTHING;
    SELECT posix_name,posix_group_id,projected_uid,projected_gid
    INTO v_identity
    FROM filebelt_mount.nfs_posix_users
    WHERE tenant_id=NEW.tenant_id AND principal_id=NEW.principal_id
    FOR KEY SHARE;
    IF NOT FOUND
       OR v_identity.posix_name IS DISTINCT FROM NEW.posix_name
       OR v_identity.posix_group_id IS DISTINCT FROM NEW.posix_group_id
       OR v_identity.projected_uid IS DISTINCT FROM NEW.projected_uid
       OR v_identity.projected_gid IS DISTINCT FROM NEW.projected_gid THEN
      RAISE EXCEPTION USING
        ERRCODE='23505',
        MESSAGE='NFS Kerberos aliases must share one immutable POSIX identity';
    END IF;
  ELSIF NEW.revoked_at IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE='23514',
      MESSAGE='active NFS mapping requires a complete POSIX identity';
  END IF;
  IF NEW.revoked_at IS NULL THEN
    PERFORM 1
    FROM filebelt_mount.nfs_posix_groups AS posix_group
    JOIN public.group_memberships AS membership
      ON membership.tenant_id=posix_group.tenant_id
     AND membership.group_id=posix_group.group_id
     AND membership.user_principal_id=NEW.principal_id
    WHERE posix_group.tenant_id=NEW.tenant_id
      AND posix_group.group_id=NEW.posix_group_id
      AND posix_group.projected_gid=NEW.projected_gid
    FOR KEY SHARE OF membership;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING
        ERRCODE='23503',
        MESSAGE='active NFS mapping requires a registered primary-group membership';
    END IF;
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION filebelt_mount.enforce_nfs_mapping_projection()
  FROM PUBLIC;

ALTER TABLE public.nodes DROP CONSTRAINT nodes_kind_check;
ALTER TABLE public.nodes
  ADD COLUMN owner_principal_id uuid,
  ADD COLUMN posix_group_id uuid,
  ADD COLUMN posix_mode integer,
  ADD COLUMN handle_generation bigint NOT NULL DEFAULT 1,
  ADD COLUMN accessed_at timestamptz,
  ADD COLUMN modified_at timestamptz,
  ADD COLUMN changed_at timestamptz,
  ADD COLUMN symlink_target text,
  ADD CONSTRAINT nodes_kind_check CHECK (kind IN ('file','directory','symlink')),
  ADD CONSTRAINT nodes_owner_principal_fk
    FOREIGN KEY (tenant_id,owner_principal_id)
    REFERENCES public.principals(tenant_id,id),
  ADD CONSTRAINT nodes_posix_group_fk
    FOREIGN KEY (tenant_id,posix_group_id)
    REFERENCES filebelt_mount.nfs_posix_groups(tenant_id,group_id),
  ADD CONSTRAINT nodes_posix_mode_check CHECK (posix_mode BETWEEN 0 AND 511),
  ADD CONSTRAINT nodes_handle_generation_check CHECK (handle_generation>0),
  ADD CONSTRAINT nodes_symlink_shape_check CHECK (
    (kind='symlink'
      AND symlink_target IS NOT NULL
      AND octet_length(symlink_target) BETWEEN 1 AND 4096
      AND left(symlink_target,1)<>'/')
    OR (kind<>'symlink' AND symlink_target IS NULL)
  );

UPDATE public.nodes AS node
SET owner_principal_id=drive.owner_principal_id,
    posix_mode=CASE node.kind WHEN 'directory' THEN 493 ELSE 420 END,
    accessed_at=node.created_at,
    modified_at=node.updated_at,
    changed_at=node.updated_at
FROM public.drives AS drive
WHERE drive.tenant_id=node.tenant_id AND drive.id=node.drive_id;

ALTER TABLE public.nodes
  ALTER COLUMN owner_principal_id SET NOT NULL,
  ALTER COLUMN posix_mode SET NOT NULL,
  ALTER COLUMN accessed_at SET NOT NULL,
  ALTER COLUMN modified_at SET NOT NULL,
  ALTER COLUMN changed_at SET NOT NULL;

CREATE FUNCTION filebelt_mount.prepare_common_node_metadata()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_now timestamptz := clock_timestamp();
BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.owner_principal_id IS NULL THEN
      SELECT drive.owner_principal_id INTO NEW.owner_principal_id
      FROM public.drives AS drive
      WHERE drive.tenant_id=NEW.tenant_id AND drive.id=NEW.drive_id;
    END IF;
    NEW.posix_mode := COALESCE(NEW.posix_mode,CASE NEW.kind
      WHEN 'directory' THEN 493
      WHEN 'symlink' THEN 511
      ELSE 420
    END);
    NEW.accessed_at := COALESCE(NEW.accessed_at,NEW.created_at,v_now);
    NEW.modified_at := COALESCE(NEW.modified_at,NEW.created_at,v_now);
    NEW.changed_at := COALESCE(NEW.changed_at,NEW.created_at,v_now);
    RETURN NEW;
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.drive_id IS DISTINCT FROM OLD.drive_id
     OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.kind IS DISTINCT FROM OLD.kind THEN
    RAISE EXCEPTION USING
      ERRCODE='55000',
      MESSAGE='common node identity and kind are immutable';
  END IF;
  IF NEW.handle_generation IS DISTINCT FROM OLD.handle_generation THEN
    RAISE EXCEPTION USING
      ERRCODE='55000',
      MESSAGE='node handle generations are immutable';
  END IF;
  IF NEW.parent_id IS DISTINCT FROM OLD.parent_id
     OR NEW.display_name IS DISTINCT FROM OLD.display_name
     OR NEW.name_key IS DISTINCT FROM OLD.name_key
     OR NEW.head_version_id IS DISTINCT FROM OLD.head_version_id
     OR NEW.trash_root_id IS DISTINCT FROM OLD.trash_root_id
     OR NEW.owner_principal_id IS DISTINCT FROM OLD.owner_principal_id
     OR NEW.posix_group_id IS DISTINCT FROM OLD.posix_group_id
     OR NEW.posix_mode IS DISTINCT FROM OLD.posix_mode
     OR NEW.modified_at IS DISTINCT FROM OLD.modified_at
     OR NEW.accessed_at IS DISTINCT FROM OLD.accessed_at
     OR NEW.symlink_target IS DISTINCT FROM OLD.symlink_target THEN
    NEW.changed_at := v_now;
  END IF;
  IF NEW.head_version_id IS DISTINCT FROM OLD.head_version_id THEN
    NEW.modified_at := v_now;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER common_node_metadata_projection
BEFORE INSERT OR UPDATE ON public.nodes
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.prepare_common_node_metadata();

-- Only the portable user namespace is persisted. One node may carry at most
-- the 256 names admitted by the VFS protocol; each value is independently
-- bounded at 64 KiB.
CREATE TABLE public.node_xattrs (
  tenant_id uuid NOT NULL,
  drive_id uuid NOT NULL,
  node_id uuid NOT NULL,
  name text NOT NULL,
  value bytea NOT NULL CHECK (octet_length(value)<=65536),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,drive_id,node_id,name),
  FOREIGN KEY (tenant_id,drive_id,node_id)
    REFERENCES public.nodes(tenant_id,drive_id,id) ON DELETE CASCADE,
  CHECK (
    left(name,5)='user.'
    AND octet_length(name) BETWEEN 6 AND 255
    AND name !~ '[[:cntrl:]]'
  )
);

CREATE FUNCTION filebelt_mount.enforce_node_xattr_limit()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,public
AS $$
BEGIN
  IF TG_OP='UPDATE' AND (
    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.drive_id IS DISTINCT FROM OLD.drive_id
    OR NEW.node_id IS DISTINCT FROM OLD.node_id
    OR NEW.name IS DISTINCT FROM OLD.name
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
  ) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='node xattr identity is immutable';
  END IF;
  IF TG_OP='INSERT' THEN
    -- Serialize the per-node count across distinct replay identities. The
    -- xattr primary key alone cannot prevent two concurrent inserts from both
    -- observing 255 rows and admitting a 257th entry.
    PERFORM 1 FROM public.nodes AS node
    WHERE node.tenant_id=NEW.tenant_id
      AND node.drive_id=NEW.drive_id
      AND node.id=NEW.node_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='23503',MESSAGE='node xattr owner does not exist';
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM public.node_xattrs AS xattr
      WHERE xattr.tenant_id=NEW.tenant_id
        AND xattr.drive_id=NEW.drive_id
        AND xattr.node_id=NEW.node_id
        AND xattr.name=NEW.name
    ) AND (
      SELECT count(*) FROM public.node_xattrs AS xattr
      WHERE xattr.tenant_id=NEW.tenant_id
        AND xattr.drive_id=NEW.drive_id
        AND xattr.node_id=NEW.node_id
    )>=256 THEN
      RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='node xattr limit exceeded';
    END IF;
  END IF;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END
$$;
CREATE TRIGGER node_xattr_limit
BEFORE INSERT OR UPDATE ON public.node_xattrs
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.enforce_node_xattr_limit();

-- Core and NFS ACL rows can coexist. NFS is restricted to ALLOW entries and
-- direct application-role callers cannot create, rewrite, or remove its tag.
ALTER TABLE public.acl_entries ADD COLUMN source text NOT NULL DEFAULT 'core';
DO $$
DECLARE
  v_constraint name;
BEGIN
  SELECT constraint_name INTO v_constraint
  FROM information_schema.table_constraints
  WHERE table_schema='public' AND table_name='acl_entries'
    AND constraint_type='UNIQUE'
  ORDER BY constraint_name
  LIMIT 1;
  IF v_constraint IS NULL THEN
    RAISE EXCEPTION 'acl_entries source cutover could not find the prior unique constraint';
  END IF;
  EXECUTE format('ALTER TABLE public.acl_entries DROP CONSTRAINT %I',v_constraint);
END
$$;
ALTER TABLE public.acl_entries
  ADD CONSTRAINT acl_entries_source_check CHECK (
    source='core'
    OR (source='nfs' AND effect='allow' AND direct_share_id IS NULL)
  ),
  ADD CONSTRAINT acl_entries_source_unique UNIQUE (
    tenant_id,resource_id,principal_id,action,inheritance,source
  );

CREATE FUNCTION filebelt_mount.protect_acl_source()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,public,filebelt_mount
AS $$
BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.source='nfs' AND NOT pg_has_role(session_user,'filebelt_vfs','MEMBER') THEN
      RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='NFS ACL rows are VFS-owned';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP='UPDATE' AND NEW.source IS DISTINCT FROM OLD.source THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ACL source tags are immutable';
  END IF;
  IF OLD.source='nfs' AND NOT pg_has_role(session_user,'filebelt_vfs','MEMBER') THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='NFS ACL rows are VFS-owned';
  END IF;
  RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END
$$;
CREATE TRIGGER acl_source_ownership
BEFORE INSERT OR UPDATE OR DELETE ON public.acl_entries
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.protect_acl_source();

-- Feature-generation-scoped live projections replace the former global
-- activation snapshot. They derive from current ACL ancestry and membership
-- rows on every read, so ACL, group, mapping, and rename changes cannot leave
-- stale NFS traversal or flat-group authority behind.
CREATE VIEW filebelt_mount.nfs_managed_traversal AS
SELECT DISTINCT
  acl.tenant_id,
  acl.drive_id,
  path.ancestor_id,
  acl.principal_id,
  acl.id AS source_acl_entry_id,
  acl.generation AS source_acl_generation,
  feature.generation AS feature_generation
FROM filebelt_mount.nfs_feature_state AS feature
JOIN public.acl_entries AS acl
  ON acl.tenant_id=feature.tenant_id AND acl.effect='allow'
JOIN public.node_ancestry AS covered
  ON covered.tenant_id=acl.tenant_id AND covered.drive_id=acl.drive_id
 AND covered.ancestor_id=acl.resource_id
 AND ((covered.depth=0 AND acl.inheritance IN ('self','self_and_descendants'))
   OR (covered.depth>0 AND acl.inheritance IN ('descendants','self_and_descendants')))
JOIN public.node_ancestry AS path
  ON path.tenant_id=covered.tenant_id AND path.drive_id=covered.drive_id
 AND path.descendant_id=covered.descendant_id AND path.depth>0
WHERE feature.state IN ('preflight','active','draining');

CREATE VIEW filebelt_mount.nfs_managed_group_memberships AS
SELECT
  membership.tenant_id,
  membership.group_id,
  membership.user_principal_id,
  membership.generation AS source_membership_generation,
  feature.generation AS feature_generation
FROM filebelt_mount.nfs_feature_state AS feature
JOIN filebelt_mount.nfs_principal_mappings AS mapping
  ON mapping.tenant_id=feature.tenant_id AND mapping.revoked_at IS NULL
JOIN public.group_memberships AS membership
  ON membership.tenant_id=mapping.tenant_id
 AND membership.user_principal_id=mapping.principal_id
WHERE feature.state IN ('preflight','active','draining');

REVOKE ALL ON filebelt_mount.nfs_managed_traversal,
  filebelt_mount.nfs_managed_group_memberships FROM PUBLIC;

CREATE FUNCTION filebelt_mount.fence_nfs_mapping_sessions(
  p_tenant_id uuid,
  p_principal_id uuid,
  p_credential_id uuid,
  p_mapping_generation bigint,
  p_reason text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_changed bigint;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_api','MEMBER')
     OR p_mapping_generation<=0
     OR p_reason NOT IN ('nfs_mapping_changed','nfs_mapping_revoked')
     OR NOT EXISTS (
       SELECT 1 FROM filebelt_mount.nfs_principal_mappings AS mapping
       WHERE mapping.tenant_id=p_tenant_id
         AND mapping.principal_id=p_principal_id
         AND mapping.credential_id=p_credential_id
         AND mapping.generation=p_mapping_generation
         AND (p_reason='nfs_mapping_revoked')=(mapping.revoked_at IS NOT NULL)
     ) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS mapping session fence';
  END IF;
  UPDATE filebelt_mount.sessions
  SET state='closed',closed_at=clock_timestamp(),close_reason=p_reason,
      last_activity_at=clock_timestamp()
  WHERE tenant_id=p_tenant_id AND user_principal_id=p_principal_id
    AND credential_id=p_credential_id AND protocol='nfs'
    AND state IN ('active','draining');
  GET DIAGNOSTICS v_changed=ROW_COUNT;
  RETURN v_changed;
END
$$;
REVOKE ALL ON FUNCTION filebelt_mount.fence_nfs_mapping_sessions(
  uuid,uuid,uuid,bigint,text
) FROM PUBLIC;

REVOKE ALL ON FUNCTION filebelt_mount.prepare_common_node_metadata() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.enforce_node_xattr_limit() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.protect_acl_source() FROM PUBLIC;
