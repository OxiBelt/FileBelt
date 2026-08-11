-- SPDX-License-Identifier: Apache-2.0

-- First deployable NFS authority slice. PostgreSQL owns tenant activation,
-- export reconciliation, POSIX group projections, and authenticated session
-- creation. Neither the adapter nor the Phase 8 compatibility advertisement
-- can substitute for these tenant-scoped fences.

-- Password-derived mount credentials remain short lived. A Kerberos mapping
-- is an internal projection of authority already authenticated by RPCSEC_GSS,
-- so it is deliberately non-expiring and is fenced by mapping, policy, feature,
-- gateway, and principal generations instead.
ALTER TABLE filebelt_mount.credentials
  DROP CONSTRAINT mount_credential_maximum_lifetime;
UPDATE filebelt_mount.credentials
SET expires_at='infinity'::timestamptz
WHERE protocol='nfs' AND verifier_kind='kerberos_principal';
ALTER TABLE filebelt_mount.credentials
  ADD CONSTRAINT mount_credential_maximum_lifetime CHECK (
    (protocol='nfs' AND verifier_kind='kerberos_principal'
      AND expires_at='infinity'::timestamptz)
    OR
    (NOT (protocol='nfs' AND verifier_kind='kerberos_principal')
      AND expires_at <= created_at+interval '7 days')
  );

-- Preview mappings did not own an immutable POSIX user name and allowed the
-- primary GID to float independently of a registered group. There is no safe
-- value to infer during migration, so close and revoke every preview mapping;
-- its row keeps ownership of the UID and Kerberos name until an administrator
-- explicitly reactivates it under the new constraints.
UPDATE filebelt_mount.sessions AS session
SET state='closed',
    closed_at=COALESCE(session.closed_at,clock_timestamp()),
    close_reason=COALESCE(session.close_reason,'nfs_posix_registry_cutover')
WHERE session.protocol='nfs' AND session.state IN ('active','draining');
UPDATE filebelt_mount.credentials AS credential
SET revoked_at=COALESCE(credential.revoked_at,clock_timestamp()),
    credential_generation=credential.credential_generation+1,
    authorization_generation=credential.authorization_generation+1
FROM filebelt_mount.nfs_principal_mappings AS mapping
WHERE credential.tenant_id=mapping.tenant_id
  AND credential.id=mapping.credential_id;
UPDATE filebelt_mount.nfs_principal_mappings
SET revoked_at=COALESCE(revoked_at,clock_timestamp()),
    generation=generation+1,
    updated_at=clock_timestamp();
ALTER TABLE filebelt_mount.nfs_principal_mappings
  ADD COLUMN posix_name text,
  DROP CONSTRAINT nfs_principal_mappings_tenant_id_projected_gid_key;

-- Preview replay receipts could identify only a client slot and retained a
-- digest that could not reproduce the acknowledged protobuf after restart.
-- Their lifetime is only 90 seconds, so the forward cutover safely discards
-- them and installs the complete immutable per-operation replay identity.
DELETE FROM filebelt_mount.nfs_replay_receipts;
ALTER TABLE filebelt_mount.nfs_replay_receipts
  DROP CONSTRAINT nfs_replay_receipts_pkey,
  ADD COLUMN mount_session_id uuid NOT NULL,
  ADD COLUMN nfs_session_id text NOT NULL
    CHECK (length(nfs_session_id) BETWEEN 1 AND 255)
    CHECK (nfs_session_id ~ '^[A-Za-z0-9_.:@-]+$'),
  ADD COLUMN operation_index integer NOT NULL
    CHECK (operation_index BETWEEN 0 AND 63),
  ADD COLUMN operation text NOT NULL
    CHECK (operation ~ '^[a-z][a-z0-9_]{0,63}$'),
  ADD COLUMN response_bytes bytea NOT NULL
    CHECK (octet_length(response_bytes) BETWEEN 1 AND 1114112),
  ADD COLUMN created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  ADD CONSTRAINT nfs_replay_receipts_client_shape_check
    CHECK (client_id ~ '^[A-Za-z0-9_.:@-]+$'),
  ADD CONSTRAINT nfs_replay_receipts_pkey PRIMARY KEY (
    tenant_id,mount_session_id,nfs_session_id,slot_id,sequence_id,operation_index
  ),
  ADD CONSTRAINT nfs_replay_receipts_mount_session_fk
    FOREIGN KEY (tenant_id,mount_session_id)
    REFERENCES filebelt_mount.sessions(tenant_id,id),
  ADD CONSTRAINT nfs_replay_receipts_expiry_bound_check CHECK (
    expires_at>created_at AND expires_at<=created_at+interval '90 seconds'
  );
CREATE INDEX nfs_replay_receipts_expiry_index
  ON filebelt_mount.nfs_replay_receipts (expires_at);

CREATE FUNCTION filebelt_mount.enforce_nfs_replay_receipt()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,filebelt_mount
AS $$
BEGIN
  IF TG_OP='UPDATE' OR (TG_OP='DELETE' AND OLD.expires_at>statement_timestamp()) THEN
    RAISE EXCEPTION USING
      ERRCODE='55000',
      MESSAGE='NFS replay receipts are immutable';
  END IF;
  IF TG_OP='DELETE' THEN
    RETURN OLD;
  END IF;
  PERFORM 1
  FROM filebelt_mount.sessions AS session
  WHERE session.tenant_id=NEW.tenant_id
    AND session.id=NEW.mount_session_id
    AND session.protocol='nfs'
    AND session.gateway_epoch=NEW.gateway_epoch
    AND session.state IN ('active','draining')
    AND session.absolute_expires_at>statement_timestamp()
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE='23503',
      MESSAGE='NFS replay receipt requires a current bound mount session';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER nfs_replay_receipt_immutable
BEFORE INSERT OR UPDATE OR DELETE ON filebelt_mount.nfs_replay_receipts
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.enforce_nfs_replay_receipt();

CREATE TABLE filebelt_mount.nfs_feature_state (
  tenant_id uuid PRIMARY KEY REFERENCES public.tenants(id) ON DELETE CASCADE,
  state text NOT NULL DEFAULT 'disabled'
    CHECK (state IN ('disabled','preflight','active','draining')),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  manifest_generation bigint NOT NULL DEFAULT 1 CHECK (manifest_generation > 0),
  applied_manifest_generation bigint NOT NULL DEFAULT 0
    CHECK (applied_manifest_generation >= 0),
  applied_manifest_digest bytea
    CHECK (applied_manifest_digest IS NULL OR octet_length(applied_manifest_digest)=32),
  applied_gateway_id text,
  applied_gateway_epoch bigint CHECK (applied_gateway_epoch IS NULL OR applied_gateway_epoch>0),
  applied_export_ids bigint[] NOT NULL DEFAULT '{}',
  applied_export_generations bigint[] NOT NULL DEFAULT '{}',
  applied_root_handle_digests bytea[] NOT NULL DEFAULT '{}',
  restore_generation bigint NOT NULL DEFAULT 1 CHECK (restore_generation > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (applied_manifest_generation<=manifest_generation),
  CHECK ((applied_manifest_generation=0) = (applied_manifest_digest IS NULL)),
  CHECK ((applied_manifest_generation=0) = (applied_gateway_id IS NULL)),
  CHECK ((applied_manifest_generation=0) = (applied_gateway_epoch IS NULL)),
  CHECK (cardinality(applied_export_ids)=cardinality(applied_export_generations)),
  CHECK (cardinality(applied_export_ids)=cardinality(applied_root_handle_digests))
);

INSERT INTO filebelt_mount.nfs_feature_state (tenant_id)
SELECT id FROM public.tenants
ON CONFLICT (tenant_id) DO NOTHING;

CREATE FUNCTION filebelt_mount.seed_nfs_feature_state()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
BEGIN
  INSERT INTO filebelt_mount.nfs_feature_state (tenant_id)
  VALUES (NEW.id)
  ON CONFLICT (tenant_id) DO NOTHING;
  RETURN NEW;
END
$$;
CREATE TRIGGER nfs_feature_state_seed
AFTER INSERT ON public.tenants
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.seed_nfs_feature_state();

CREATE FUNCTION filebelt_mount.enforce_nfs_feature_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_feature_changed boolean;
  v_manifest_changed boolean;
  v_applied_manifest_changed boolean;
  v_restore_changed boolean;
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION USING
      ERRCODE='55000',
      MESSAGE='NFS tenant authority identity is immutable';
  END IF;

  v_feature_changed := NEW.state IS DISTINCT FROM OLD.state
    OR NEW.generation IS DISTINCT FROM OLD.generation;
  v_manifest_changed := NEW.manifest_generation IS DISTINCT FROM OLD.manifest_generation;
  v_applied_manifest_changed :=
    NEW.applied_manifest_generation IS DISTINCT FROM OLD.applied_manifest_generation
    OR NEW.applied_manifest_digest IS DISTINCT FROM OLD.applied_manifest_digest
    OR NEW.applied_gateway_id IS DISTINCT FROM OLD.applied_gateway_id
    OR NEW.applied_gateway_epoch IS DISTINCT FROM OLD.applied_gateway_epoch
    OR NEW.applied_export_ids IS DISTINCT FROM OLD.applied_export_ids
    OR NEW.applied_export_generations IS DISTINCT FROM OLD.applied_export_generations
    OR NEW.applied_root_handle_digests IS DISTINCT FROM OLD.applied_root_handle_digests;
  v_restore_changed := NEW.restore_generation IS DISTINCT FROM OLD.restore_generation;
  IF (v_feature_changed::integer+v_manifest_changed::integer
      +v_applied_manifest_changed::integer+v_restore_changed::integer)<>1 THEN
    RAISE EXCEPTION USING
      ERRCODE='23514',
      MESSAGE='change exactly one NFS tenant authority projection';
  END IF;

  IF v_feature_changed THEN
    IF NEW.manifest_generation IS DISTINCT FROM OLD.manifest_generation
       OR NEW.restore_generation IS DISTINCT FROM OLD.restore_generation
       OR v_applied_manifest_changed
       OR NEW.generation IS DISTINCT FROM OLD.generation+1
       OR NOT (CASE OLD.state
         WHEN 'disabled' THEN NEW.state='preflight'
         WHEN 'preflight' THEN NEW.state IN ('disabled','active')
         WHEN 'active' THEN NEW.state='draining'
         WHEN 'draining' THEN NEW.state='disabled'
         ELSE false
       END)
    THEN
      RAISE EXCEPTION USING
        ERRCODE='23514',
        MESSAGE='invalid NFS feature-state transition';
    END IF;
    IF NEW.state='active' THEN
      IF OLD.applied_manifest_generation<>OLD.manifest_generation
         OR OLD.applied_manifest_digest IS NULL THEN
        RAISE EXCEPTION USING
          ERRCODE='23514',
          MESSAGE='NFS activation requires an exact applied manifest acknowledgement';
      END IF;
      PERFORM 1
      FROM filebelt_mount.gateway_epochs AS gateway
      WHERE gateway.tenant_id=NEW.tenant_id
        AND gateway.protocol='nfs'
        AND gateway.gateway_id=OLD.applied_gateway_id
        AND gateway.epoch=OLD.applied_gateway_epoch
        AND NOT gateway.draining
        AND gateway.lease_expires_at>clock_timestamp()
      ORDER BY gateway.shard_key
      LIMIT 1
      FOR SHARE;
      IF NOT FOUND THEN
        RAISE EXCEPTION USING
          ERRCODE='23514',
          MESSAGE='NFS activation requires a fresh non-draining gateway lease';
      END IF;
      PERFORM 1
      FROM filebelt_mount.nfs_exports AS export
      JOIN public.nodes AS root
        ON root.tenant_id=export.tenant_id
       AND root.drive_id=export.drive_id
       AND root.parent_id IS NULL
       AND root.trash_root_id IS NULL
       AND root.kind='directory'
      WHERE export.tenant_id=NEW.tenant_id
        AND export.desired_state='active'
        AND export.applied_state='active'
        AND export.desired_generation=export.applied_generation
      ORDER BY export.export_id
      LIMIT 1
      FOR SHARE;
      IF NOT FOUND THEN
        RAISE EXCEPTION USING
          ERRCODE='23514',
          MESSAGE='NFS activation requires an applied active export';
      END IF;
    ELSIF NEW.state='draining' THEN
      PERFORM 1
      FROM filebelt_mount.gateway_epochs AS gateway
      WHERE gateway.tenant_id=NEW.tenant_id
        AND gateway.protocol='nfs'
        AND gateway.gateway_id=OLD.applied_gateway_id
        AND gateway.epoch=OLD.applied_gateway_epoch
        AND gateway.draining
        AND gateway.drain_deadline>clock_timestamp()
      FOR SHARE;
      IF NOT FOUND OR EXISTS (
        SELECT 1
        FROM filebelt_mount.sessions AS session
        WHERE session.tenant_id=NEW.tenant_id
          AND session.protocol='nfs'
          AND session.state IN ('active','draining')
          AND NOT EXISTS (
            SELECT 1
            FROM filebelt_mount.gateway_epochs AS gateway
            WHERE gateway.tenant_id=session.tenant_id
              AND gateway.protocol=session.protocol
              AND gateway.gateway_id=session.gateway_id
              AND gateway.epoch=session.gateway_epoch
              AND gateway.draining
              AND gateway.drain_deadline>clock_timestamp()
          )
      ) THEN
        RAISE EXCEPTION USING
          ERRCODE='23514',
          MESSAGE='NFS draining requires an explicit current gateway drain';
      END IF;
    ELSIF NEW.state='disabled' AND EXISTS (
      SELECT 1 FROM filebelt_mount.nfs_exports AS export
      WHERE export.tenant_id=NEW.tenant_id
        AND (
          export.desired_state<>'disabled'
          OR export.applied_state<>'disabled'
          OR export.desired_generation<>export.applied_generation
        )
    ) THEN
      RAISE EXCEPTION USING
        ERRCODE='23514',
        MESSAGE='NFS disable requires every export to be reconciled disabled';
    END IF;
  ELSIF v_manifest_changed THEN
    IF NEW.state IS DISTINCT FROM OLD.state
       OR NEW.generation IS DISTINCT FROM OLD.generation
       OR NEW.restore_generation IS DISTINCT FROM OLD.restore_generation
       OR v_applied_manifest_changed
       OR NEW.manifest_generation IS DISTINCT FROM OLD.manifest_generation+1
    THEN
      RAISE EXCEPTION USING
        ERRCODE='23514',
        MESSAGE='invalid NFS manifest-generation advance';
    END IF;
  ELSIF v_restore_changed THEN
    IF NEW.state IS DISTINCT FROM OLD.state
       OR NEW.generation IS DISTINCT FROM OLD.generation
       OR NEW.manifest_generation IS DISTINCT FROM OLD.manifest_generation
       OR NEW.restore_generation IS DISTINCT FROM OLD.restore_generation+1
    THEN
      RAISE EXCEPTION USING
        ERRCODE='23514',
        MESSAGE='invalid NFS restore-generation advance';
    END IF;
  ELSE
    IF NEW.state IS DISTINCT FROM OLD.state
       OR NEW.generation IS DISTINCT FROM OLD.generation
       OR NEW.manifest_generation IS DISTINCT FROM OLD.manifest_generation
       OR NEW.restore_generation IS DISTINCT FROM OLD.restore_generation
       OR NEW.applied_manifest_generation IS DISTINCT FROM NEW.manifest_generation
       OR NEW.applied_manifest_digest IS NULL
       OR length(NEW.applied_gateway_id) NOT BETWEEN 1 AND 255
       OR NEW.applied_gateway_epoch IS NULL
    THEN
      RAISE EXCEPTION USING
        ERRCODE='23514',
        MESSAGE='invalid NFS applied-manifest acknowledgement';
    END IF;
  END IF;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END
$$;
CREATE TRIGGER nfs_feature_state_transition
BEFORE UPDATE ON filebelt_mount.nfs_feature_state
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.enforce_nfs_feature_transition();

CREATE FUNCTION filebelt_mount.fence_nfs_feature_sessions()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
BEGIN
  IF NEW.state='draining' AND NEW.state IS DISTINCT FROM OLD.state THEN
    UPDATE filebelt_mount.sessions AS session
    SET state='draining',
        nfs_feature_generation=NEW.generation,
        idle_expires_at=LEAST(session.idle_expires_at,gateway.drain_deadline),
        absolute_expires_at=LEAST(session.absolute_expires_at,gateway.drain_deadline),
        last_activity_at=clock_timestamp()
    FROM filebelt_mount.gateway_epochs AS gateway
    WHERE session.tenant_id=NEW.tenant_id
      AND session.protocol='nfs'
      AND session.state IN ('active','draining')
      AND gateway.tenant_id=session.tenant_id
      AND gateway.protocol=session.protocol
      AND gateway.gateway_id=session.gateway_id
      AND gateway.epoch=session.gateway_epoch
      AND gateway.draining
      AND gateway.drain_deadline>clock_timestamp();
  ELSIF NEW.state='disabled' AND NEW.state IS DISTINCT FROM OLD.state THEN
    UPDATE filebelt_mount.sessions AS session
    SET state='closed',
        closed_at=clock_timestamp(),
        close_reason='nfs_feature_disabled',
        last_activity_at=clock_timestamp()
    WHERE session.tenant_id=NEW.tenant_id
      AND session.protocol='nfs'
      AND session.state IN ('active','draining');
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER nfs_feature_session_fence
AFTER UPDATE OF state ON filebelt_mount.nfs_feature_state
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.fence_nfs_feature_sessions();

-- Export IDs and pseudopaths are stable for the lifetime of the registry row.
-- IDs and paths are globally unique because one shared NFS listener renders
-- exports for multiple tenants. Removal is represented by a reconciled
-- disabled state, never by deleting and reusing an identifier.
CREATE TABLE filebelt_mount.nfs_exports (
  tenant_id uuid NOT NULL,
  drive_id uuid NOT NULL,
  export_id bigint NOT NULL CHECK (export_id > 0),
  export_path text NOT NULL,
  desired_state text NOT NULL DEFAULT 'disabled'
    CHECK (desired_state IN ('disabled','active','draining')),
  applied_state text NOT NULL DEFAULT 'disabled'
    CHECK (applied_state IN ('disabled','active','draining')),
  desired_generation bigint NOT NULL DEFAULT 1 CHECK (desired_generation > 0),
  applied_generation bigint NOT NULL DEFAULT 0 CHECK (applied_generation >= 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,drive_id),
  UNIQUE (export_id),
  UNIQUE (export_path),
  FOREIGN KEY (tenant_id,drive_id) REFERENCES public.drives(tenant_id,id),
  CHECK (export_path='/filebelt/' || drive_id::text),
  CHECK (applied_generation <= desired_generation)
);

CREATE FUNCTION filebelt_mount.enforce_nfs_export_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_desired_changed boolean;
  v_applied_changed boolean;
BEGIN
  IF TG_OP='INSERT' THEN
    NEW.export_path := '/filebelt/' || NEW.drive_id::text;
    IF NEW.desired_state<>'disabled'
       OR NEW.applied_state<>'disabled'
       OR NEW.desired_generation<>1
       OR NEW.applied_generation<>0
       OR NOT EXISTS (
         SELECT 1 FROM public.nodes AS root
         WHERE root.tenant_id=NEW.tenant_id
           AND root.drive_id=NEW.drive_id
           AND root.parent_id IS NULL
           AND root.trash_root_id IS NULL
           AND root.kind='directory'
           AND root.namespace_generation>0
       )
       OR NOT EXISTS (
         SELECT 1 FROM filebelt_mount.nfs_feature_state AS feature
         WHERE feature.tenant_id=NEW.tenant_id
           AND feature.state IN ('preflight','draining')
       )
    THEN
      RAISE EXCEPTION USING
        ERRCODE='23514',
        MESSAGE='new NFS exports must begin disabled and unapplied during preflight or drain';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION USING
      ERRCODE='55000',
      MESSAGE='NFS export registry rows are immutable';
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.drive_id IS DISTINCT FROM OLD.drive_id
     OR NEW.export_id IS DISTINCT FROM OLD.export_id
     OR NEW.export_path IS DISTINCT FROM OLD.export_path
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
  THEN
    RAISE EXCEPTION USING
      ERRCODE='55000',
      MESSAGE='NFS export identity is immutable';
  END IF;

  v_desired_changed := NEW.desired_state IS DISTINCT FROM OLD.desired_state
    OR NEW.desired_generation IS DISTINCT FROM OLD.desired_generation;
  v_applied_changed := NEW.applied_state IS DISTINCT FROM OLD.applied_state
    OR NEW.applied_generation IS DISTINCT FROM OLD.applied_generation;
  IF v_desired_changed = v_applied_changed THEN
    RAISE EXCEPTION USING
      ERRCODE='23514',
      MESSAGE='change exactly one NFS export generation projection';
  END IF;

  IF v_desired_changed THEN
    IF NEW.applied_state IS DISTINCT FROM OLD.applied_state
       OR NEW.applied_generation IS DISTINCT FROM OLD.applied_generation
       OR NEW.desired_generation IS DISTINCT FROM OLD.desired_generation+1
       OR NOT EXISTS (
         SELECT 1 FROM filebelt_mount.nfs_feature_state AS feature
         WHERE feature.tenant_id=NEW.tenant_id
           AND feature.state IN ('preflight','draining')
       )
       OR NOT (CASE OLD.desired_state
         WHEN 'disabled' THEN NEW.desired_state='active'
         WHEN 'active' THEN NEW.desired_state='draining'
         WHEN 'draining' THEN NEW.desired_state IN ('active','disabled')
         ELSE false
       END)
       OR (NEW.desired_state='disabled'
         AND NOT (
           OLD.applied_state='draining'
           AND OLD.applied_generation=OLD.desired_generation
         ))
    THEN
      RAISE EXCEPTION USING
        ERRCODE='23514',
        MESSAGE='invalid staged NFS export transition';
    END IF;
  ELSE
    IF NEW.desired_state IS DISTINCT FROM OLD.desired_state
       OR NEW.desired_generation IS DISTINCT FROM OLD.desired_generation
       OR NEW.applied_state IS DISTINCT FROM OLD.desired_state
       OR NEW.applied_generation IS DISTINCT FROM OLD.desired_generation
    THEN
      RAISE EXCEPTION USING
        ERRCODE='23514',
        MESSAGE='invalid NFS export reconciliation';
    END IF;
  END IF;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END
$$;
CREATE TRIGGER nfs_export_transition
BEFORE INSERT OR UPDATE OR DELETE ON filebelt_mount.nfs_exports
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.enforce_nfs_export_transition();

CREATE FUNCTION filebelt_mount.advance_nfs_manifest_generation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
BEGIN
  IF TG_OP='INSERT'
     OR NEW.desired_state IS DISTINCT FROM OLD.desired_state
     OR NEW.desired_generation IS DISTINCT FROM OLD.desired_generation THEN
    UPDATE filebelt_mount.nfs_feature_state
    SET manifest_generation=manifest_generation+1
    WHERE tenant_id=NEW.tenant_id;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER nfs_export_manifest_generation_insert
AFTER INSERT ON filebelt_mount.nfs_exports
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.advance_nfs_manifest_generation();
CREATE TRIGGER nfs_export_manifest_generation_update
AFTER UPDATE OF desired_state,desired_generation ON filebelt_mount.nfs_exports
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.advance_nfs_manifest_generation();

-- These rows are an append-only numeric/name registry. They intentionally
-- remain after a group stops receiving memberships so neither name nor GID can
-- acquire a different meaning later.
CREATE TABLE filebelt_mount.nfs_posix_groups (
  tenant_id uuid NOT NULL,
  group_id uuid NOT NULL,
  posix_name text NOT NULL
    CHECK (posix_name ~ '^[a-z_][a-z0-9_.-]{0,254}$'),
  projected_gid bigint NOT NULL CHECK (
    projected_gid BETWEEN 1 AND 4294967294 AND projected_gid<>65534
  ),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,group_id),
  UNIQUE (tenant_id,posix_name),
  UNIQUE (tenant_id,projected_gid),
  FOREIGN KEY (tenant_id,group_id) REFERENCES public.groups(tenant_id,id)
);

CREATE FUNCTION filebelt_mount.enforce_nfs_posix_group_immutability()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,filebelt_mount
AS $$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE='55000',
    MESSAGE='NFS POSIX group registry rows are immutable';
END
$$;
CREATE TRIGGER nfs_posix_group_immutable
BEFORE UPDATE OR DELETE ON filebelt_mount.nfs_posix_groups
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.enforce_nfs_posix_group_immutability();

ALTER TABLE filebelt_mount.nfs_principal_mappings
  ADD COLUMN posix_group_id uuid,
  ADD CONSTRAINT nfs_principal_mappings_posix_name_key
    UNIQUE (tenant_id,posix_name),
  ADD CONSTRAINT nfs_mapping_posix_group_fk
    FOREIGN KEY (tenant_id,posix_group_id)
    REFERENCES filebelt_mount.nfs_posix_groups(tenant_id,group_id),
  ADD CONSTRAINT nfs_mapping_root_principal_check CHECK (
    lower(split_part(kerberos_principal,'@',1))<>'root'
  ) NOT VALID,
  ADD CONSTRAINT nfs_active_principal_shape_check CHECK (
    revoked_at IS NOT NULL
    OR (
      kerberos_principal ~ '^[^/@[:space:]]+@[^/@[:space:]]+$'
      AND position(E'\\' in kerberos_principal)=0
      AND lower(split_part(kerberos_principal,'@',1))<>'root'
      AND posix_name ~ '^[a-z_][a-z0-9_.-]{0,254}$'
    )
  ),
  ADD CONSTRAINT nfs_active_projected_id_range_check CHECK (
    revoked_at IS NOT NULL
    OR (
      projected_uid BETWEEN 1 AND 4294967294
      AND projected_uid<>65534
      AND projected_gid BETWEEN 1 AND 4294967294
      AND projected_gid<>65534
      AND posix_group_id IS NOT NULL
    )
  );

-- The Kerberos name, FileBelt user, credential, POSIX user name, and UID form
-- one never-reassigned identity. A revoked legacy row may acquire its POSIX
-- name once when it is explicitly reactivated. Primary-group changes remain
-- generation-fenced but must reference a registered group containing the user.
CREATE FUNCTION filebelt_mount.enforce_nfs_mapping_projection()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,filebelt_mount
AS $$
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
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE='55000',
      MESSAGE='NFS user projection identity is immutable';
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
CREATE TRIGGER nfs_mapping_projection
BEFORE INSERT OR UPDATE OR DELETE
ON filebelt_mount.nfs_principal_mappings
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.enforce_nfs_mapping_projection();

-- Membership removal must be staged after revoking any mapping for which the
-- membership is the registered primary group. This keeps the invariant true
-- under direct SQL writers, not only repository methods.
CREATE FUNCTION filebelt_mount.protect_nfs_primary_group_membership()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,public,filebelt_mount
AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM filebelt_mount.nfs_principal_mappings AS mapping
    JOIN filebelt_mount.nfs_posix_groups AS posix_group
      ON posix_group.tenant_id=mapping.tenant_id
     AND posix_group.group_id=mapping.posix_group_id
    WHERE mapping.tenant_id=OLD.tenant_id
      AND posix_group.group_id=OLD.group_id
      AND mapping.principal_id=OLD.user_principal_id
      AND mapping.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE='23503',
      MESSAGE='revoke the active NFS mapping before removing its primary-group membership';
  END IF;
  RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END
$$;
CREATE TRIGGER nfs_primary_group_membership_backstop
BEFORE DELETE OR UPDATE OF tenant_id,group_id,user_principal_id
ON public.group_memberships
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.protect_nfs_primary_group_membership();

-- A gateway drain is an epoch-scoped, persisted fence. The current boot may
-- finish already-admitted work for at most five minutes, but Hello cannot
-- clear the drain. A later claim advances the epoch even when a StatefulSet
-- pod reuses the same stable gateway ID.
ALTER TABLE filebelt_mount.gateway_epochs
  ADD COLUMN drain_deadline timestamptz,
  ADD COLUMN drain_reason text;
UPDATE filebelt_mount.gateway_epochs
SET drain_deadline=statement_timestamp(),
    drain_reason='nfs_authority_migration_fence',
    updated_at=statement_timestamp()
WHERE draining;
ALTER TABLE filebelt_mount.gateway_epochs
  ADD CONSTRAINT mount_gateway_drain_projection_check CHECK (
    (NOT draining AND drain_deadline IS NULL AND drain_reason IS NULL)
    OR
    (draining AND drain_deadline IS NOT NULL
      AND length(drain_reason) BETWEEN 1 AND 64
      AND drain_deadline<=updated_at+interval '5 minutes')
  ),
  ADD CONSTRAINT mount_gateway_lease_bound_check CHECK (
    lease_expires_at<=updated_at+CASE protocol
      WHEN 'nfs' THEN interval '31 seconds'
      ELSE interval '21 seconds'
    END
  );

CREATE FUNCTION filebelt_mount.enforce_mount_gateway_epoch()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,filebelt_mount
AS $$
BEGIN
  NEW.updated_at := statement_timestamp();
  IF TG_OP='INSERT' THEN
    IF NEW.epoch<>1 OR NEW.draining OR NEW.drain_deadline IS NOT NULL
       OR NEW.drain_reason IS NOT NULL THEN
      RAISE EXCEPTION USING
        ERRCODE='23514',
        MESSAGE='new mount gateway epochs must begin at one without a drain';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.protocol IS DISTINCT FROM OLD.protocol
     OR NEW.shard_key IS DISTINCT FROM OLD.shard_key THEN
    RAISE EXCEPTION USING
      ERRCODE='55000',
      MESSAGE='mount gateway epoch identity is immutable';
  END IF;

  IF OLD.draining THEN
    IF NEW.draining
       OR OLD.drain_deadline>statement_timestamp()
       OR NEW.epoch IS DISTINCT FROM OLD.epoch+1
       OR NEW.drain_deadline IS NOT NULL
       OR NEW.drain_reason IS NOT NULL THEN
      RAISE EXCEPTION USING
        ERRCODE='23514',
        MESSAGE='a draining mount gateway requires an expired deadline and a new epoch';
    END IF;
  ELSIF NEW.draining THEN
    IF NEW.gateway_id IS DISTINCT FROM OLD.gateway_id
       OR NEW.epoch IS DISTINCT FROM OLD.epoch
       OR NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at
       OR NEW.drain_deadline<=statement_timestamp()
       OR NEW.drain_deadline>statement_timestamp()+interval '5 minutes'
       OR length(NEW.drain_reason) NOT BETWEEN 1 AND 64 THEN
      RAISE EXCEPTION USING
        ERRCODE='23514',
        MESSAGE='invalid mount gateway drain';
    END IF;
  ELSE
    IF NEW.drain_deadline IS NOT NULL OR NEW.drain_reason IS NOT NULL
       OR (OLD.lease_expires_at>statement_timestamp() AND (
         NEW.gateway_id IS DISTINCT FROM OLD.gateway_id
         OR NEW.epoch IS DISTINCT FROM OLD.epoch
       ))
       OR (OLD.lease_expires_at<=statement_timestamp()
         AND NEW.epoch IS DISTINCT FROM OLD.epoch+1) THEN
      RAISE EXCEPTION USING
        ERRCODE='23514',
        MESSAGE='invalid mount gateway epoch claim';
    END IF;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER mount_gateway_epoch_transition
BEFORE INSERT OR UPDATE ON filebelt_mount.gateway_epochs
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.enforce_mount_gateway_epoch();

ALTER TABLE filebelt_mount.sessions
  ADD COLUMN nfs_gss_binding_digest bytea
    CHECK (nfs_gss_binding_digest IS NULL OR octet_length(nfs_gss_binding_digest)=32),
  ADD COLUMN nfs_mapping_generation bigint
    CHECK (nfs_mapping_generation IS NULL OR nfs_mapping_generation > 0),
  ADD COLUMN nfs_feature_generation bigint
    CHECK (nfs_feature_generation IS NULL OR nfs_feature_generation > 0),
  ADD COLUMN nfs_restore_generation bigint
    CHECK (nfs_restore_generation IS NULL OR nfs_restore_generation > 0),
  ADD CONSTRAINT mount_active_nfs_session_projection_check CHECK (
    protocol<>'nfs'
    OR state NOT IN ('active','draining')
    OR (
      nfs_gss_binding_digest IS NOT NULL
      AND nfs_mapping_generation IS NOT NULL
      AND nfs_feature_generation IS NOT NULL
      AND nfs_restore_generation IS NOT NULL
    )
  );
CREATE UNIQUE INDEX mount_nfs_session_context_active_index
  ON filebelt_mount.sessions (
    tenant_id,credential_id,gateway_id,gateway_epoch,source_address,
    nfs_gss_binding_digest
  )
  WHERE protocol='nfs' AND state IN ('active','draining');

-- Preserve the least-privilege boundary for the existing SMB/FTPS session
-- path: VFS may create only a mount-session principal, not arbitrary public
-- principals. The surrounding Rust transaction inserts the matching session.
CREATE FUNCTION filebelt_mount.create_session_principal(
  p_tenant_id uuid,
  p_principal_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER') THEN
    RAISE EXCEPTION USING
      ERRCODE='42501',
      MESSAGE='caller is not a FileBelt VFS database principal';
  END IF;
  INSERT INTO public.principals (tenant_id,id,kind)
  VALUES (p_tenant_id,p_principal_id,'mount_session');
END
$$;

-- Resolve the exact RPCSEC_GSS name, validate the tenant-local NFS feature and
-- gateway lease, and create the session principal/session as one privileged
-- database operation. Inputs never include an AUTH_SYS identity or keytab.
CREATE FUNCTION filebelt_mount.create_nfs_session(
  p_tenant_id uuid,
  p_kerberos_principal text,
  p_gss_binding_digest bytea,
  p_gateway_id text,
  p_gateway_epoch bigint,
  p_source_address inet,
  p_gss_expires_at timestamptz,
  p_session_id uuid,
  p_session_principal_id uuid
)
RETURNS TABLE (
  session_id uuid,
  user_principal_id uuid,
  credential_id uuid,
  posix_name text,
  posix_group_id uuid,
  primary_group_name text,
  projected_uid bigint,
  projected_gid bigint,
  mapping_generation bigint,
  feature_generation bigint,
  manifest_generation bigint,
  restore_generation bigint,
  credential_generation bigint,
  authorization_generation bigint,
  membership_generation bigint,
  read_only boolean,
  absolute_expires_at_unix_seconds bigint,
  allowed_drive_ids uuid[],
  allowed_export_ids bigint[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_mapping record;
  v_existing record;
  v_allowed_drive_ids uuid[];
  v_allowed_export_ids bigint[];
  v_return_session_id uuid;
  v_effective_expires_at timestamptz;
  v_reuse_existing boolean := false;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER') THEN
    RAISE EXCEPTION USING
      ERRCODE='42501',
      MESSAGE='caller is not a FileBelt VFS database principal';
  END IF;
  IF p_kerberos_principal IS NULL
     OR p_kerberos_principal !~ '^[^/@[:space:]]+@[^/@[:space:]]+$'
     OR position(E'\\' in p_kerberos_principal)>0
     OR lower(split_part(p_kerberos_principal,'@',1))='root'
     OR length(p_kerberos_principal) > 512
     OR p_gss_binding_digest IS NULL
     OR octet_length(p_gss_binding_digest) <> 32
     OR p_gateway_id IS NULL
     OR length(p_gateway_id) NOT BETWEEN 1 AND 255
     OR p_gateway_epoch <= 0
     OR p_source_address IS NULL
     OR p_gss_expires_at IS NULL
     OR p_gss_expires_at='infinity'::timestamptz
     OR p_gss_expires_at<=clock_timestamp()
  THEN
    RAISE EXCEPTION USING
      ERRCODE='22023',
      MESSAGE='invalid NFS session projection input';
  END IF;

  SELECT mapping.principal_id,
         mapping.credential_id,
         mapping.posix_name,
         mapping.posix_group_id,
         posix_group.posix_name AS primary_group_name,
         mapping.projected_uid,
         mapping.projected_gid,
         mapping.generation AS mapping_generation,
         feature.generation AS feature_generation,
         feature.manifest_generation,
         feature.restore_generation,
         credential.credential_generation,
         credential.authorization_generation,
         principal.generation AS membership_generation,
         credential.read_only,
         credential.allowed_drive_ids
  INTO v_mapping
  FROM filebelt_mount.nfs_principal_mappings AS mapping
  JOIN filebelt_mount.credentials AS credential
    ON credential.tenant_id=mapping.tenant_id
   AND credential.id=mapping.credential_id
   AND credential.principal_id=mapping.principal_id
  JOIN filebelt_mount.policies AS policy
    ON policy.tenant_id=credential.tenant_id
   AND policy.principal_id=credential.principal_id
   AND policy.protocol='nfs'
  JOIN public.principals AS principal
    ON principal.tenant_id=mapping.tenant_id
   AND principal.id=mapping.principal_id
  JOIN public.users AS user_account
    ON user_account.tenant_id=principal.tenant_id
   AND user_account.principal_id=principal.id
  JOIN filebelt_mount.nfs_posix_groups AS posix_group
    ON posix_group.tenant_id=mapping.tenant_id
   AND posix_group.group_id=mapping.posix_group_id
   AND posix_group.projected_gid=mapping.projected_gid
  JOIN public.group_memberships AS membership
    ON membership.tenant_id=mapping.tenant_id
   AND membership.group_id=posix_group.group_id
   AND membership.user_principal_id=mapping.principal_id
  JOIN filebelt_mount.nfs_feature_state AS feature
    ON feature.tenant_id=mapping.tenant_id
   AND feature.state='active'
   AND feature.applied_manifest_generation=feature.manifest_generation
   AND feature.applied_manifest_digest IS NOT NULL
   AND feature.applied_gateway_id=p_gateway_id
   AND feature.applied_gateway_epoch=p_gateway_epoch
  JOIN filebelt_mount.gateway_epochs AS gateway
    ON gateway.tenant_id=mapping.tenant_id
   AND gateway.protocol='nfs'
   AND gateway.gateway_id=p_gateway_id
   AND gateway.epoch=p_gateway_epoch
   AND NOT gateway.draining
   AND gateway.lease_expires_at>clock_timestamp()
  WHERE mapping.tenant_id=p_tenant_id
    AND mapping.kerberos_principal=p_kerberos_principal
    AND mapping.revoked_at IS NULL
    AND credential.protocol='nfs'
    AND credential.verifier_kind='kerberos_principal'
    AND credential.expires_at='infinity'::timestamptz
    AND credential.revoked_at IS NULL
    AND policy.enabled
    AND principal.kind='user'
    AND principal.disabled_at IS NULL
    AND user_account.status='active'
  FOR UPDATE OF mapping;

  IF NOT FOUND THEN
    RETURN;
  END IF;

  SELECT COALESCE(array_agg(export.drive_id ORDER BY export.drive_id),'{}'::uuid[]),
         COALESCE(array_agg(export.export_id ORDER BY export.export_id),'{}'::bigint[])
  INTO v_allowed_drive_ids,v_allowed_export_ids
  FROM filebelt_mount.nfs_exports AS export
  JOIN public.nodes AS root
    ON root.tenant_id=export.tenant_id
   AND root.drive_id=export.drive_id
   AND root.parent_id IS NULL
   AND root.trash_root_id IS NULL
   AND root.kind='directory'
  WHERE export.tenant_id=p_tenant_id
    AND export.drive_id=ANY(v_mapping.allowed_drive_ids)
    AND export.desired_state='active'
    AND export.applied_state='active'
    AND export.applied_generation=export.desired_generation;
  IF cardinality(v_allowed_drive_ids)=0 THEN
    RETURN;
  END IF;

  SELECT session.id,
         session.session_principal_id,
         session.credential_generation,
         session.authorization_generation,
         session.membership_generation,
         session.nfs_mapping_generation,
         session.nfs_feature_generation,
         session.nfs_restore_generation,
         session.idle_expires_at,
         session.absolute_expires_at
  INTO v_existing
  FROM filebelt_mount.sessions AS session
  WHERE session.tenant_id=p_tenant_id
    AND session.credential_id=v_mapping.credential_id
    AND session.protocol='nfs'
    AND session.gateway_id=p_gateway_id
    AND session.gateway_epoch=p_gateway_epoch
    AND session.source_address=p_source_address
    AND session.nfs_gss_binding_digest=p_gss_binding_digest
    AND session.state IN ('active','draining')
  FOR UPDATE;
  v_reuse_existing := FOUND;
  IF v_reuse_existing AND (
    v_existing.credential_generation IS DISTINCT FROM v_mapping.credential_generation
    OR v_existing.authorization_generation IS DISTINCT FROM v_mapping.authorization_generation
    OR v_existing.membership_generation IS DISTINCT FROM v_mapping.membership_generation
    OR v_existing.nfs_mapping_generation IS DISTINCT FROM v_mapping.mapping_generation
    OR v_existing.nfs_feature_generation IS DISTINCT FROM v_mapping.feature_generation
    OR v_existing.nfs_restore_generation IS DISTINCT FROM v_mapping.restore_generation
    OR v_existing.idle_expires_at<=clock_timestamp()
    OR v_existing.absolute_expires_at<=clock_timestamp()
  ) THEN
    UPDATE filebelt_mount.sessions
    SET state='closed',closed_at=clock_timestamp(),
        close_reason='nfs_authentication_context_stale'
    WHERE tenant_id=p_tenant_id AND id=v_existing.id;
    v_reuse_existing := false;
  END IF;

  IF NOT v_reuse_existing THEN
    v_effective_expires_at := LEAST(
      clock_timestamp()+interval '4 hours',p_gss_expires_at
    );
    INSERT INTO public.principals (tenant_id,id,kind)
    VALUES (p_tenant_id,p_session_principal_id,'mount_session');
    INSERT INTO filebelt_mount.sessions (
      tenant_id,id,session_principal_id,user_principal_id,credential_id,protocol,
      gateway_id,gateway_epoch,source_address,credential_generation,
      authorization_generation,membership_generation,idle_expires_at,
      absolute_expires_at,nfs_gss_binding_digest,nfs_mapping_generation,
      nfs_feature_generation,nfs_restore_generation
    ) VALUES (
      p_tenant_id,p_session_id,p_session_principal_id,v_mapping.principal_id,
      v_mapping.credential_id,'nfs',p_gateway_id,p_gateway_epoch,p_source_address,
      v_mapping.credential_generation,v_mapping.authorization_generation,
      v_mapping.membership_generation,
      LEAST(clock_timestamp()+interval '15 minutes',v_effective_expires_at),
      v_effective_expires_at,
      p_gss_binding_digest,
      v_mapping.mapping_generation,v_mapping.feature_generation,
      v_mapping.restore_generation
    );
    v_return_session_id := p_session_id;
  ELSE
    v_return_session_id := v_existing.id;
    v_effective_expires_at := LEAST(
      v_existing.absolute_expires_at,
      clock_timestamp()+interval '4 hours',
      p_gss_expires_at
    );
    UPDATE filebelt_mount.sessions
    SET last_activity_at=clock_timestamp(),
        absolute_expires_at=v_effective_expires_at,
        idle_expires_at=LEAST(
          clock_timestamp()+interval '15 minutes',
          v_effective_expires_at
        )
    WHERE tenant_id=p_tenant_id AND id=v_return_session_id;
  END IF;
  UPDATE filebelt_mount.credentials
  SET last_used_at=clock_timestamp()
  WHERE tenant_id=p_tenant_id AND id=v_mapping.credential_id;

  RETURN QUERY SELECT
    v_return_session_id::uuid,
    v_mapping.principal_id::uuid,
    v_mapping.credential_id::uuid,
    v_mapping.posix_name::text,
    v_mapping.posix_group_id::uuid,
    v_mapping.primary_group_name::text,
    v_mapping.projected_uid::bigint,
    v_mapping.projected_gid::bigint,
    v_mapping.mapping_generation::bigint,
    v_mapping.feature_generation::bigint,
    v_mapping.manifest_generation::bigint,
    v_mapping.restore_generation::bigint,
    v_mapping.credential_generation::bigint,
    v_mapping.authorization_generation::bigint,
    v_mapping.membership_generation::bigint,
    v_mapping.read_only::boolean,
    floor(extract(epoch FROM v_effective_expires_at))::bigint,
    v_allowed_drive_ids::uuid[],
    v_allowed_export_ids::bigint[];
END
$$;

-- Disaster-restore filehandle fencing is recovery-only and can advance only
-- while NFS is disabled. The state transition fence guarantees that no live
-- NFS session can survive into the new restore generation.
CREATE FUNCTION filebelt_mount.advance_nfs_restore_generation(
  p_tenant_id uuid,
  p_expected_generation bigint
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_state text;
  v_generation bigint;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_recovery','MEMBER') THEN
    RAISE EXCEPTION USING
      ERRCODE='42501',
      MESSAGE='caller is not a FileBelt recovery database principal';
  END IF;
  SELECT feature.state
  INTO v_state
  FROM filebelt_mount.nfs_feature_state AS feature
  WHERE feature.tenant_id=p_tenant_id
    AND feature.restore_generation=p_expected_generation
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE='40001',
      MESSAGE='stale NFS restore generation';
  END IF;
  IF v_state<>'disabled' OR EXISTS (
    SELECT 1 FROM filebelt_mount.sessions AS session
    WHERE session.tenant_id=p_tenant_id
      AND session.protocol='nfs'
      AND session.state IN ('active','draining')
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE='55000',
      MESSAGE='disable and fence NFS before advancing the restore generation';
  END IF;
  UPDATE filebelt_mount.nfs_feature_state
  SET restore_generation=restore_generation+1
  WHERE tenant_id=p_tenant_id
  RETURNING restore_generation INTO v_generation;
  INSERT INTO public.audit_events (
    tenant_id,id,resource_id,action,outcome,reason_code,privacy_visible,details
  ) VALUES (
    p_tenant_id,gen_random_uuid(),p_tenant_id,
    'mount.nfs.restore_generation.advance','allowed','recovery_restore_fence',false,
    jsonb_build_object('restore_generation',v_generation)
  );
  RETURN v_generation;
END
$$;

-- A sessionless GatewayReconcile acknowledges one complete desired manifest,
-- never one administrator-selected export row. PostgreSQL validates the exact
-- boot/epoch and sorted export identity/generation set before advancing every
-- applied projection and the tenant-wide acknowledgement in one transaction.
CREATE FUNCTION filebelt_mount.reconcile_nfs_export_manifest(
  p_tenant_id uuid,
  p_gateway_id text,
  p_gateway_epoch bigint,
  p_feature_generation bigint,
  p_manifest_generation bigint,
  p_manifest_digest bytea,
  p_export_ids bigint[],
  p_export_generations bigint[],
  p_root_handle_digests bytea[]
)
RETURNS TABLE (
  applied_manifest_generation bigint,
  applied_manifest_digest bytea,
  applied_gateway_id text,
  applied_gateway_epoch bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_feature record;
  v_expected_export_ids bigint[];
  v_expected_export_generations bigint[];
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER')
     OR p_gateway_id IS NULL
     OR length(p_gateway_id) NOT BETWEEN 1 AND 255
     OR p_gateway_epoch<=0
     OR p_feature_generation<=0
     OR p_manifest_generation<=0
     OR p_manifest_digest IS NULL
     OR octet_length(p_manifest_digest)<>32
     OR p_export_ids IS NULL
     OR p_export_generations IS NULL
     OR p_root_handle_digests IS NULL
     OR cardinality(p_export_ids)<>cardinality(p_export_generations)
     OR cardinality(p_export_ids)<>cardinality(p_root_handle_digests)
     OR EXISTS (
       SELECT 1 FROM unnest(p_root_handle_digests) AS digest
       WHERE digest IS NULL OR octet_length(digest)<>32
     )
     OR EXISTS (
       SELECT 1 FROM generate_subscripts(p_export_ids,1) AS position_index
       WHERE position_index>1
         AND p_export_ids[position_index]<=p_export_ids[position_index-1]
     )
  THEN
    RAISE EXCEPTION USING
      ERRCODE='22023',
      MESSAGE='invalid NFS manifest acknowledgement';
  END IF;

  SELECT feature.state,feature.generation,feature.manifest_generation
  INTO v_feature
  FROM filebelt_mount.nfs_feature_state AS feature
  WHERE feature.tenant_id=p_tenant_id
    AND feature.generation=p_feature_generation
    AND feature.manifest_generation=p_manifest_generation
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE='40001',
      MESSAGE='stale NFS desired manifest';
  END IF;

  PERFORM 1
  FROM filebelt_mount.gateway_epochs AS gateway
  WHERE gateway.tenant_id=p_tenant_id
    AND gateway.protocol='nfs'
    AND gateway.gateway_id=p_gateway_id
    AND gateway.epoch=p_gateway_epoch
    AND (
      (v_feature.state IN ('preflight','active')
        AND NOT gateway.draining
        AND gateway.lease_expires_at>statement_timestamp())
      OR
      (v_feature.state='draining'
        AND gateway.draining
        AND gateway.drain_deadline>statement_timestamp())
    )
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE='40001',
      MESSAGE='stale NFS gateway manifest acknowledgement';
  END IF;

  IF EXISTS (
    SELECT 1 FROM filebelt_mount.nfs_exports AS export
    WHERE export.tenant_id=p_tenant_id
      AND export.desired_state='active'
      AND NOT EXISTS (
        SELECT 1 FROM public.nodes AS root
        WHERE root.tenant_id=export.tenant_id
          AND root.drive_id=export.drive_id
          AND root.parent_id IS NULL
          AND root.trash_root_id IS NULL
          AND root.kind='directory'
          AND root.namespace_generation>0
      )
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE='23503',
      MESSAGE='NFS desired manifest contains an export without a live root';
  END IF;

  SELECT COALESCE(array_agg(export.export_id ORDER BY export.export_id),'{}'::bigint[]),
         COALESCE(array_agg(export.desired_generation ORDER BY export.export_id),'{}'::bigint[])
  INTO v_expected_export_ids,v_expected_export_generations
  FROM filebelt_mount.nfs_exports AS export
  WHERE export.tenant_id=p_tenant_id
    AND export.desired_state='active';
  IF p_export_ids IS DISTINCT FROM v_expected_export_ids
     OR p_export_generations IS DISTINCT FROM v_expected_export_generations THEN
    RAISE EXCEPTION USING
      ERRCODE='40001',
      MESSAGE='NFS manifest acknowledgement does not match the desired export set';
  END IF;

  UPDATE filebelt_mount.nfs_exports AS export
  SET applied_state=export.desired_state,
      applied_generation=export.desired_generation
  WHERE export.tenant_id=p_tenant_id
    AND (
      export.applied_state IS DISTINCT FROM export.desired_state
      OR export.applied_generation IS DISTINCT FROM export.desired_generation
    );
  UPDATE filebelt_mount.nfs_feature_state
  SET applied_manifest_generation=p_manifest_generation,
      applied_manifest_digest=p_manifest_digest,
      applied_gateway_id=p_gateway_id,
      applied_gateway_epoch=p_gateway_epoch,
      applied_export_ids=p_export_ids,
      applied_export_generations=p_export_generations,
      applied_root_handle_digests=p_root_handle_digests
  WHERE tenant_id=p_tenant_id;

  RETURN QUERY SELECT
    p_manifest_generation,
    p_manifest_digest,
    p_gateway_id,
    p_gateway_epoch;
END
$$;

REVOKE ALL ON FUNCTION filebelt_mount.seed_nfs_feature_state() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.enforce_nfs_replay_receipt() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.enforce_nfs_feature_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.fence_nfs_feature_sessions() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.enforce_nfs_export_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.advance_nfs_manifest_generation() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.enforce_nfs_posix_group_immutability() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.enforce_nfs_mapping_projection() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.protect_nfs_primary_group_membership() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.enforce_mount_gateway_epoch() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.create_session_principal(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.create_nfs_session(
  uuid,text,bytea,text,bigint,inet,timestamptz,uuid,uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.advance_nfs_restore_generation(uuid,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.reconcile_nfs_export_manifest(
  uuid,text,bigint,bigint,bigint,bytea,bigint[],bigint[],bytea[]
) FROM PUBLIC;
