-- SPDX-License-Identifier: Apache-2.0

-- NFS writer, replay, conflict, and restore-fencing authority. This builds
-- on the common namespace and identity projection established by migration
-- 000013 and keeps byte-plane state transitions PostgreSQL-authoritative.

ALTER TABLE public.file_versions DROP CONSTRAINT file_versions_origin_kind_check;
ALTER TABLE public.file_versions ADD CONSTRAINT file_versions_origin_kind_check
  CHECK (origin_kind IN (
    'upload','markdown_save','collaboration_checkpoint','import','restore',
    'external_document','nfs'
  ));

-- A never-finalized NFS staging object has no trustworthy whole-payload
-- digest. Once its bytes have been durably deleted, retaining a fabricated
-- digest would be worse than retaining NULL. Finalized and live payload states
-- continue to require an integrity digest.
ALTER TABLE public.payload_objects DROP CONSTRAINT payload_objects_check;
ALTER TABLE public.payload_objects ADD CONSTRAINT payload_objects_integrity_digest_check
  CHECK (state NOT IN (
    'finalized','referenced','delete_intent','deleting','quarantining','quarantined'
  ) OR blake3 IS NOT NULL);

ALTER TABLE filebelt_mount.write_sessions DROP CONSTRAINT write_sessions_state_check;
ALTER TABLE filebelt_mount.write_sessions ADD CONSTRAINT write_sessions_state_check
  CHECK (state IN (
    'open','flushing','committing','committed','conflicted',
    'aborting','aborted','expired'
  ));
DO $$
DECLARE
  v_tenant_id uuid;
  v_drive_id uuid;
  v_node_id uuid;
  v_writer_ids text;
BEGIN
  SELECT writer.tenant_id,writer.drive_id,writer.node_id,
         string_agg(writer.id::text,',' ORDER BY writer.id)
  INTO v_tenant_id,v_drive_id,v_node_id,v_writer_ids
  FROM filebelt_mount.write_sessions AS writer
  WHERE writer.state IN ('open','flushing','committing','aborting')
  GROUP BY writer.tenant_id,writer.drive_id,writer.node_id
  HAVING count(*)>1
  ORDER BY writer.tenant_id,writer.drive_id,writer.node_id
  LIMIT 1;
  IF FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE='55000',
      MESSAGE='cannot enforce one active mount writer per node',
      DETAIL=format(
        'tenant_id=%s drive_id=%s node_id=%s writer_ids=%s',
        v_tenant_id,v_drive_id,v_node_id,v_writer_ids
      ),
      HINT='Complete or explicitly clean up the legacy aborting writer before retrying migration 000014.';
  END IF;
END
$$;
DROP INDEX filebelt_mount.mount_one_active_writer_per_node;
CREATE UNIQUE INDEX mount_one_active_writer_per_node
  ON filebelt_mount.write_sessions (tenant_id,drive_id,node_id)
  WHERE state IN ('open','flushing','committing','aborting');

-- A mount session retains the exact export/manifest authority authenticated by
-- its RPCSEC_GSS context. Current export rows are still rechecked for live
-- admission, but cannot silently broaden an already authenticated session.
CREATE FUNCTION filebelt_mount.sorted_unique_positive_bigints(p_values bigint[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path=pg_catalog
AS $$
  SELECT p_values=ARRAY(
    SELECT DISTINCT value FROM unnest(p_values) AS value
    WHERE value>0 ORDER BY value
  )
$$;
UPDATE filebelt_mount.sessions
SET state='closed',closed_at=clock_timestamp(),
    close_reason='nfs_manifest_session_cutover',last_activity_at=clock_timestamp()
WHERE protocol='nfs' AND state IN ('active','draining');

-- NFSv4.1 replay identity is sequence-based, not time-window based. Retain the
-- current response set for every slot through the bound mount-session lifetime
-- and atomically replace it when that slot observes any higher sequence
-- (locally handled compounds can create gaps). This bounds storage to at most
-- one compound response set per slot
-- while preserving restart-safe replay for the full 15-minute/4-hour session.
DROP TRIGGER nfs_replay_receipt_immutable
  ON filebelt_mount.nfs_replay_receipts;
DELETE FROM filebelt_mount.nfs_replay_receipts;
ALTER TABLE filebelt_mount.nfs_replay_receipts
  DROP CONSTRAINT nfs_replay_receipts_expiry_bound_check,
  ADD CONSTRAINT nfs_replay_receipts_expiry_check CHECK (expires_at>created_at);
CREATE TABLE filebelt_mount.nfs_replay_slots (
  tenant_id uuid NOT NULL,
  mount_session_id uuid NOT NULL,
  nfs_session_id text NOT NULL
    CHECK (length(nfs_session_id) BETWEEN 1 AND 255)
    CHECK (nfs_session_id ~ '^[A-Za-z0-9_.:@-]+$'),
  slot_id integer NOT NULL CHECK (slot_id BETWEEN 0 AND 1023),
  client_id text NOT NULL
    CHECK (length(client_id) BETWEEN 1 AND 255)
    CHECK (client_id ~ '^[A-Za-z0-9_.:@-]+$'),
  current_sequence_id bigint NOT NULL CHECK (current_sequence_id>0),
  max_operation_index integer NOT NULL CHECK (max_operation_index BETWEEN 0 AND 63),
  gateway_epoch bigint NOT NULL CHECK (gateway_epoch>0),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (tenant_id,mount_session_id,nfs_session_id,slot_id),
  FOREIGN KEY (tenant_id,mount_session_id)
    REFERENCES filebelt_mount.sessions(tenant_id,id) ON DELETE CASCADE
);
CREATE TABLE filebelt_mount.nfs_pending_protocol_operations (
  tenant_id uuid NOT NULL,
  mount_session_id uuid NOT NULL,
  client_id text NOT NULL
    CHECK (length(client_id) BETWEEN 1 AND 255)
    CHECK (client_id ~ '^[A-Za-z0-9_.:@-]+$'),
  nfs_session_id text NOT NULL
    CHECK (length(nfs_session_id) BETWEEN 1 AND 255)
    CHECK (nfs_session_id ~ '^[A-Za-z0-9_.:@-]+$'),
  slot_id integer NOT NULL CHECK (slot_id BETWEEN 0 AND 1023),
  sequence_id bigint NOT NULL CHECK (sequence_id>0),
  operation_index integer NOT NULL CHECK (operation_index BETWEEN 0 AND 63),
  protocol_operation text NOT NULL
    CHECK (length(protocol_operation) BETWEEN 1 AND 64)
    CHECK (protocol_operation ~ '^[A-Za-z0-9_.:@-]+$'),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
  gateway_epoch bigint NOT NULL CHECK (gateway_epoch>0),
  protocol_operation_id uuid NOT NULL,
  write_session_id uuid NOT NULL,
  capability_id uuid NOT NULL,
  nonce_digest bytea NOT NULL CHECK (octet_length(nonce_digest)=32),
  claims_digest bytea NOT NULL CHECK (octet_length(claims_digest)=32),
  io_operation text NOT NULL CHECK (io_operation IN (
    'write_data','hole_deallocate','allocate','seek_data','seek_hole',
    'flush','finalize','abort','delete_staging'
  )),
  operation_id uuid,
  content_blake3 bytea CHECK (
    content_blake3 IS NULL OR octet_length(content_blake3)=32
  ),
  range_start bigint,
  range_end bigint,
  fencing_token bigint NOT NULL CHECK (fencing_token>0),
  capability_expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (
    tenant_id,mount_session_id,nfs_session_id,slot_id,sequence_id,operation_index
  ),
  UNIQUE (tenant_id,capability_id),
  UNIQUE (tenant_id,protocol_operation_id),
  UNIQUE (tenant_id,write_session_id),
  FOREIGN KEY (tenant_id,mount_session_id)
    REFERENCES filebelt_mount.sessions(tenant_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,write_session_id)
    REFERENCES filebelt_mount.write_sessions(tenant_id,id),
  CHECK ((operation_id IS NOT NULL)=(io_operation IN (
    'write_data','hole_deallocate','allocate','seek_data','seek_hole'
  ))),
  CHECK ((range_start IS NOT NULL AND range_end IS NOT NULL)
    =(operation_id IS NOT NULL)),
  CHECK (range_start IS NULL OR (range_start>=0 AND range_end>=range_start)),
  CHECK ((io_operation='write_data')=(content_blake3 IS NOT NULL)),
  CHECK (capability_expires_at>created_at),
  CHECK (expires_at>created_at)
);
CREATE INDEX nfs_pending_protocol_operations_expiry_index
  ON filebelt_mount.nfs_pending_protocol_operations (expires_at);
ALTER TABLE filebelt_mount.nfs_replay_receipts
  ADD CONSTRAINT nfs_replay_receipts_slot_fk FOREIGN KEY (
    tenant_id,mount_session_id,nfs_session_id,slot_id
  ) REFERENCES filebelt_mount.nfs_replay_slots (
    tenant_id,mount_session_id,nfs_session_id,slot_id
  ) ON DELETE CASCADE;

CREATE FUNCTION filebelt_mount.prepare_nfs_replay_sequence(
  p_tenant_id uuid,
  p_mount_session_id uuid,
  p_client_id text,
  p_nfs_session_id text,
  p_slot_id integer,
  p_sequence_id bigint,
  p_operation_index integer,
  p_gateway_epoch bigint
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_slot filebelt_mount.nfs_replay_slots%ROWTYPE;
  v_pending filebelt_mount.nfs_pending_protocol_operations%ROWTYPE;
  v_pending_found boolean := false;
  v_slot_found boolean;
  v_receipt_exists boolean;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER')
     OR p_client_id !~ '^[A-Za-z0-9_.:@-]{1,255}$'
     OR p_nfs_session_id !~ '^[A-Za-z0-9_.:@-]{1,255}$'
     OR p_slot_id NOT BETWEEN 0 AND 1023 OR p_sequence_id<=0
     OR p_operation_index NOT BETWEEN 0 AND 63 OR p_gateway_epoch<=0 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS replay sequence caller';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    p_tenant_id::text || ':' || p_mount_session_id::text || ':' ||
    p_nfs_session_id || ':' || p_slot_id::text,0
  ));
  SELECT * INTO v_pending
  FROM filebelt_mount.nfs_pending_protocol_operations AS pending
  WHERE pending.tenant_id=p_tenant_id
    AND pending.mount_session_id=p_mount_session_id
    AND pending.nfs_session_id=p_nfs_session_id
    AND pending.slot_id=p_slot_id
  FOR UPDATE;
  v_pending_found := FOUND;
  IF FOUND AND (
    v_pending.client_id IS DISTINCT FROM p_client_id
    OR v_pending.sequence_id IS DISTINCT FROM p_sequence_id
    OR v_pending.operation_index IS DISTINCT FROM p_operation_index
    OR v_pending.gateway_epoch IS DISTINCT FROM p_gateway_epoch
  ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='NFS slot has an unfinished protocol operation';
  END IF;
  SELECT * INTO v_slot FROM filebelt_mount.nfs_replay_slots AS slot
  WHERE slot.tenant_id=p_tenant_id AND slot.mount_session_id=p_mount_session_id
    AND slot.nfs_session_id=p_nfs_session_id AND slot.slot_id=p_slot_id
  FOR UPDATE;
  v_slot_found := FOUND;
  IF v_slot_found AND (v_slot.client_id IS DISTINCT FROM p_client_id
     OR v_slot.gateway_epoch IS DISTINCT FROM p_gateway_epoch) THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS slot identity context mismatch';
  END IF;
  IF v_slot_found AND p_sequence_id<v_slot.current_sequence_id THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='misordered NFS slot sequence';
  END IF;
  IF v_slot_found AND p_sequence_id=v_slot.current_sequence_id THEN
    SELECT EXISTS (
      SELECT 1 FROM filebelt_mount.nfs_replay_receipts AS receipt
      WHERE receipt.tenant_id=p_tenant_id
        AND receipt.mount_session_id=p_mount_session_id
        AND receipt.nfs_session_id=p_nfs_session_id
        AND receipt.slot_id=p_slot_id AND receipt.sequence_id=p_sequence_id
        AND receipt.operation_index=p_operation_index
        AND receipt.expires_at>statement_timestamp()
    ) INTO v_receipt_exists;
    IF NOT v_receipt_exists
       AND p_operation_index<=v_slot.max_operation_index AND NOT v_pending_found THEN
      RAISE EXCEPTION USING ERRCODE='40001',
        MESSAGE='missing prior NFS compound operation receipt';
    END IF;
  END IF;

  PERFORM 1
  FROM filebelt_mount.sessions AS session
  JOIN filebelt_mount.gateway_epochs AS gateway
    ON gateway.tenant_id=session.tenant_id AND gateway.protocol='nfs'
   AND gateway.gateway_id=session.gateway_id AND gateway.epoch=session.gateway_epoch
  WHERE session.tenant_id=p_tenant_id AND session.id=p_mount_session_id
    AND session.protocol='nfs' AND session.gateway_epoch=p_gateway_epoch
    AND session.absolute_expires_at>statement_timestamp()
    AND ((session.state='active' AND NOT gateway.draining
          AND gateway.lease_expires_at>statement_timestamp())
      OR (session.state='draining' AND gateway.draining
          AND gateway.drain_deadline>statement_timestamp()))
  FOR SHARE OF session,gateway;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS replay session';
  END IF;
  IF v_receipt_exists THEN
    RETURN true;
  END IF;
  IF NOT v_slot_found THEN
    INSERT INTO filebelt_mount.nfs_replay_slots (
      tenant_id,mount_session_id,nfs_session_id,slot_id,client_id,
      current_sequence_id,max_operation_index,gateway_epoch
    ) VALUES (
      p_tenant_id,p_mount_session_id,p_nfs_session_id,p_slot_id,p_client_id,
      p_sequence_id,p_operation_index,p_gateway_epoch
    );
    RETURN false;
  END IF;
  IF p_sequence_id=v_slot.current_sequence_id THEN
    IF p_operation_index<=v_slot.max_operation_index THEN
      RETURN false;
    END IF;
    UPDATE filebelt_mount.nfs_replay_slots
    SET max_operation_index=p_operation_index,updated_at=statement_timestamp()
    WHERE tenant_id=p_tenant_id AND mount_session_id=p_mount_session_id
      AND nfs_session_id=p_nfs_session_id AND slot_id=p_slot_id
      AND current_sequence_id=p_sequence_id
      AND max_operation_index=v_slot.max_operation_index;
    RETURN false;
  END IF;
  UPDATE filebelt_mount.nfs_replay_slots
  SET current_sequence_id=p_sequence_id,max_operation_index=p_operation_index,
      updated_at=statement_timestamp()
  WHERE tenant_id=p_tenant_id AND mount_session_id=p_mount_session_id
    AND nfs_session_id=p_nfs_session_id AND slot_id=p_slot_id
    AND current_sequence_id=v_slot.current_sequence_id;
  DELETE FROM filebelt_mount.nfs_replay_receipts
  WHERE tenant_id=p_tenant_id AND mount_session_id=p_mount_session_id
    AND nfs_session_id=p_nfs_session_id AND slot_id=p_slot_id
    AND sequence_id=v_slot.current_sequence_id;
  RETURN false;
END
$$;

-- Raw SELECT ... FOR UPDATE would require granting the VFS role UPDATE on the
-- immutable replay table. Keep the exact replay read and row lock behind this
-- caller-bound function instead.
CREATE FUNCTION filebelt_mount.lock_nfs_replay_receipt(
  p_tenant_id uuid,
  p_mount_session_id uuid,
  p_client_id text,
  p_nfs_session_id text,
  p_slot_id integer,
  p_sequence_id bigint,
  p_operation_index integer,
  p_operation text,
  p_request_digest bytea,
  p_gateway_epoch bigint
)
RETURNS TABLE (
  response_bytes bytea,
  response_digest bytea,
  mutation_outcome text,
  mutation_result jsonb,
  gateway_epoch bigint,
  expires_at_unix_seconds bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_receipt filebelt_mount.nfs_replay_receipts%ROWTYPE;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER')
     OR p_client_id !~ '^[A-Za-z0-9_.:@-]{1,255}$'
     OR p_nfs_session_id !~ '^[A-Za-z0-9_.:@-]{1,255}$'
     OR p_slot_id NOT BETWEEN 0 AND 1023 OR p_sequence_id<=0
     OR p_operation_index NOT BETWEEN 0 AND 63
     OR p_operation !~ '^[a-z][a-z0-9_]{0,63}$'
     OR p_request_digest IS NULL OR octet_length(p_request_digest)<>32
     OR p_gateway_epoch<=0 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS replay read caller';
  END IF;
  SELECT * INTO v_receipt
  FROM filebelt_mount.nfs_replay_receipts AS receipt
  WHERE receipt.tenant_id=p_tenant_id
    AND receipt.mount_session_id=p_mount_session_id
    AND receipt.nfs_session_id=p_nfs_session_id
    AND receipt.slot_id=p_slot_id AND receipt.sequence_id=p_sequence_id
    AND receipt.operation_index=p_operation_index
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF v_receipt.client_id IS DISTINCT FROM p_client_id
     OR v_receipt.operation IS DISTINCT FROM p_operation
     OR v_receipt.request_digest IS DISTINCT FROM p_request_digest
     OR v_receipt.gateway_epoch IS DISTINCT FROM p_gateway_epoch THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS replay identity context mismatch';
  END IF;
  PERFORM 1
  FROM filebelt_mount.sessions AS session
  JOIN filebelt_mount.gateway_epochs AS gateway
    ON gateway.tenant_id=session.tenant_id AND gateway.protocol='nfs'
   AND gateway.gateway_id=session.gateway_id AND gateway.epoch=session.gateway_epoch
  WHERE session.tenant_id=p_tenant_id AND session.id=p_mount_session_id
    AND session.protocol='nfs' AND session.gateway_epoch=p_gateway_epoch
    AND session.absolute_expires_at>statement_timestamp()
    AND v_receipt.expires_at>statement_timestamp()
    AND ((session.state='active' AND NOT gateway.draining
          AND gateway.lease_expires_at>statement_timestamp())
      OR (session.state='draining' AND gateway.draining
          AND gateway.drain_deadline>statement_timestamp()))
  FOR SHARE OF session,gateway;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS replay receipt';
  END IF;
  RETURN QUERY SELECT
    v_receipt.response_bytes,v_receipt.response_digest,
    v_receipt.mutation_outcome,v_receipt.mutation_result,
    v_receipt.gateway_epoch,
    floor(extract(epoch FROM v_receipt.expires_at))::bigint;
END
$$;

CREATE OR REPLACE FUNCTION filebelt_mount.enforce_nfs_replay_receipt()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_absolute_expires_at timestamptz;
  v_pending filebelt_mount.nfs_pending_protocol_operations%ROWTYPE;
BEGIN
  IF TG_OP='UPDATE' THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='NFS replay receipts are immutable';
  END IF;
  IF TG_OP='DELETE' THEN
    PERFORM 1 FROM filebelt_mount.nfs_replay_slots AS slot
    JOIN filebelt_mount.sessions AS session
      ON session.tenant_id=slot.tenant_id AND session.id=slot.mount_session_id
    WHERE slot.tenant_id=OLD.tenant_id
      AND slot.mount_session_id=OLD.mount_session_id
      AND slot.nfs_session_id=OLD.nfs_session_id AND slot.slot_id=OLD.slot_id
      AND slot.current_sequence_id=OLD.sequence_id
      AND session.absolute_expires_at>statement_timestamp();
    IF FOUND THEN
      RAISE EXCEPTION USING ERRCODE='55000',
        MESSAGE='current NFS slot replay receipts are immutable';
    END IF;
    RETURN OLD;
  END IF;
  SELECT session.absolute_expires_at INTO v_absolute_expires_at
  FROM filebelt_mount.sessions AS session
  JOIN filebelt_mount.nfs_replay_slots AS slot
    ON slot.tenant_id=session.tenant_id AND slot.mount_session_id=session.id
   AND slot.nfs_session_id=NEW.nfs_session_id AND slot.slot_id=NEW.slot_id
  WHERE session.tenant_id=NEW.tenant_id AND session.id=NEW.mount_session_id
    AND session.protocol='nfs' AND session.gateway_epoch=NEW.gateway_epoch
    AND session.state IN ('active','draining')
    AND session.absolute_expires_at>statement_timestamp()
    AND slot.client_id=NEW.client_id AND slot.gateway_epoch=NEW.gateway_epoch
    AND slot.current_sequence_id=NEW.sequence_id
  FOR SHARE OF session,slot;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='23503',
      MESSAGE='NFS replay receipt requires the current admitted slot sequence';
  END IF;
  SELECT * INTO v_pending
  FROM filebelt_mount.nfs_pending_protocol_operations AS pending
  WHERE pending.tenant_id=NEW.tenant_id
    AND pending.mount_session_id=NEW.mount_session_id
    AND pending.nfs_session_id=NEW.nfs_session_id
    AND pending.slot_id=NEW.slot_id
    AND pending.sequence_id=NEW.sequence_id
    AND pending.operation_index=NEW.operation_index
  FOR UPDATE;
  IF FOUND THEN
    IF v_pending.client_id IS DISTINCT FROM NEW.client_id
       OR v_pending.protocol_operation IS DISTINCT FROM NEW.operation
       OR v_pending.request_digest IS DISTINCT FROM NEW.request_digest
       OR v_pending.gateway_epoch IS DISTINCT FROM NEW.gateway_epoch THEN
      RAISE EXCEPTION USING ERRCODE='40001',
        MESSAGE='NFS pending protocol operation identity mismatch';
    END IF;
    DELETE FROM filebelt_mount.nfs_pending_protocol_operations AS pending
    WHERE pending.tenant_id=NEW.tenant_id
      AND pending.mount_session_id=NEW.mount_session_id
      AND pending.nfs_session_id=NEW.nfs_session_id
      AND pending.slot_id=NEW.slot_id
      AND pending.sequence_id=NEW.sequence_id
      AND pending.operation_index=NEW.operation_index;
  END IF;
  NEW.expires_at := v_absolute_expires_at;
  RETURN NEW;
END
$$;
CREATE TRIGGER nfs_replay_receipt_immutable
BEFORE INSERT OR UPDATE OR DELETE ON filebelt_mount.nfs_replay_receipts
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.enforce_nfs_replay_receipt();
ALTER TABLE filebelt_mount.sessions
  ADD COLUMN nfs_manifest_generation bigint
    CHECK (nfs_manifest_generation IS NULL OR nfs_manifest_generation>0),
  ADD COLUMN nfs_allowed_export_ids bigint[] NOT NULL DEFAULT '{}',
  DROP CONSTRAINT mount_active_nfs_session_projection_check,
  ADD CONSTRAINT mount_active_nfs_session_projection_check CHECK (
    protocol<>'nfs'
    OR state NOT IN ('active','draining')
    OR (
      nfs_gss_binding_digest IS NOT NULL
      AND nfs_mapping_generation IS NOT NULL
      AND nfs_feature_generation IS NOT NULL
      AND nfs_restore_generation IS NOT NULL
      AND nfs_manifest_generation IS NOT NULL
      AND cardinality(nfs_allowed_export_ids)>0
    )
  );

CREATE FUNCTION filebelt_mount.project_nfs_session_manifest()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_manifest_generation bigint;
  v_export_ids bigint[];
BEGIN
  IF TG_OP='UPDATE' AND (
    NEW.nfs_manifest_generation IS DISTINCT FROM OLD.nfs_manifest_generation
    OR NEW.nfs_allowed_export_ids IS DISTINCT FROM OLD.nfs_allowed_export_ids
  ) THEN
    RAISE EXCEPTION USING ERRCODE='55000',
      MESSAGE='authenticated NFS session manifest authority is immutable';
  END IF;
  IF TG_OP='INSERT' AND NEW.protocol='nfs' AND NEW.state='draining' THEN
    RAISE EXCEPTION USING ERRCODE='23514',
      MESSAGE='new NFS sessions cannot begin in draining state';
  ELSIF TG_OP='INSERT' AND NEW.protocol='nfs' AND NEW.state='active' THEN
    SELECT feature.manifest_generation,ARRAY(
      SELECT export.export_id
      FROM filebelt_mount.nfs_exports AS export
      WHERE export.tenant_id=NEW.tenant_id
        AND export.drive_id=ANY(credential.allowed_drive_ids)
        AND export.drive_id=ANY(policy.allowed_drive_ids)
        AND export.desired_state='active' AND export.applied_state='active'
        AND export.desired_generation=export.applied_generation
      ORDER BY export.export_id
    )
    INTO v_manifest_generation,v_export_ids
    FROM filebelt_mount.nfs_feature_state AS feature
    JOIN filebelt_mount.credentials AS credential
      ON credential.tenant_id=feature.tenant_id AND credential.id=NEW.credential_id
     AND credential.principal_id=NEW.user_principal_id
     AND credential.protocol='nfs' AND credential.revoked_at IS NULL
     AND credential.expires_at>statement_timestamp()
     AND credential.credential_generation=NEW.credential_generation
     AND credential.authorization_generation=NEW.authorization_generation
    JOIN filebelt_mount.policies AS policy
      ON policy.tenant_id=credential.tenant_id
     AND policy.principal_id=credential.principal_id AND policy.protocol='nfs'
     AND policy.enabled
     AND policy.authorization_generation=NEW.authorization_generation
    JOIN public.principals AS principal
      ON principal.tenant_id=credential.tenant_id AND principal.id=credential.principal_id
     AND principal.disabled_at IS NULL AND principal.generation=NEW.membership_generation
    JOIN public.users AS user_account
      ON user_account.tenant_id=principal.tenant_id
     AND user_account.principal_id=principal.id AND user_account.status='active'
    JOIN filebelt_mount.nfs_principal_mappings AS mapping
      ON mapping.tenant_id=credential.tenant_id
     AND mapping.credential_id=credential.id AND mapping.principal_id=credential.principal_id
     AND mapping.revoked_at IS NULL AND mapping.generation=NEW.nfs_mapping_generation
    JOIN filebelt_mount.nfs_posix_groups AS posix_group
      ON posix_group.tenant_id=mapping.tenant_id
     AND posix_group.group_id=mapping.posix_group_id
     AND posix_group.projected_gid=mapping.projected_gid
    JOIN public.group_memberships AS membership
      ON membership.tenant_id=mapping.tenant_id
     AND membership.group_id=mapping.posix_group_id
     AND membership.user_principal_id=mapping.principal_id
    JOIN filebelt_mount.gateway_epochs AS gateway
      ON gateway.tenant_id=feature.tenant_id AND gateway.protocol='nfs'
     AND gateway.gateway_id=NEW.gateway_id AND gateway.epoch=NEW.gateway_epoch
     AND NOT gateway.draining AND gateway.lease_expires_at>statement_timestamp()
    WHERE feature.tenant_id=NEW.tenant_id
      AND feature.state='active'
      AND feature.generation=NEW.nfs_feature_generation
      AND feature.restore_generation=NEW.nfs_restore_generation
      AND feature.applied_manifest_generation=feature.manifest_generation;
    IF v_manifest_generation IS NULL OR cardinality(v_export_ids)=0 THEN
      RAISE EXCEPTION USING ERRCODE='23514',
        MESSAGE='active NFS session requires an applied export manifest';
    END IF;
    NEW.nfs_manifest_generation := v_manifest_generation;
    NEW.nfs_allowed_export_ids := v_export_ids;
  ELSIF NEW.protocol<>'nfs' THEN
    NEW.nfs_manifest_generation := NULL;
    NEW.nfs_allowed_export_ids := '{}';
  END IF;
  IF NEW.protocol='nfs'
     AND NOT filebelt_mount.sorted_unique_positive_bigints(NEW.nfs_allowed_export_ids) THEN
    RAISE EXCEPTION USING ERRCODE='23514',
      MESSAGE='NFS session export IDs must be sorted, unique, and positive';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER mount_nfs_session_manifest_projection
BEFORE INSERT OR UPDATE ON filebelt_mount.sessions
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.project_nfs_session_manifest();

-- Bind authentication and idempotent reuse to the exact applied manifest and
-- effective mount policy. Migration 000012 predates the persisted session
-- manifest columns, so returning a current manifest for an older session would
-- silently broaden that authenticated RPCSEC_GSS context.
CREATE OR REPLACE FUNCTION filebelt_mount.create_nfs_session(
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
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='caller is not a FileBelt VFS database principal';
  END IF;
  IF p_kerberos_principal IS NULL
     OR p_kerberos_principal !~ '^[^/@[:space:]]+@[^/@[:space:]]+$'
     OR position(E'\\' in p_kerberos_principal)>0
     OR lower(split_part(p_kerberos_principal,'@',1))='root'
     OR length(p_kerberos_principal)>512
     OR p_gss_binding_digest IS NULL OR octet_length(p_gss_binding_digest)<>32
     OR p_gateway_id IS NULL OR length(p_gateway_id) NOT BETWEEN 1 AND 255
     OR p_gateway_epoch<=0 OR p_source_address IS NULL
     OR p_gss_expires_at IS NULL OR p_gss_expires_at='infinity'::timestamptz
     OR p_gss_expires_at<=clock_timestamp() THEN
    RAISE EXCEPTION USING ERRCODE='22023',
      MESSAGE='invalid NFS session projection input';
  END IF;

  SELECT mapping.principal_id,mapping.credential_id,mapping.posix_name,
         mapping.posix_group_id,posix_group.posix_name AS primary_group_name,
         mapping.projected_uid,mapping.projected_gid,
         mapping.generation AS mapping_generation,
         feature.generation AS feature_generation,
         feature.manifest_generation,feature.restore_generation,
         credential.credential_generation,credential.authorization_generation,
         principal.generation AS membership_generation,
         (credential.read_only OR policy.read_only) AS read_only,
         credential.allowed_drive_ids AS credential_allowed_drive_ids,
         policy.allowed_drive_ids AS policy_allowed_drive_ids
  INTO v_mapping
  FROM filebelt_mount.nfs_principal_mappings AS mapping
  JOIN filebelt_mount.credentials AS credential
    ON credential.tenant_id=mapping.tenant_id
   AND credential.id=mapping.credential_id
   AND credential.principal_id=mapping.principal_id
  JOIN filebelt_mount.policies AS policy
    ON policy.tenant_id=credential.tenant_id
   AND policy.principal_id=credential.principal_id AND policy.protocol='nfs'
   AND policy.enabled
   AND policy.authorization_generation=credential.authorization_generation
  JOIN public.principals AS principal
    ON principal.tenant_id=mapping.tenant_id AND principal.id=mapping.principal_id
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
    ON feature.tenant_id=mapping.tenant_id AND feature.state='active'
   AND feature.applied_manifest_generation=feature.manifest_generation
   AND feature.applied_manifest_digest IS NOT NULL
   AND feature.applied_gateway_id=p_gateway_id
   AND feature.applied_gateway_epoch=p_gateway_epoch
  JOIN filebelt_mount.gateway_epochs AS gateway
    ON gateway.tenant_id=mapping.tenant_id AND gateway.protocol='nfs'
   AND gateway.gateway_id=p_gateway_id AND gateway.epoch=p_gateway_epoch
   AND NOT gateway.draining AND gateway.lease_expires_at>clock_timestamp()
  WHERE mapping.tenant_id=p_tenant_id
    AND mapping.kerberos_principal=p_kerberos_principal
    AND mapping.revoked_at IS NULL
    AND credential.protocol='nfs'
    AND credential.verifier_kind='kerberos_principal'
    AND credential.expires_at='infinity'::timestamptz
    AND credential.revoked_at IS NULL
    AND principal.kind='user' AND principal.disabled_at IS NULL
    AND user_account.status='active'
  FOR UPDATE OF mapping,credential,policy,principal,user_account;
  IF NOT FOUND THEN
    RETURN;
  END IF;

  SELECT COALESCE(array_agg(export.drive_id ORDER BY export.drive_id),'{}'::uuid[]),
         COALESCE(array_agg(export.export_id ORDER BY export.export_id),'{}'::bigint[])
  INTO v_allowed_drive_ids,v_allowed_export_ids
  FROM filebelt_mount.nfs_exports AS export
  JOIN public.nodes AS root
    ON root.tenant_id=export.tenant_id AND root.drive_id=export.drive_id
   AND root.parent_id IS NULL AND root.trash_root_id IS NULL AND root.kind='directory'
  WHERE export.tenant_id=p_tenant_id
    AND export.drive_id=ANY(v_mapping.credential_allowed_drive_ids)
    AND export.drive_id=ANY(v_mapping.policy_allowed_drive_ids)
    AND export.desired_state='active' AND export.applied_state='active'
    AND export.applied_generation=export.desired_generation;
  IF cardinality(v_allowed_export_ids)=0 THEN
    RETURN;
  END IF;

  SELECT session.id,session.session_principal_id,session.state,
         session.credential_generation,session.authorization_generation,
         session.membership_generation,session.nfs_mapping_generation,
         session.nfs_feature_generation,session.nfs_manifest_generation,
         session.nfs_restore_generation,session.nfs_allowed_export_ids,
         session.idle_expires_at,session.absolute_expires_at
  INTO v_existing
  FROM filebelt_mount.sessions AS session
  WHERE session.tenant_id=p_tenant_id
    AND session.credential_id=v_mapping.credential_id
    AND session.protocol='nfs' AND session.gateway_id=p_gateway_id
    AND session.gateway_epoch=p_gateway_epoch
    AND session.source_address=p_source_address
    AND session.nfs_gss_binding_digest=p_gss_binding_digest
    AND session.state IN ('active','draining')
  FOR UPDATE;
  v_reuse_existing := FOUND;
  IF v_reuse_existing AND (
    v_existing.state<>'active'
    OR v_existing.credential_generation IS DISTINCT FROM v_mapping.credential_generation
    OR v_existing.authorization_generation IS DISTINCT FROM v_mapping.authorization_generation
    OR v_existing.membership_generation IS DISTINCT FROM v_mapping.membership_generation
    OR v_existing.nfs_mapping_generation IS DISTINCT FROM v_mapping.mapping_generation
    OR v_existing.nfs_feature_generation IS DISTINCT FROM v_mapping.feature_generation
    OR v_existing.nfs_manifest_generation IS DISTINCT FROM v_mapping.manifest_generation
    OR v_existing.nfs_restore_generation IS DISTINCT FROM v_mapping.restore_generation
    OR v_existing.nfs_allowed_export_ids IS DISTINCT FROM v_allowed_export_ids
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
      nfs_feature_generation,nfs_manifest_generation,nfs_restore_generation,
      nfs_allowed_export_ids
    ) VALUES (
      p_tenant_id,p_session_id,p_session_principal_id,v_mapping.principal_id,
      v_mapping.credential_id,'nfs',p_gateway_id,p_gateway_epoch,p_source_address,
      v_mapping.credential_generation,v_mapping.authorization_generation,
      v_mapping.membership_generation,
      LEAST(clock_timestamp()+interval '15 minutes',v_effective_expires_at),
      v_effective_expires_at,p_gss_binding_digest,v_mapping.mapping_generation,
      v_mapping.feature_generation,v_mapping.manifest_generation,
      v_mapping.restore_generation,v_allowed_export_ids
    );
    v_return_session_id := p_session_id;
  ELSE
    v_return_session_id := v_existing.id;
    v_effective_expires_at := LEAST(
      v_existing.absolute_expires_at,
      clock_timestamp()+interval '4 hours',p_gss_expires_at
    );
    UPDATE filebelt_mount.sessions
    SET last_activity_at=clock_timestamp(),absolute_expires_at=v_effective_expires_at,
        idle_expires_at=LEAST(clock_timestamp()+interval '15 minutes',v_effective_expires_at)
    WHERE tenant_id=p_tenant_id AND id=v_return_session_id;
  END IF;
  UPDATE filebelt_mount.credentials SET last_used_at=clock_timestamp()
  WHERE tenant_id=p_tenant_id AND id=v_mapping.credential_id;

  SELECT session.nfs_mapping_generation,session.nfs_feature_generation,
         session.nfs_manifest_generation,session.nfs_restore_generation,
         session.credential_generation,session.authorization_generation,
         session.membership_generation,session.absolute_expires_at,
         session.nfs_allowed_export_ids
  INTO v_existing
  FROM filebelt_mount.sessions AS session
  WHERE session.tenant_id=p_tenant_id AND session.id=v_return_session_id;
  RETURN QUERY SELECT
    v_return_session_id::uuid,v_mapping.principal_id::uuid,
    v_mapping.credential_id::uuid,v_mapping.posix_name::text,
    v_mapping.posix_group_id::uuid,v_mapping.primary_group_name::text,
    v_mapping.projected_uid::bigint,v_mapping.projected_gid::bigint,
    v_existing.nfs_mapping_generation::bigint,
    v_existing.nfs_feature_generation::bigint,
    v_existing.nfs_manifest_generation::bigint,
    v_existing.nfs_restore_generation::bigint,
    v_existing.credential_generation::bigint,
    v_existing.authorization_generation::bigint,
    v_existing.membership_generation::bigint,v_mapping.read_only::boolean,
    floor(extract(epoch FROM v_existing.absolute_expires_at))::bigint,
    v_allowed_drive_ids::uuid[],v_existing.nfs_allowed_export_ids::bigint[];
END
$$;

-- A failed expected-head CAS retains the finalized staging payload and exact
-- authority snapshot for seven days. Rows remain inventory even after a user
-- copies or discards the conflict; only expiry permits deletion.
CREATE TABLE filebelt_mount.nfs_write_conflicts (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  write_session_id uuid NOT NULL,
  mount_session_id uuid NOT NULL,
  drive_id uuid NOT NULL,
  node_id uuid NOT NULL,
  base_version_id uuid,
  expected_head_version_id uuid,
  observed_head_version_id uuid,
  staging_payload_id uuid NOT NULL,
  logical_size_bytes bigint NOT NULL CHECK (logical_size_bytes>=0),
  gateway_epoch bigint NOT NULL CHECK (gateway_epoch>0),
  restore_generation bigint NOT NULL CHECK (restore_generation>0),
  state text NOT NULL DEFAULT 'retained'
    CHECK (state IN ('retained','copied','discarded','expired')),
  conflict_copy_node_id uuid,
  conflict_copy_version_id uuid,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  expires_at timestamptz NOT NULL DEFAULT (statement_timestamp()+interval '7 days'),
  resolved_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,write_session_id),
  FOREIGN KEY (tenant_id,write_session_id)
    REFERENCES filebelt_mount.write_sessions(tenant_id,id),
  FOREIGN KEY (tenant_id,mount_session_id)
    REFERENCES filebelt_mount.sessions(tenant_id,id),
  FOREIGN KEY (tenant_id,drive_id,node_id)
    REFERENCES public.nodes(tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,node_id,base_version_id)
    REFERENCES public.file_versions(tenant_id,node_id,id),
  FOREIGN KEY (tenant_id,node_id,expected_head_version_id)
    REFERENCES public.file_versions(tenant_id,node_id,id),
  FOREIGN KEY (tenant_id,node_id,observed_head_version_id)
    REFERENCES public.file_versions(tenant_id,node_id,id),
  FOREIGN KEY (tenant_id,staging_payload_id)
    REFERENCES public.payload_objects(tenant_id,id),
  FOREIGN KEY (tenant_id,drive_id,conflict_copy_node_id)
    REFERENCES public.nodes(tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,conflict_copy_node_id,conflict_copy_version_id)
    REFERENCES public.file_versions(tenant_id,node_id,id),
  CHECK (expires_at=created_at+interval '7 days'),
  CHECK ((state='copied')=(conflict_copy_node_id IS NOT NULL
    AND conflict_copy_version_id IS NOT NULL)),
  CHECK ((state='retained')=(resolved_at IS NULL))
);
CREATE INDEX nfs_write_conflicts_expiry_index
  ON filebelt_mount.nfs_write_conflicts (expires_at,state);

CREATE FUNCTION filebelt_mount.enforce_nfs_write_conflict_retention()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,filebelt_mount
AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    IF OLD.expires_at>statement_timestamp() THEN
      RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='NFS write conflicts are retained for seven days';
    END IF;
    RETURN OLD;
  END IF;
  IF TG_OP='UPDATE' AND (
    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.id IS DISTINCT FROM OLD.id
    OR NEW.write_session_id IS DISTINCT FROM OLD.write_session_id
    OR NEW.mount_session_id IS DISTINCT FROM OLD.mount_session_id
    OR NEW.drive_id IS DISTINCT FROM OLD.drive_id
    OR NEW.node_id IS DISTINCT FROM OLD.node_id
    OR NEW.base_version_id IS DISTINCT FROM OLD.base_version_id
    OR NEW.expected_head_version_id IS DISTINCT FROM OLD.expected_head_version_id
    OR NEW.observed_head_version_id IS DISTINCT FROM OLD.observed_head_version_id
    OR NEW.staging_payload_id IS DISTINCT FROM OLD.staging_payload_id
    OR NEW.logical_size_bytes IS DISTINCT FROM OLD.logical_size_bytes
    OR NEW.gateway_epoch IS DISTINCT FROM OLD.gateway_epoch
    OR NEW.restore_generation IS DISTINCT FROM OLD.restore_generation
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
  ) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='NFS write conflict authority is immutable';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER nfs_write_conflict_retention
BEFORE UPDATE OR DELETE ON filebelt_mount.nfs_write_conflicts
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.enforce_nfs_write_conflict_retention();

ALTER TABLE filebelt_mount.nfs_replay_receipts
  ADD COLUMN mutation_outcome text
    CHECK (mutation_outcome IS NULL OR mutation_outcome IN ('applied','conflict')),
  ADD COLUMN mutation_result jsonb
    CHECK (mutation_result IS NULL OR jsonb_typeof(mutation_result)='object');

-- Every fbcap2 sparse/write operation is predeclared by VFS before the
-- capability is issued. The worker admits the exact UUID/range/mode twice
-- (before nonce consumption and after the filesystem lock), so a signed
-- high-offset or cross-mode request cannot invent unplanned COW chunks.
CREATE TABLE filebelt_mount.nfs_write_operations (
  tenant_id uuid NOT NULL,
  write_session_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  operation text NOT NULL CHECK (operation IN (
    'write_data','hole_deallocate','allocate','seek_data','seek_hole'
  )),
  operation_ordinal bigint NOT NULL CHECK (operation_ordinal>0),
  content_blake3 bytea CHECK (content_blake3 IS NULL OR octet_length(content_blake3)=32),
  state text NOT NULL DEFAULT 'planned'
    CHECK (state IN ('planned','executing','io_completed','applied','cancelled')),
  range_start bigint NOT NULL CHECK (range_start>=0),
  range_end bigint NOT NULL CHECK (range_end>=range_start),
  CHECK (operation NOT IN ('seek_data','seek_hole') OR range_start=range_end),
  resulting_logical_size bigint NOT NULL CHECK (resulting_logical_size>=0),
  reserved_bytes bigint NOT NULL CHECK (reserved_bytes>range_end),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (tenant_id,write_session_id,operation_id),
  UNIQUE (tenant_id,write_session_id,operation_ordinal),
  FOREIGN KEY (tenant_id,write_session_id)
    REFERENCES filebelt_mount.write_sessions(tenant_id,id) ON DELETE CASCADE
);
ALTER TABLE filebelt_mount.nfs_write_operations
  ADD CONSTRAINT nfs_write_operation_content_digest_check CHECK (
    (operation='write_data')=(content_blake3 IS NOT NULL)
  );
CREATE INDEX nfs_write_operations_writer_range_index
  ON filebelt_mount.nfs_write_operations (
    tenant_id,write_session_id,range_start,range_end
  );

CREATE FUNCTION filebelt_mount.enforce_nfs_write_operation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,filebelt_mount
AS $$
BEGIN
  IF TG_OP='INSERT' THEN
    PERFORM 1 FROM filebelt_mount.write_sessions AS writer
    WHERE writer.tenant_id=NEW.tenant_id AND writer.id=NEW.write_session_id
      AND writer.state='open'
    FOR UPDATE;
    IF NOT FOUND OR NEW.state<>'planned'
       OR EXISTS (SELECT 1 FROM filebelt_mount.nfs_write_operations AS operation
         WHERE operation.tenant_id=NEW.tenant_id
           AND operation.write_session_id=NEW.write_session_id
           AND operation.state<>'applied')
       OR EXISTS (SELECT 1 FROM filebelt_mount.nfs_io_receipts AS receipt
         WHERE receipt.tenant_id=NEW.tenant_id
           AND receipt.write_session_id=NEW.write_session_id
           AND receipt.state='pending')
       OR NEW.operation_ordinal<>(SELECT COALESCE(max(operation.operation_ordinal),0)+1
         FROM filebelt_mount.nfs_write_operations AS operation
         WHERE operation.tenant_id=NEW.tenant_id
           AND operation.write_session_id=NEW.write_session_id) THEN
      RAISE EXCEPTION USING ERRCODE='40001',
        MESSAGE='NFS write operation ordering is stale';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP='UPDATE' AND (
    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.write_session_id IS DISTINCT FROM OLD.write_session_id
    OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
    OR NEW.operation IS DISTINCT FROM OLD.operation
    OR NEW.operation_ordinal IS DISTINCT FROM OLD.operation_ordinal
    OR NEW.content_blake3 IS DISTINCT FROM OLD.content_blake3
    OR NEW.range_start IS DISTINCT FROM OLD.range_start
    OR NEW.range_end IS DISTINCT FROM OLD.range_end
    OR NEW.resulting_logical_size IS DISTINCT FROM OLD.resulting_logical_size
    OR NEW.reserved_bytes IS DISTINCT FROM OLD.reserved_bytes
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR (OLD.state='planned' AND NEW.state NOT IN ('planned','executing','cancelled'))
    OR (OLD.state='executing' AND NEW.state NOT IN ('executing','io_completed','cancelled'))
    OR (OLD.state='io_completed' AND NEW.state NOT IN ('io_completed','applied','cancelled'))
    OR OLD.state='applied' AND NEW.state<>'applied'
    OR OLD.state='cancelled' AND NEW.state<>'cancelled'
  ) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='NFS write operation plans are immutable';
  END IF;
  RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END
$$;
CREATE TRIGGER nfs_write_operation_immutable
BEFORE INSERT OR UPDATE ON filebelt_mount.nfs_write_operations
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.enforce_nfs_write_operation();

-- Byte-plane response-loss recovery is separate from NFS compound replay.
-- The signed nonce and deterministic full-claims digest identify one exact
-- physical operation. At most one operation per writer may be pending, and a
-- completed typed outcome remains available for an exact capability retry.
CREATE TABLE filebelt_mount.nfs_io_receipts (
  tenant_id uuid NOT NULL,
  nonce_digest bytea NOT NULL CHECK (octet_length(nonce_digest)=32),
  capability_id uuid NOT NULL,
  write_session_id uuid NOT NULL,
  operation_id uuid,
  operation text NOT NULL CHECK (operation IN (
    'write_data','hole_deallocate','allocate','seek_data','seek_hole',
    'flush','finalize','abort','delete_staging'
  )),
  operation_ordinal bigint NOT NULL CHECK (operation_ordinal>0),
  claims_digest bytea NOT NULL CHECK (octet_length(claims_digest)=32),
  content_blake3 bytea CHECK (content_blake3 IS NULL OR octet_length(content_blake3)=32),
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','completed')),
  outcome jsonb CHECK (outcome IS NULL OR jsonb_typeof(outcome)='object'),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  completed_at timestamptz,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,nonce_digest),
  UNIQUE (tenant_id,capability_id),
  UNIQUE (tenant_id,write_session_id,operation_ordinal),
  FOREIGN KEY (tenant_id,write_session_id)
    REFERENCES filebelt_mount.write_sessions(tenant_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,write_session_id,operation_id)
    REFERENCES filebelt_mount.nfs_write_operations(tenant_id,write_session_id,operation_id),
  CHECK ((operation_id IS NOT NULL)=
    (operation IN ('write_data','hole_deallocate','allocate','seek_data','seek_hole'))),
  CHECK ((operation='write_data')=(content_blake3 IS NOT NULL)),
  CHECK ((state='completed')=(outcome IS NOT NULL AND completed_at IS NOT NULL)),
  CHECK (expires_at>created_at)
);
CREATE UNIQUE INDEX nfs_io_one_pending_per_writer
  ON filebelt_mount.nfs_io_receipts (tenant_id,write_session_id)
  WHERE state='pending';
CREATE FUNCTION filebelt_mount.enforce_nfs_io_receipt()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,filebelt_mount
AS $$
BEGIN
  IF TG_OP='UPDATE' AND (
    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.nonce_digest IS DISTINCT FROM OLD.nonce_digest
    OR NEW.capability_id IS DISTINCT FROM OLD.capability_id
    OR NEW.write_session_id IS DISTINCT FROM OLD.write_session_id
    OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
    OR NEW.operation IS DISTINCT FROM OLD.operation
    OR NEW.operation_ordinal IS DISTINCT FROM OLD.operation_ordinal
    OR NEW.claims_digest IS DISTINCT FROM OLD.claims_digest
    OR NEW.content_blake3 IS DISTINCT FROM OLD.content_blake3
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
    OR OLD.state='completed'
    OR NEW.state<>'completed'
  ) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='NFS I/O receipts are immutable';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER nfs_io_receipt_immutable
BEFORE UPDATE ON filebelt_mount.nfs_io_receipts
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.enforce_nfs_io_receipt();

-- VFS preauthorizes the exact signed capability identity before token
-- issuance. The byte worker may consume this opaque grant but cannot create
-- one, so knowledge of database identifiers and generation values is not
-- sufficient to invent physical I/O.
CREATE TABLE filebelt_mount.nfs_io_admissions (
  tenant_id uuid NOT NULL,
  nonce_digest bytea NOT NULL CHECK (octet_length(nonce_digest)=32),
  capability_id uuid NOT NULL,
  write_session_id uuid NOT NULL,
  operation_id uuid,
  operation text NOT NULL CHECK (operation IN (
    'write_data','hole_deallocate','allocate','seek_data','seek_hole',
    'flush','finalize','abort','delete_staging'
  )),
  claims_digest bytea NOT NULL CHECK (octet_length(claims_digest)=32),
  content_blake3 bytea CHECK (
    content_blake3 IS NULL OR octet_length(content_blake3)=32
  ),
  range_start bigint,
  range_end bigint,
  fencing_token bigint NOT NULL CHECK (fencing_token>0),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,nonce_digest),
  UNIQUE (tenant_id,capability_id),
  FOREIGN KEY (tenant_id,write_session_id)
    REFERENCES filebelt_mount.write_sessions(tenant_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,write_session_id,operation_id)
    REFERENCES filebelt_mount.nfs_write_operations(
      tenant_id,write_session_id,operation_id
    ),
  CHECK ((operation_id IS NOT NULL)=(operation IN (
    'write_data','hole_deallocate','allocate','seek_data','seek_hole'
  ))),
  CHECK ((range_start IS NOT NULL AND range_end IS NOT NULL)
    =(operation_id IS NOT NULL)),
  CHECK (range_start IS NULL OR (range_start>=0 AND range_end>=range_start)),
  CHECK ((operation='write_data')=(content_blake3 IS NOT NULL)),
  CHECK (expires_at>created_at)
);
CREATE INDEX nfs_io_admissions_expiry_index
  ON filebelt_mount.nfs_io_admissions (expires_at);
CREATE UNIQUE INDEX nfs_io_one_preauthorized_per_writer
  ON filebelt_mount.nfs_io_admissions (tenant_id,write_session_id);
CREATE FUNCTION filebelt_mount.enforce_nfs_io_admission()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,filebelt_mount
AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000',
    MESSAGE='NFS I/O admissions are immutable';
END
$$;
CREATE TRIGGER nfs_io_admission_immutable
BEFORE UPDATE ON filebelt_mount.nfs_io_admissions
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.enforce_nfs_io_admission();

-- The legacy I/O role retains payload UPDATE for upload/collaboration paths.
-- NFS authority, however, is reachable only through the exact preauthorized
-- SECURITY DEFINER transitions below; raw worker DML cannot mutate its rows.
CREATE FUNCTION filebelt_mount.protect_nfs_worker_authority()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,public,filebelt_mount
AS $$
BEGIN
  IF NOT pg_has_role(current_user,'filebelt_io','MEMBER')
     OR current_user=pg_get_userbyid((
       SELECT relation.relowner FROM pg_class AS relation
       WHERE relation.oid='filebelt_mount.write_sessions'::regclass
     )) THEN
    RETURN NEW;
  END IF;
  IF TG_TABLE_SCHEMA='filebelt_mount' AND TG_TABLE_NAME='write_sessions'
     AND EXISTS (
       SELECT 1 FROM filebelt_mount.sessions AS mount_session
       WHERE mount_session.tenant_id=OLD.tenant_id
         AND mount_session.id=OLD.mount_session_id
         AND mount_session.protocol='nfs'
     ) THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='raw NFS writer mutation is forbidden';
  ELSIF TG_TABLE_SCHEMA='filebelt_mount' AND TG_TABLE_NAME='write_chunks'
     AND EXISTS (
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
  ELSIF TG_TABLE_SCHEMA='public' AND TG_TABLE_NAME='payload_objects'
     AND EXISTS (
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
  RETURN NEW;
END
$$;
CREATE TRIGGER protect_nfs_worker_write_session
BEFORE UPDATE ON filebelt_mount.write_sessions
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.protect_nfs_worker_authority();
CREATE TRIGGER protect_nfs_worker_write_chunk
BEFORE UPDATE ON filebelt_mount.write_chunks
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.protect_nfs_worker_authority();
CREATE TRIGGER protect_nfs_worker_payload
BEFORE UPDATE ON public.payload_objects
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.protect_nfs_worker_authority();

-- The byte worker never receives raw receipt or operation-plan privileges.
-- These functions bind every read and transition to the exact signed claims
-- identity and the immutable VFS-issued writer fence.
CREATE FUNCTION filebelt_mount.nfs_io_fence_live(
  p_tenant_id uuid,
  p_principal_id uuid,
  p_mount_session_id uuid,
  p_credential_id uuid,
  p_handle_id uuid,
  p_drive_id uuid,
  p_node_id uuid,
  p_version_id uuid,
  p_write_session_id uuid,
  p_credential_generation bigint,
  p_authorization_generation bigint,
  p_membership_generation bigint,
  p_drive_acl_generation bigint,
  p_namespace_generation bigint,
  p_resource_acl_generation bigint,
  p_gateway_epoch bigint,
  p_fencing_token bigint,
  p_operation text,
  p_require_worker_lease boolean
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path=pg_catalog,filebelt_mount
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM filebelt_mount.write_sessions AS writer
    JOIN filebelt_mount.handles AS handle
      ON handle.tenant_id=writer.tenant_id AND handle.id=writer.handle_id
    JOIN filebelt_mount.sessions AS mount_session
      ON mount_session.tenant_id=writer.tenant_id
     AND mount_session.id=writer.mount_session_id
    JOIN filebelt_mount.credentials AS credential
      ON credential.tenant_id=mount_session.tenant_id
     AND credential.id=mount_session.credential_id
    JOIN filebelt_mount.policies AS policy
      ON policy.tenant_id=mount_session.tenant_id
     AND policy.principal_id=mount_session.user_principal_id
     AND policy.protocol=mount_session.protocol
    JOIN public.principals AS principal
      ON principal.tenant_id=mount_session.tenant_id
     AND principal.id=mount_session.user_principal_id
    JOIN public.users AS user_account
      ON user_account.tenant_id=principal.tenant_id
     AND user_account.principal_id=principal.id
    JOIN public.drives AS drive
      ON drive.tenant_id=writer.tenant_id AND drive.id=writer.drive_id
    JOIN public.nodes AS node
      ON node.tenant_id=writer.tenant_id AND node.drive_id=writer.drive_id
     AND node.id=writer.node_id
    JOIN filebelt_mount.gateway_epochs AS gateway
      ON gateway.tenant_id=mount_session.tenant_id
     AND gateway.protocol=mount_session.protocol
     AND gateway.gateway_id=mount_session.gateway_id
     AND gateway.epoch=mount_session.gateway_epoch
    JOIN public.payload_objects AS staging
      ON staging.tenant_id=writer.tenant_id AND staging.id=writer.staging_payload_id
    LEFT JOIN public.file_versions AS base_version
      ON base_version.tenant_id=writer.tenant_id
     AND base_version.node_id=writer.node_id
     AND base_version.id=writer.base_version_id
    LEFT JOIN public.payload_objects AS base_payload
      ON base_payload.tenant_id=base_version.tenant_id
     AND base_payload.id=base_version.payload_id
    WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
      AND writer.mount_session_id=p_mount_session_id
      AND writer.handle_id=p_handle_id AND writer.drive_id=p_drive_id
      AND writer.node_id=p_node_id AND writer.fencing_token=p_fencing_token
      AND writer.gateway_epoch=p_gateway_epoch
      AND writer.authorization_generation=p_authorization_generation
      AND (NOT p_require_worker_lease
        OR writer.lease_expires_at>statement_timestamp())
      AND writer.expires_at>statement_timestamp()
      AND handle.session_id=p_mount_session_id AND handle.drive_id=p_drive_id
      AND handle.node_id=p_node_id AND handle.closed_at IS NULL
      AND handle.expires_at>statement_timestamp()
      AND 'WRITE_CONTENT'=ANY(handle.access_actions)
      AND (p_operation IN ('abort','delete_staging')
        OR handle.version_id IS NOT DISTINCT FROM p_version_id)
      AND handle.credential_generation=p_credential_generation
      AND handle.authorization_generation=p_authorization_generation
      AND handle.membership_generation=p_membership_generation
      AND handle.drive_acl_generation=p_drive_acl_generation
      AND handle.namespace_generation=p_namespace_generation
      AND handle.resource_acl_generation=p_resource_acl_generation
      AND handle.gateway_epoch=p_gateway_epoch
      AND mount_session.user_principal_id=p_principal_id
      AND mount_session.credential_id=p_credential_id
      AND mount_session.credential_generation=p_credential_generation
      AND mount_session.authorization_generation=p_authorization_generation
      AND mount_session.membership_generation=p_membership_generation
      AND mount_session.gateway_epoch=p_gateway_epoch
      AND mount_session.state IN ('active','draining')
      AND mount_session.idle_expires_at>statement_timestamp()
      AND mount_session.absolute_expires_at>statement_timestamp()
      AND credential.credential_generation=p_credential_generation
      AND credential.authorization_generation=p_authorization_generation
      AND credential.revoked_at IS NULL
      AND credential.expires_at>statement_timestamp()
      AND NOT credential.read_only AND p_drive_id=ANY(credential.allowed_drive_ids)
      AND policy.enabled AND NOT policy.read_only
      AND p_drive_id=ANY(policy.allowed_drive_ids)
      AND policy.authorization_generation=p_authorization_generation
      AND principal.generation=p_membership_generation
      AND principal.disabled_at IS NULL AND user_account.status='active'
      AND drive.acl_generation=p_drive_acl_generation
      AND node.acl_generation=p_resource_acl_generation
      AND node.namespace_generation=p_namespace_generation
      AND node.kind='file' AND node.trash_root_id IS NULL
      AND staging.drive_id=p_drive_id
      AND (base_payload.id IS NULL OR (
        base_payload.drive_id=p_drive_id AND base_payload.state='referenced'
      ))
      AND (
        (mount_session.state='active' AND NOT gateway.draining
          AND gateway.lease_expires_at>statement_timestamp())
        OR (mount_session.state='draining' AND gateway.draining
          AND gateway.drain_deadline>statement_timestamp())
      )
      AND (
        (p_operation IN ('write_data','hole_deallocate','allocate','seek_data','seek_hole','flush')
          AND writer.state IN ('open','flushing') AND staging.state='staging')
        OR (p_operation='finalize' AND writer.state IN ('flushing','committing')
          AND staging.state IN ('staging','finalized'))
        OR (p_operation='abort' AND writer.state IN ('open','flushing','aborting','aborted')
          AND staging.state IN ('staging','abandoned'))
        OR (p_operation='delete_staging' AND writer.state IN ('aborted','expired')
          AND staging.state IN ('abandoned','deleting','deleted'))
      )
      AND (mount_session.protocol<>'nfs' OR (
        mount_session.nfs_gss_binding_digest IS NOT NULL
        AND EXISTS (
          SELECT 1
          FROM filebelt_mount.nfs_principal_mappings AS mapping
          JOIN public.group_memberships AS membership
            ON membership.tenant_id=mapping.tenant_id
           AND membership.group_id=mapping.posix_group_id
           AND membership.user_principal_id=mapping.principal_id
          WHERE mapping.tenant_id=mount_session.tenant_id
            AND mapping.credential_id=mount_session.credential_id
            AND mapping.principal_id=mount_session.user_principal_id
            AND mapping.generation=mount_session.nfs_mapping_generation
            AND mapping.revoked_at IS NULL
        )
        AND EXISTS (
          SELECT 1 FROM filebelt_mount.nfs_feature_state AS feature
          WHERE feature.tenant_id=mount_session.tenant_id
            AND feature.generation=mount_session.nfs_feature_generation
            AND feature.restore_generation=mount_session.nfs_restore_generation
            AND feature.manifest_generation=mount_session.nfs_manifest_generation
            AND feature.applied_manifest_generation=feature.manifest_generation
            AND feature.applied_gateway_id=mount_session.gateway_id
            AND feature.applied_gateway_epoch=mount_session.gateway_epoch
            AND ((mount_session.state='active' AND feature.state='active')
              OR (mount_session.state='draining'
                AND feature.state IN ('active','draining')))
        )
        AND EXISTS (
          SELECT 1 FROM filebelt_mount.nfs_exports AS export
          WHERE export.tenant_id=mount_session.tenant_id
            AND export.drive_id=p_drive_id
            AND export.export_id=ANY(mount_session.nfs_allowed_export_ids)
            AND export.desired_state='active' AND export.applied_state='active'
            AND export.desired_generation=export.applied_generation
        )
      ))
  )
$$;

CREATE FUNCTION filebelt_mount.preauthorize_nfs_io(
  p_tenant_id uuid,
  p_principal_id uuid,
  p_mount_session_id uuid,
  p_credential_id uuid,
  p_handle_id uuid,
  p_drive_id uuid,
  p_node_id uuid,
  p_version_id uuid,
  p_write_session_id uuid,
  p_credential_generation bigint,
  p_authorization_generation bigint,
  p_membership_generation bigint,
  p_drive_acl_generation bigint,
  p_namespace_generation bigint,
  p_resource_acl_generation bigint,
  p_gateway_epoch bigint,
  p_fencing_token bigint,
  p_client_id text,
  p_nfs_session_id text,
  p_slot_id integer,
  p_sequence_id bigint,
  p_operation_index integer,
  p_protocol_operation text,
  p_request_digest bytea,
  p_protocol_operation_id uuid,
  p_capability_id uuid,
  p_nonce_digest bytea,
  p_operation_id uuid,
  p_operation text,
  p_claims_digest bytea,
  p_content_blake3 bytea,
  p_range_start bigint,
  p_range_end bigint,
  p_expires_at_unix_seconds bigint
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_expires_at timestamptz := to_timestamp(p_expires_at_unix_seconds);
  v_session_expires_at timestamptz;
  v_pending filebelt_mount.nfs_pending_protocol_operations%ROWTYPE;
  v_slot filebelt_mount.nfs_replay_slots%ROWTYPE;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER')
     OR p_client_id !~ '^[A-Za-z0-9_.:@-]{1,255}$'
     OR p_nfs_session_id !~ '^[A-Za-z0-9_.:@-]{1,255}$'
     OR p_slot_id NOT BETWEEN 0 AND 1023 OR p_sequence_id<=0
     OR p_operation_index NOT BETWEEN 0 AND 63
     OR p_protocol_operation !~ '^[A-Za-z0-9_.:@-]{1,64}$'
     OR p_request_digest IS NULL OR octet_length(p_request_digest)<>32
     OR p_protocol_operation_id IS NULL
     OR p_capability_id IS NULL
     OR p_nonce_digest IS NULL OR octet_length(p_nonce_digest)<>32
     OR p_claims_digest IS NULL OR octet_length(p_claims_digest)<>32
     OR (p_operation='write_data')<>(p_content_blake3 IS NOT NULL)
     OR (p_content_blake3 IS NOT NULL AND octet_length(p_content_blake3)<>32)
     OR p_operation NOT IN (
       'write_data','hole_deallocate','allocate','seek_data','seek_hole',
       'flush','finalize','abort','delete_staging'
     )
     OR (p_operation IN (
       'write_data','hole_deallocate','allocate','seek_data','seek_hole'
     ))<>(p_operation_id IS NOT NULL)
     OR (p_operation_id IS NOT NULL)<>(p_range_start IS NOT NULL AND p_range_end IS NOT NULL)
     OR (p_range_start IS NOT NULL AND (
       p_range_start<0 OR p_range_end<p_range_start
       OR (p_operation IN ('seek_data','seek_hole') AND p_range_start<>p_range_end)
     ))
     OR v_expires_at<=statement_timestamp()
     OR v_expires_at>statement_timestamp()+interval '15 seconds'
     OR NOT filebelt_mount.nfs_io_fence_live(
       p_tenant_id,p_principal_id,p_mount_session_id,p_credential_id,
       p_handle_id,p_drive_id,p_node_id,p_version_id,p_write_session_id,
       p_credential_generation,p_authorization_generation,p_membership_generation,
       p_drive_acl_generation,p_namespace_generation,p_resource_acl_generation,
       p_gateway_epoch,p_fencing_token,p_operation,p_operation<>'delete_staging'
     ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS I/O preauthorization';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    p_tenant_id::text || ':' || p_mount_session_id::text || ':' ||
    p_nfs_session_id || ':' || p_slot_id::text,0
  ));
  SELECT * INTO v_pending
  FROM filebelt_mount.nfs_pending_protocol_operations AS pending
  WHERE pending.tenant_id=p_tenant_id
    AND pending.mount_session_id=p_mount_session_id
    AND pending.nfs_session_id=p_nfs_session_id
    AND pending.slot_id=p_slot_id
    AND pending.sequence_id=p_sequence_id
    AND pending.operation_index=p_operation_index
  FOR UPDATE;
  IF FOUND THEN
    IF v_pending.client_id IS DISTINCT FROM p_client_id
       OR v_pending.protocol_operation IS DISTINCT FROM p_protocol_operation
       OR v_pending.request_digest IS DISTINCT FROM p_request_digest
       OR v_pending.gateway_epoch IS DISTINCT FROM p_gateway_epoch
       OR v_pending.protocol_operation_id IS DISTINCT FROM p_protocol_operation_id
       OR v_pending.write_session_id IS DISTINCT FROM p_write_session_id
       OR v_pending.capability_id IS DISTINCT FROM p_capability_id
       OR v_pending.nonce_digest IS DISTINCT FROM p_nonce_digest
       OR v_pending.claims_digest IS DISTINCT FROM p_claims_digest
       OR v_pending.io_operation IS DISTINCT FROM p_operation
       OR v_pending.operation_id IS DISTINCT FROM p_operation_id
       OR v_pending.content_blake3 IS DISTINCT FROM p_content_blake3
       OR v_pending.range_start IS DISTINCT FROM p_range_start
       OR v_pending.range_end IS DISTINCT FROM p_range_end
       OR v_pending.fencing_token IS DISTINCT FROM p_fencing_token THEN
      RAISE EXCEPTION USING ERRCODE='40001',
        MESSAGE='conflicting pending NFS protocol operation';
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM filebelt_mount.nfs_io_admissions AS admission
      WHERE admission.tenant_id=p_tenant_id
        AND admission.capability_id=p_capability_id
        AND admission.nonce_digest=p_nonce_digest
        AND admission.write_session_id=p_write_session_id
        AND admission.operation_id IS NOT DISTINCT FROM p_operation_id
        AND admission.operation=p_operation
        AND admission.claims_digest=p_claims_digest
        AND admission.content_blake3 IS NOT DISTINCT FROM p_content_blake3
        AND admission.range_start IS NOT DISTINCT FROM p_range_start
        AND admission.range_end IS NOT DISTINCT FROM p_range_end
        AND admission.fencing_token=p_fencing_token
        AND admission.expires_at=v_expires_at
    ) AND NOT EXISTS (
      SELECT 1 FROM filebelt_mount.nfs_io_receipts AS receipt
      WHERE receipt.tenant_id=p_tenant_id
        AND receipt.capability_id=p_capability_id
        AND receipt.write_session_id=p_write_session_id
        AND receipt.operation_id IS NOT DISTINCT FROM p_operation_id
        AND receipt.operation=p_operation AND receipt.claims_digest=p_claims_digest
        AND receipt.content_blake3 IS NOT DISTINCT FROM p_content_blake3
    ) THEN
      RAISE EXCEPTION USING ERRCODE='40001',
        MESSAGE='pending NFS operation lost its worker authority';
    END IF;
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1 FROM filebelt_mount.nfs_pending_protocol_operations AS pending
    WHERE pending.tenant_id=p_tenant_id
      AND ((pending.mount_session_id=p_mount_session_id
        AND pending.nfs_session_id=p_nfs_session_id AND pending.slot_id=p_slot_id)
        OR pending.write_session_id=p_write_session_id)
  ) OR EXISTS (
    SELECT 1 FROM filebelt_mount.nfs_io_receipts AS receipt
    WHERE receipt.tenant_id=p_tenant_id
      AND receipt.write_session_id=p_write_session_id AND receipt.state='pending'
  ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='unfinished NFS protocol or worker operation';
  END IF;
  SELECT * INTO v_slot FROM filebelt_mount.nfs_replay_slots AS slot
  WHERE slot.tenant_id=p_tenant_id AND slot.mount_session_id=p_mount_session_id
    AND slot.nfs_session_id=p_nfs_session_id AND slot.slot_id=p_slot_id
  FOR UPDATE;
  IF FOUND AND (
    v_slot.client_id IS DISTINCT FROM p_client_id
    OR v_slot.gateway_epoch IS DISTINCT FROM p_gateway_epoch
    OR p_sequence_id<v_slot.current_sequence_id
    OR (p_sequence_id=v_slot.current_sequence_id
      AND p_operation_index<=v_slot.max_operation_index)
  ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='stale NFS protocol preauthorization sequence';
  END IF;
  IF p_operation_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM filebelt_mount.nfs_write_operations AS planned
    WHERE planned.tenant_id=p_tenant_id
      AND planned.write_session_id=p_write_session_id
      AND planned.operation_id=p_operation_id AND planned.operation=p_operation
      AND planned.content_blake3 IS NOT DISTINCT FROM p_content_blake3
      AND planned.range_start=p_range_start AND planned.range_end=p_range_end
      AND planned.state='planned'
  ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS I/O preauthorized plan';
  END IF;
  IF p_operation_id IS NULL AND EXISTS (
    SELECT 1 FROM filebelt_mount.nfs_write_operations AS planned
    WHERE planned.tenant_id=p_tenant_id
      AND planned.write_session_id=p_write_session_id
      AND planned.state<>'applied'
  ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='unfinished NFS range operation';
  END IF;
  SELECT session.absolute_expires_at INTO v_session_expires_at
  FROM filebelt_mount.sessions AS session
  WHERE session.tenant_id=p_tenant_id AND session.id=p_mount_session_id
    AND session.absolute_expires_at>statement_timestamp()
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS pending session';
  END IF;
  INSERT INTO filebelt_mount.nfs_pending_protocol_operations (
    tenant_id,mount_session_id,client_id,nfs_session_id,slot_id,sequence_id,
    operation_index,protocol_operation,request_digest,gateway_epoch,
    protocol_operation_id,write_session_id,capability_id,nonce_digest,
    claims_digest,io_operation,
    operation_id,content_blake3,range_start,range_end,fencing_token,
    capability_expires_at,expires_at
  ) VALUES (
    p_tenant_id,p_mount_session_id,p_client_id,p_nfs_session_id,p_slot_id,
    p_sequence_id,p_operation_index,p_protocol_operation,p_request_digest,
    p_gateway_epoch,p_protocol_operation_id,p_write_session_id,p_capability_id,p_nonce_digest,
    p_claims_digest,p_operation,p_operation_id,p_content_blake3,p_range_start,
    p_range_end,p_fencing_token,v_expires_at,v_session_expires_at
  );
  INSERT INTO filebelt_mount.nfs_io_admissions (
    tenant_id,nonce_digest,capability_id,write_session_id,operation_id,operation,
    claims_digest,content_blake3,range_start,range_end,fencing_token,expires_at
  ) VALUES (
    p_tenant_id,p_nonce_digest,p_capability_id,p_write_session_id,p_operation_id,
    p_operation,p_claims_digest,p_content_blake3,p_range_start,p_range_end,
    p_fencing_token,v_expires_at
  );
  RETURN true;
END
$$;

CREATE FUNCTION filebelt_mount.lookup_nfs_io_preauthorization(
  p_tenant_id uuid,
  p_mount_session_id uuid,
  p_client_id text,
  p_nfs_session_id text,
  p_slot_id integer,
  p_sequence_id bigint,
  p_operation_index integer,
  p_protocol_operation text,
  p_request_digest bytea,
  p_gateway_epoch bigint,
  p_protocol_operation_id uuid,
  p_write_session_id uuid,
  p_capability_id uuid,
  p_nonce_digest bytea,
  p_claims_digest bytea,
  p_io_operation text,
  p_operation_id uuid,
  p_content_blake3 bytea,
  p_range_start bigint,
  p_range_end bigint,
  p_fencing_token bigint,
  p_expires_at_unix_seconds bigint
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_pending filebelt_mount.nfs_pending_protocol_operations%ROWTYPE;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER') THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS pending lookup caller';
  END IF;
  SELECT * INTO v_pending
  FROM filebelt_mount.nfs_pending_protocol_operations AS pending
  WHERE pending.tenant_id=p_tenant_id
    AND pending.mount_session_id=p_mount_session_id
    AND pending.nfs_session_id=p_nfs_session_id
    AND pending.slot_id=p_slot_id
    AND pending.sequence_id=p_sequence_id
    AND pending.operation_index=p_operation_index;
  IF FOUND THEN
    IF v_pending.client_id IS DISTINCT FROM p_client_id
       OR v_pending.protocol_operation IS DISTINCT FROM p_protocol_operation
       OR v_pending.request_digest IS DISTINCT FROM p_request_digest
       OR v_pending.gateway_epoch IS DISTINCT FROM p_gateway_epoch
       OR v_pending.protocol_operation_id IS DISTINCT FROM p_protocol_operation_id
       OR v_pending.write_session_id IS DISTINCT FROM p_write_session_id
       OR v_pending.capability_id IS DISTINCT FROM p_capability_id
       OR v_pending.nonce_digest IS DISTINCT FROM p_nonce_digest
       OR v_pending.claims_digest IS DISTINCT FROM p_claims_digest
       OR v_pending.io_operation IS DISTINCT FROM p_io_operation
       OR v_pending.operation_id IS DISTINCT FROM p_operation_id
       OR v_pending.content_blake3 IS DISTINCT FROM p_content_blake3
       OR v_pending.range_start IS DISTINCT FROM p_range_start
       OR v_pending.range_end IS DISTINCT FROM p_range_end
       OR v_pending.fencing_token IS DISTINCT FROM p_fencing_token
       OR v_pending.capability_expires_at<>to_timestamp(p_expires_at_unix_seconds)
       OR NOT EXISTS (
         SELECT 1 FROM filebelt_mount.nfs_io_admissions AS admission
         WHERE admission.tenant_id=p_tenant_id
           AND admission.capability_id=p_capability_id
           AND admission.expires_at=to_timestamp(p_expires_at_unix_seconds)
       ) AND NOT EXISTS (
         SELECT 1 FROM filebelt_mount.nfs_io_receipts AS receipt
         WHERE receipt.tenant_id=p_tenant_id
           AND receipt.capability_id=p_capability_id
           AND receipt.write_session_id=p_write_session_id
           AND receipt.operation_id IS NOT DISTINCT FROM p_operation_id
           AND receipt.operation=p_io_operation
           AND receipt.claims_digest=p_claims_digest
       ) THEN
      RAISE EXCEPTION USING ERRCODE='40001',
        MESSAGE='conflicting NFS pending preauthorization lookup';
    END IF;
    RETURN true;
  END IF;
  IF EXISTS (
    SELECT 1 FROM filebelt_mount.nfs_pending_protocol_operations AS pending
    WHERE pending.tenant_id=p_tenant_id
      AND ((pending.mount_session_id=p_mount_session_id
        AND pending.nfs_session_id=p_nfs_session_id AND pending.slot_id=p_slot_id)
        OR pending.write_session_id=p_write_session_id)
  ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='another NFS protocol operation is pending';
  END IF;
  RETURN false;
END
$$;

-- A restarted VFS locates an unfinished protocol operation by the NFS slot
-- identity it can reconstruct from the request. Bearer material is never
-- returned: only its digests and the stable internal operation identity are
-- projected. An exact completed worker receipt is included so VFS can resume
-- the authoritative final protocol transaction without re-running bytes.
CREATE FUNCTION filebelt_mount.inspect_nfs_pending_io(
  p_tenant_id uuid,
  p_mount_session_id uuid,
  p_client_id text,
  p_nfs_session_id text,
  p_slot_id integer,
  p_sequence_id bigint,
  p_operation_index integer,
  p_protocol_operation text,
  p_request_digest bytea,
  p_gateway_epoch bigint
)
RETURNS TABLE (
  protocol_operation_id uuid,
  write_session_id uuid,
  capability_id uuid,
  nonce_digest bytea,
  claims_digest bytea,
  io_operation text,
  operation_id uuid,
  content_blake3 bytea,
  range_start bigint,
  range_end bigint,
  fencing_token bigint,
  capability_expires_at_unix_seconds bigint,
  worker_state text,
  worker_outcome jsonb
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_pending filebelt_mount.nfs_pending_protocol_operations%ROWTYPE;
  v_admission_count integer;
  v_receipt_count integer;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER')
     OR p_client_id !~ '^[A-Za-z0-9_.:@-]{1,255}$'
     OR p_nfs_session_id !~ '^[A-Za-z0-9_.:@-]{1,255}$'
     OR p_slot_id NOT BETWEEN 0 AND 1023 OR p_sequence_id<=0
     OR p_operation_index NOT BETWEEN 0 AND 63
     OR p_protocol_operation !~ '^[A-Za-z0-9_.:@-]{1,64}$'
     OR p_request_digest IS NULL OR octet_length(p_request_digest)<>32
     OR p_gateway_epoch<=0 THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='invalid pending NFS inspection caller';
  END IF;
  SELECT * INTO v_pending
  FROM filebelt_mount.nfs_pending_protocol_operations AS pending
  WHERE pending.tenant_id=p_tenant_id
    AND pending.mount_session_id=p_mount_session_id
    AND pending.nfs_session_id=p_nfs_session_id
    AND pending.slot_id=p_slot_id
    AND pending.sequence_id=p_sequence_id
    AND pending.operation_index=p_operation_index;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF v_pending.client_id IS DISTINCT FROM p_client_id
     OR v_pending.protocol_operation IS DISTINCT FROM p_protocol_operation
     OR v_pending.request_digest IS DISTINCT FROM p_request_digest
     OR v_pending.gateway_epoch IS DISTINCT FROM p_gateway_epoch THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='conflicting pending NFS inspection identity';
  END IF;
  SELECT count(*) INTO v_admission_count
  FROM filebelt_mount.nfs_io_admissions AS admission
  WHERE admission.tenant_id=v_pending.tenant_id
    AND admission.capability_id=v_pending.capability_id
    AND admission.nonce_digest=v_pending.nonce_digest
    AND admission.write_session_id=v_pending.write_session_id;
  SELECT count(*) INTO v_receipt_count
  FROM filebelt_mount.nfs_io_receipts AS receipt
  WHERE receipt.tenant_id=v_pending.tenant_id
    AND receipt.capability_id=v_pending.capability_id
    AND receipt.nonce_digest=v_pending.nonce_digest
    AND receipt.write_session_id=v_pending.write_session_id;
  IF v_admission_count+v_receipt_count<>1 THEN
    RAISE EXCEPTION USING ERRCODE='55000',
      MESSAGE='pending NFS operation has incoherent worker authority';
  END IF;
  RETURN QUERY
  SELECT v_pending.protocol_operation_id,v_pending.write_session_id,
         v_pending.capability_id,v_pending.nonce_digest,v_pending.claims_digest,
         v_pending.io_operation,v_pending.operation_id,v_pending.content_blake3,
         v_pending.range_start,v_pending.range_end,v_pending.fencing_token,
         floor(extract(epoch FROM v_pending.capability_expires_at))::bigint,
         CASE WHEN admission.capability_id IS NOT NULL THEN 'admission'
              ELSE receipt.state END,
         receipt.outcome
  FROM (SELECT 1) AS singleton
  LEFT JOIN filebelt_mount.nfs_io_admissions AS admission
    ON admission.tenant_id=v_pending.tenant_id
   AND admission.capability_id=v_pending.capability_id
   AND admission.nonce_digest=v_pending.nonce_digest
  LEFT JOIN filebelt_mount.nfs_io_receipts AS receipt
    ON receipt.tenant_id=v_pending.tenant_id
   AND receipt.capability_id=v_pending.capability_id
   AND receipt.nonce_digest=v_pending.nonce_digest;
END
$$;

-- Replacing a lost short-lived bearer is safe only while its old admission is
-- still present and no worker receipt exists. Both VFS reissue and worker Begin
-- lock/delete that row, producing a strict either-or outcome. Stable protocol
-- and range-plan identities never change.
CREATE FUNCTION filebelt_mount.reissue_nfs_io(
  p_tenant_id uuid,
  p_principal_id uuid,
  p_mount_session_id uuid,
  p_credential_id uuid,
  p_handle_id uuid,
  p_drive_id uuid,
  p_node_id uuid,
  p_version_id uuid,
  p_write_session_id uuid,
  p_credential_generation bigint,
  p_authorization_generation bigint,
  p_membership_generation bigint,
  p_drive_acl_generation bigint,
  p_namespace_generation bigint,
  p_resource_acl_generation bigint,
  p_gateway_epoch bigint,
  p_fencing_token bigint,
  p_client_id text,
  p_nfs_session_id text,
  p_slot_id integer,
  p_sequence_id bigint,
  p_operation_index integer,
  p_protocol_operation text,
  p_request_digest bytea,
  p_protocol_operation_id uuid,
  p_operation_id uuid,
  p_operation text,
  p_content_blake3 bytea,
  p_range_start bigint,
  p_range_end bigint,
  p_new_capability_id uuid,
  p_new_nonce_digest bytea,
  p_new_claims_digest bytea,
  p_new_expires_at_unix_seconds bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_pending filebelt_mount.nfs_pending_protocol_operations%ROWTYPE;
  v_admission filebelt_mount.nfs_io_admissions%ROWTYPE;
  v_expires_at timestamptz := to_timestamp(p_new_expires_at_unix_seconds);
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER')
     OR p_protocol_operation_id IS NULL OR p_new_capability_id IS NULL
     OR p_new_nonce_digest IS NULL OR octet_length(p_new_nonce_digest)<>32
     OR p_new_claims_digest IS NULL OR octet_length(p_new_claims_digest)<>32
     OR (p_operation='write_data')<>(p_content_blake3 IS NOT NULL)
     OR (p_content_blake3 IS NOT NULL AND octet_length(p_content_blake3)<>32)
     OR v_expires_at<=statement_timestamp()
     OR v_expires_at>statement_timestamp()+interval '15 seconds'
     OR NOT filebelt_mount.nfs_io_fence_live(
       p_tenant_id,p_principal_id,p_mount_session_id,p_credential_id,
       p_handle_id,p_drive_id,p_node_id,p_version_id,p_write_session_id,
       p_credential_generation,p_authorization_generation,p_membership_generation,
       p_drive_acl_generation,p_namespace_generation,p_resource_acl_generation,
       p_gateway_epoch,p_fencing_token,p_operation,p_operation<>'delete_staging'
     ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS I/O reissue fence';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    p_tenant_id::text || ':' || p_mount_session_id::text || ':' ||
    p_nfs_session_id || ':' || p_slot_id::text,0
  ));
  SELECT * INTO v_pending
  FROM filebelt_mount.nfs_pending_protocol_operations AS pending
  WHERE pending.tenant_id=p_tenant_id
    AND pending.mount_session_id=p_mount_session_id
    AND pending.nfs_session_id=p_nfs_session_id
    AND pending.slot_id=p_slot_id AND pending.sequence_id=p_sequence_id
    AND pending.operation_index=p_operation_index
  FOR UPDATE;
  IF NOT FOUND OR v_pending.client_id IS DISTINCT FROM p_client_id
     OR v_pending.protocol_operation IS DISTINCT FROM p_protocol_operation
     OR v_pending.request_digest IS DISTINCT FROM p_request_digest
     OR v_pending.gateway_epoch IS DISTINCT FROM p_gateway_epoch
     OR v_pending.protocol_operation_id IS DISTINCT FROM p_protocol_operation_id
     OR v_pending.write_session_id IS DISTINCT FROM p_write_session_id
     OR v_pending.operation_id IS DISTINCT FROM p_operation_id
     OR v_pending.io_operation IS DISTINCT FROM p_operation
     OR v_pending.content_blake3 IS DISTINCT FROM p_content_blake3
     OR v_pending.range_start IS DISTINCT FROM p_range_start
     OR v_pending.range_end IS DISTINCT FROM p_range_end
     OR v_pending.fencing_token IS DISTINCT FROM p_fencing_token THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='conflicting NFS I/O reissue';
  END IF;
  IF EXISTS (
    SELECT 1 FROM filebelt_mount.nfs_io_receipts AS receipt
    WHERE receipt.tenant_id=p_tenant_id
      AND receipt.capability_id=v_pending.capability_id
      AND receipt.nonce_digest=v_pending.nonce_digest
  ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='NFS I/O already began and cannot be reissued';
  END IF;
  SELECT * INTO v_admission
  FROM filebelt_mount.nfs_io_admissions AS admission
  WHERE admission.tenant_id=p_tenant_id
    AND admission.capability_id=v_pending.capability_id
    AND admission.nonce_digest=v_pending.nonce_digest
    AND admission.write_session_id=p_write_session_id
  FOR UPDATE;
  IF NOT FOUND OR v_admission.operation_id IS DISTINCT FROM p_operation_id
     OR v_admission.operation IS DISTINCT FROM p_operation
     OR v_admission.content_blake3 IS DISTINCT FROM p_content_blake3
     OR v_admission.range_start IS DISTINCT FROM p_range_start
     OR v_admission.range_end IS DISTINCT FROM p_range_end
     OR v_admission.fencing_token IS DISTINCT FROM p_fencing_token THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='missing replaceable NFS I/O admission';
  END IF;
  DELETE FROM filebelt_mount.nfs_io_admissions AS admission
  WHERE admission.tenant_id=p_tenant_id
    AND admission.capability_id=v_admission.capability_id
    AND admission.nonce_digest=v_admission.nonce_digest;
  UPDATE filebelt_mount.nfs_pending_protocol_operations AS pending
  SET capability_id=p_new_capability_id,nonce_digest=p_new_nonce_digest,
      claims_digest=p_new_claims_digest,capability_expires_at=v_expires_at
  WHERE pending.tenant_id=p_tenant_id
    AND pending.protocol_operation_id=p_protocol_operation_id;
  INSERT INTO filebelt_mount.nfs_io_admissions (
    tenant_id,nonce_digest,capability_id,write_session_id,operation_id,operation,
    claims_digest,content_blake3,range_start,range_end,fencing_token,expires_at
  ) VALUES (
    p_tenant_id,p_new_nonce_digest,p_new_capability_id,p_write_session_id,
    p_operation_id,p_operation,p_new_claims_digest,p_content_blake3,
    p_range_start,p_range_end,p_fencing_token,v_expires_at
  );
END
$$;

CREATE FUNCTION filebelt_mount.read_nfs_io_receipt(
  p_tenant_id uuid,
  p_nonce_digest bytea,
  p_capability_id uuid,
  p_write_session_id uuid,
  p_operation text,
  p_claims_digest bytea,
  p_content_blake3 bytea
)
RETURNS TABLE (
  capability_id uuid,
  write_session_id uuid,
  operation_id uuid,
  operation text,
  operation_ordinal bigint,
  claims_digest bytea,
  content_blake3 bytea,
  state text,
  outcome jsonb,
  receipt_live boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_receipt filebelt_mount.nfs_io_receipts%ROWTYPE;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_io','MEMBER')
     OR p_nonce_digest IS NULL OR octet_length(p_nonce_digest)<>32
     OR p_capability_id IS NULL
     OR p_claims_digest IS NULL OR octet_length(p_claims_digest)<>32
     OR p_operation NOT IN (
       'write_data','hole_deallocate','allocate','seek_data','seek_hole',
       'flush','finalize','abort','delete_staging'
     )
     OR (p_operation='write_data')<>(p_content_blake3 IS NOT NULL)
     OR (p_content_blake3 IS NOT NULL AND octet_length(p_content_blake3)<>32) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS I/O receipt reader';
  END IF;
  SELECT * INTO v_receipt
  FROM filebelt_mount.nfs_io_receipts AS receipt
  WHERE receipt.tenant_id=p_tenant_id AND receipt.nonce_digest=p_nonce_digest;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF v_receipt.capability_id<>p_capability_id
     OR v_receipt.write_session_id<>p_write_session_id
     OR (v_receipt.operation_id IS NOT NULL)<>(p_operation IN (
       'write_data','hole_deallocate','allocate','seek_data','seek_hole'
     ))
     OR v_receipt.operation<>p_operation
     OR v_receipt.claims_digest<>p_claims_digest
     OR v_receipt.content_blake3 IS DISTINCT FROM p_content_blake3 THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='conflicting NFS I/O receipt identity';
  END IF;
  RETURN QUERY SELECT
    v_receipt.capability_id,v_receipt.write_session_id,
    v_receipt.operation_id,v_receipt.operation,
    v_receipt.operation_ordinal,v_receipt.claims_digest,v_receipt.content_blake3,
    v_receipt.state,v_receipt.outcome,
    v_receipt.expires_at>statement_timestamp();
END
$$;

CREATE FUNCTION filebelt_mount.read_nfs_write_operation(
  p_tenant_id uuid,
  p_principal_id uuid,
  p_mount_session_id uuid,
  p_credential_id uuid,
  p_handle_id uuid,
  p_drive_id uuid,
  p_node_id uuid,
  p_version_id uuid,
  p_write_session_id uuid,
  p_credential_generation bigint,
  p_authorization_generation bigint,
  p_membership_generation bigint,
  p_drive_acl_generation bigint,
  p_namespace_generation bigint,
  p_resource_acl_generation bigint,
  p_gateway_epoch bigint,
  p_fencing_token bigint,
  p_capability_id uuid,
  p_operation text,
  p_range_start bigint,
  p_range_end bigint
)
RETURNS TABLE (
  operation_id uuid,
  operation text,
  operation_ordinal bigint,
  content_blake3 bytea,
  range_start bigint,
  range_end bigint,
  resulting_logical_size bigint,
  reserved_bytes bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_operation_id uuid;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_io','MEMBER')
     OR NOT filebelt_mount.nfs_io_fence_live(
       p_tenant_id,p_principal_id,p_mount_session_id,p_credential_id,
       p_handle_id,p_drive_id,p_node_id,p_version_id,p_write_session_id,
       p_credential_generation,p_authorization_generation,p_membership_generation,
       p_drive_acl_generation,p_namespace_generation,p_resource_acl_generation,
       p_gateway_epoch,p_fencing_token,p_operation,true
     ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS I/O operation fence';
  END IF;
  SELECT authority.operation_id INTO v_operation_id
  FROM (
    SELECT admission.operation_id
    FROM filebelt_mount.nfs_io_admissions AS admission
    WHERE admission.tenant_id=p_tenant_id
      AND admission.capability_id=p_capability_id
      AND admission.write_session_id=p_write_session_id
      AND admission.operation=p_operation
      AND admission.range_start=p_range_start
      AND admission.range_end=p_range_end
      AND admission.expires_at>statement_timestamp()
    UNION ALL
    SELECT receipt.operation_id
    FROM filebelt_mount.nfs_io_receipts AS receipt
    WHERE receipt.tenant_id=p_tenant_id
      AND receipt.capability_id=p_capability_id
      AND receipt.write_session_id=p_write_session_id
      AND receipt.operation=p_operation
      AND receipt.state='pending'
  ) AS authority;
  IF NOT FOUND OR v_operation_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='missing NFS range capability authority';
  END IF;
  RETURN QUERY
  SELECT planned.operation_id,planned.operation,planned.operation_ordinal,planned.content_blake3,
         planned.range_start,planned.range_end,planned.resulting_logical_size,
         planned.reserved_bytes
  FROM filebelt_mount.nfs_write_operations AS planned
  WHERE planned.tenant_id=p_tenant_id
    AND planned.write_session_id=p_write_session_id
    AND planned.operation_id=v_operation_id AND planned.operation=p_operation
    AND planned.range_start=p_range_start AND planned.range_end=p_range_end
    AND planned.state IN ('planned','executing');
END
$$;

CREATE FUNCTION filebelt_mount.begin_nfs_io_receipt(
  p_tenant_id uuid,
  p_principal_id uuid,
  p_mount_session_id uuid,
  p_credential_id uuid,
  p_handle_id uuid,
  p_drive_id uuid,
  p_node_id uuid,
  p_version_id uuid,
  p_write_session_id uuid,
  p_credential_generation bigint,
  p_authorization_generation bigint,
  p_membership_generation bigint,
  p_drive_acl_generation bigint,
  p_namespace_generation bigint,
  p_resource_acl_generation bigint,
  p_gateway_epoch bigint,
  p_fencing_token bigint,
  p_capability_id uuid,
  p_nonce_digest bytea,
  p_operation text,
  p_claims_digest bytea,
  p_content_blake3 bytea,
  p_range_start bigint,
  p_range_end bigint
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_operation_ordinal bigint;
  v_admission filebelt_mount.nfs_io_admissions%ROWTYPE;
  v_range_operation boolean := p_operation IN (
    'write_data','hole_deallocate','allocate','seek_data','seek_hole'
  );
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_io','MEMBER')
     OR p_nonce_digest IS NULL OR octet_length(p_nonce_digest)<>32
     OR p_capability_id IS NULL
     OR p_claims_digest IS NULL OR octet_length(p_claims_digest)<>32
     OR (p_operation='write_data')<>(p_content_blake3 IS NOT NULL)
     OR (p_content_blake3 IS NOT NULL AND octet_length(p_content_blake3)<>32)
     OR p_operation NOT IN (
       'write_data','hole_deallocate','allocate','seek_data','seek_hole',
       'flush','finalize','abort','delete_staging'
     ) OR NOT filebelt_mount.nfs_io_fence_live(
       p_tenant_id,p_principal_id,p_mount_session_id,p_credential_id,
       p_handle_id,p_drive_id,p_node_id,p_version_id,p_write_session_id,
       p_credential_generation,p_authorization_generation,p_membership_generation,
       p_drive_acl_generation,p_namespace_generation,p_resource_acl_generation,
       p_gateway_epoch,p_fencing_token,p_operation,
       p_operation<>'delete_staging'
     ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS I/O begin fence';
  END IF;
  PERFORM 1 FROM filebelt_mount.write_sessions AS writer
  WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
    AND writer.fencing_token=p_fencing_token FOR UPDATE;
  IF EXISTS (
    SELECT 1 FROM filebelt_mount.nfs_io_receipts AS receipt
    WHERE receipt.tenant_id=p_tenant_id
      AND receipt.write_session_id=p_write_session_id AND receipt.state='pending'
  ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS I/O receipt already pending';
  END IF;
  SELECT * INTO v_admission
  FROM filebelt_mount.nfs_io_admissions AS admission
  WHERE admission.tenant_id=p_tenant_id
    AND admission.nonce_digest=p_nonce_digest
  FOR UPDATE;
  IF NOT FOUND OR v_admission.capability_id<>p_capability_id
     OR v_admission.write_session_id<>p_write_session_id
     OR (v_range_operation<>(v_admission.operation_id IS NOT NULL))
     OR v_admission.operation<>p_operation
     OR v_admission.claims_digest<>p_claims_digest
     OR v_admission.content_blake3 IS DISTINCT FROM p_content_blake3
     OR v_admission.range_start IS DISTINCT FROM p_range_start
     OR v_admission.range_end IS DISTINCT FROM p_range_end
     OR v_admission.fencing_token<>p_fencing_token
     OR v_admission.expires_at<=statement_timestamp() THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='missing NFS I/O preauthorization';
  END IF;
  IF v_range_operation THEN
    IF p_range_start IS NULL OR p_range_end IS NULL THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid NFS range receipt';
    END IF;
    UPDATE filebelt_mount.nfs_write_operations AS planned
    SET state='executing'
    WHERE planned.tenant_id=p_tenant_id
      AND planned.write_session_id=p_write_session_id
      AND planned.operation_id=v_admission.operation_id AND planned.operation=p_operation
      AND planned.range_start=p_range_start AND planned.range_end=p_range_end
      AND planned.content_blake3 IS NOT DISTINCT FROM p_content_blake3
      AND planned.state='planned'
    RETURNING planned.operation_ordinal INTO v_operation_ordinal;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS range plan';
    END IF;
  ELSE
    IF p_range_start IS NOT NULL OR p_range_end IS NOT NULL
       OR p_content_blake3 IS NOT NULL OR EXISTS (
         SELECT 1 FROM filebelt_mount.nfs_write_operations AS planned
         WHERE planned.tenant_id=p_tenant_id
           AND planned.write_session_id=p_write_session_id
           AND planned.state<>'applied'
       ) THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS terminal operation';
    END IF;
    SELECT GREATEST(
      COALESCE((SELECT max(planned.operation_ordinal)
        FROM filebelt_mount.nfs_write_operations AS planned
        WHERE planned.tenant_id=p_tenant_id
          AND planned.write_session_id=p_write_session_id),0),
      COALESCE((SELECT max(receipt.operation_ordinal)
        FROM filebelt_mount.nfs_io_receipts AS receipt
        WHERE receipt.tenant_id=p_tenant_id
          AND receipt.write_session_id=p_write_session_id),0)
    )+1 INTO v_operation_ordinal;
  END IF;
  INSERT INTO filebelt_mount.nfs_io_receipts (
    tenant_id,nonce_digest,capability_id,write_session_id,operation_id,operation,
    operation_ordinal,claims_digest,content_blake3,expires_at
  )
  SELECT p_tenant_id,p_nonce_digest,p_capability_id,p_write_session_id,
         v_admission.operation_id,p_operation,
         v_operation_ordinal,p_claims_digest,p_content_blake3,writer.expires_at
  FROM filebelt_mount.write_sessions AS writer
  WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
    AND writer.fencing_token=p_fencing_token;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS receipt writer';
  END IF;
  DELETE FROM filebelt_mount.nfs_io_admissions AS admission
  WHERE admission.tenant_id=p_tenant_id
    AND admission.nonce_digest=p_nonce_digest;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS I/O preauthorization';
  END IF;
  IF p_operation='abort' THEN
    UPDATE filebelt_mount.write_sessions AS writer
    SET state='aborting',heartbeat_at=statement_timestamp(),
        lease_expires_at=LEAST(writer.expires_at,statement_timestamp()+interval '30 seconds')
    WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
      AND writer.fencing_token=p_fencing_token
      AND writer.state IN ('open','flushing','aborting');
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS abort transition';
    END IF;
  ELSIF p_operation='delete_staging' THEN
    PERFORM filebelt_mount.enqueue_nfs_staging_cleanup(
      p_tenant_id,p_write_session_id,'delete_staging',p_nonce_digest,'delete_staging'
    );
  END IF;
  RETURN v_operation_ordinal;
END
$$;

CREATE FUNCTION filebelt_mount.complete_nfs_io_receipt(
  p_tenant_id uuid,
  p_principal_id uuid,
  p_mount_session_id uuid,
  p_credential_id uuid,
  p_handle_id uuid,
  p_drive_id uuid,
  p_node_id uuid,
  p_version_id uuid,
  p_write_session_id uuid,
  p_credential_generation bigint,
  p_authorization_generation bigint,
  p_membership_generation bigint,
  p_drive_acl_generation bigint,
  p_namespace_generation bigint,
  p_resource_acl_generation bigint,
  p_gateway_epoch bigint,
  p_fencing_token bigint,
  p_capability_id uuid,
  p_nonce_digest bytea,
  p_operation text,
  p_claims_digest bytea,
  p_content_blake3 bytea,
  p_outcome jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_receipt filebelt_mount.nfs_io_receipts%ROWTYPE;
  v_operation filebelt_mount.nfs_write_operations%ROWTYPE;
  v_writer_logical_size bigint;
  v_writer_state text;
  v_staging_payload_id uuid;
  v_staging_payload_state text;
  v_evidence record;
  v_chunk_number bigint;
  v_chunk_size bigint;
  v_chunk_digest bytea;
  v_overall_digest bytea;
  v_represented_size bigint := 0;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_io','MEMBER')
     OR p_nonce_digest IS NULL OR octet_length(p_nonce_digest)<>32
     OR p_capability_id IS NULL
     OR p_claims_digest IS NULL OR octet_length(p_claims_digest)<>32
     OR p_outcome IS NULL OR jsonb_typeof(p_outcome)<>'object'
     OR p_operation='delete_staging'
     OR (p_content_blake3 IS NOT NULL AND octet_length(p_content_blake3)<>32) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS I/O completion caller';
  END IF;
  SELECT * INTO v_receipt FROM filebelt_mount.nfs_io_receipts AS receipt
  WHERE receipt.tenant_id=p_tenant_id AND receipt.nonce_digest=p_nonce_digest
    AND receipt.capability_id=p_capability_id
    AND receipt.write_session_id=p_write_session_id
    AND (receipt.operation_id IS NOT NULL)=(p_operation IN (
      'write_data','hole_deallocate','allocate','seek_data','seek_hole'
    ))
    AND receipt.operation=p_operation AND receipt.claims_digest=p_claims_digest
    AND receipt.content_blake3 IS NOT DISTINCT FROM p_content_blake3
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS I/O completion receipt';
  END IF;
  IF v_receipt.state='completed' THEN
    IF v_receipt.outcome IS DISTINCT FROM p_outcome THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='conflicting NFS I/O completion';
    END IF;
    RETURN v_receipt.outcome;
  END IF;
  SELECT writer.logical_size_bytes,writer.state,writer.staging_payload_id,staging.state
  INTO v_writer_logical_size,v_writer_state,v_staging_payload_id,v_staging_payload_state
  FROM filebelt_mount.write_sessions AS writer
  JOIN filebelt_mount.handles AS handle
    ON handle.tenant_id=writer.tenant_id AND handle.id=writer.handle_id
  JOIN filebelt_mount.sessions AS mount_session
    ON mount_session.tenant_id=writer.tenant_id
   AND mount_session.id=writer.mount_session_id
  JOIN public.payload_objects AS staging
    ON staging.tenant_id=writer.tenant_id AND staging.id=writer.staging_payload_id
  WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
    AND writer.mount_session_id=p_mount_session_id
    AND writer.handle_id=p_handle_id AND writer.drive_id=p_drive_id
    AND writer.node_id=p_node_id AND writer.fencing_token=p_fencing_token
    AND writer.gateway_epoch=p_gateway_epoch
    AND writer.authorization_generation=p_authorization_generation
    AND handle.session_id=p_mount_session_id AND handle.drive_id=p_drive_id
    AND handle.node_id=p_node_id
    AND (p_operation IN ('abort','delete_staging')
      OR handle.version_id IS NOT DISTINCT FROM p_version_id)
    AND handle.credential_generation=p_credential_generation
    AND handle.authorization_generation=p_authorization_generation
    AND handle.membership_generation=p_membership_generation
    AND handle.drive_acl_generation=p_drive_acl_generation
    AND handle.namespace_generation=p_namespace_generation
    AND handle.resource_acl_generation=p_resource_acl_generation
    AND handle.gateway_epoch=p_gateway_epoch
    AND mount_session.user_principal_id=p_principal_id
    AND mount_session.credential_id=p_credential_id
    AND mount_session.credential_generation=p_credential_generation
    AND mount_session.authorization_generation=p_authorization_generation
    AND mount_session.membership_generation=p_membership_generation
    AND mount_session.gateway_epoch=p_gateway_epoch
  FOR UPDATE OF writer;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS I/O completion fence';
  END IF;
  IF p_operation IN ('write_data','hole_deallocate','allocate') THEN
    SELECT * INTO v_operation
    FROM filebelt_mount.nfs_write_operations AS operation
    WHERE operation.tenant_id=p_tenant_id
      AND operation.write_session_id=p_write_session_id
      AND operation.operation_id=v_receipt.operation_id
      AND operation.operation=p_operation
      AND operation.operation_ordinal=v_receipt.operation_ordinal
      AND operation.state='executing'
    FOR UPDATE;
    IF NOT FOUND OR p_outcome->>'kind'<>'range_mutation'
       OR p_outcome - ARRAY['kind','logical_size_bytes','reservation_delta_bytes']<>'{}'::jsonb
       OR jsonb_typeof(p_outcome->'logical_size_bytes')<>'number'
       OR jsonb_typeof(p_outcome->'reservation_delta_bytes')<>'number'
       OR (p_outcome->>'logical_size_bytes') !~ '^[0-9]+$'
       OR (p_outcome->>'reservation_delta_bytes') !~ '^[0-9]+$'
       OR (p_outcome->>'logical_size_bytes')::bigint<>v_operation.resulting_logical_size
       OR (p_outcome->>'reservation_delta_bytes')::bigint>v_operation.reserved_bytes THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid NFS range mutation outcome';
    END IF;
  ELSIF p_operation IN ('seek_data','seek_hole') THEN
    SELECT * INTO v_operation
    FROM filebelt_mount.nfs_write_operations AS operation
    WHERE operation.tenant_id=p_tenant_id
      AND operation.write_session_id=p_write_session_id
      AND operation.operation_id=v_receipt.operation_id
      AND operation.operation=p_operation
      AND operation.operation_ordinal=v_receipt.operation_ordinal
      AND operation.state='executing'
    FOR UPDATE;
    IF NOT FOUND OR p_outcome->>'kind'<>'seek'
       OR p_outcome - ARRAY['kind','offset']<>'{}'::jsonb
       OR (p_outcome->'offset'<>'null'::jsonb AND (
         jsonb_typeof(p_outcome->'offset')<>'number'
         OR (p_outcome->>'offset') !~ '^[0-9]+$'
         OR (p_outcome->>'offset')::bigint<v_operation.range_start
         OR (p_outcome->>'offset')::bigint>v_operation.resulting_logical_size
       )) THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid NFS seek outcome';
    END IF;
  ELSIF p_operation IN ('flush','finalize') THEN
    IF p_outcome->>'kind'<>p_operation
       OR p_outcome - ARRAY['kind','logical_size_bytes','blake3','chunks']<>'{}'::jsonb
       OR jsonb_typeof(p_outcome->'logical_size_bytes')<>'number'
       OR (p_outcome->>'logical_size_bytes') !~ '^[0-9]+$'
       OR (p_outcome->>'logical_size_bytes')::bigint<>v_writer_logical_size
       OR jsonb_typeof(p_outcome->'blake3')<>'array'
       OR jsonb_array_length(p_outcome->'blake3')<>32
       OR EXISTS (
         SELECT 1 FROM jsonb_array_elements_text(p_outcome->'blake3') AS digest(value)
         WHERE digest.value !~ '^[0-9]+$'
           OR digest.value::integer NOT BETWEEN 0 AND 255
       )
       OR jsonb_typeof(p_outcome->'chunks')<>'array'
       OR jsonb_array_length(p_outcome->'chunks')<>(
         SELECT count(*) FROM filebelt_mount.write_chunks AS chunk
         WHERE chunk.tenant_id=p_tenant_id
           AND chunk.write_session_id=p_write_session_id
       ) THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid NFS terminal manifest outcome';
    END IF;
    SELECT decode(string_agg(lpad(to_hex(digest.value::integer),2,'0'),''),'hex')
    INTO v_overall_digest
    FROM jsonb_array_elements_text(p_outcome->'blake3') AS digest(value);
    FOR v_evidence IN
      SELECT evidence.value,evidence.ordinality
      FROM jsonb_array_elements(p_outcome->'chunks')
        WITH ORDINALITY AS evidence(value,ordinality)
      ORDER BY evidence.ordinality
    LOOP
      IF jsonb_typeof(v_evidence.value)<>'object'
         OR v_evidence.value - ARRAY['chunk_number','size_bytes','blake3']<>'{}'::jsonb
         OR (v_evidence.value->>'chunk_number') !~ '^[0-9]+$'
         OR (v_evidence.value->>'size_bytes') !~ '^[1-9][0-9]*$'
         OR jsonb_typeof(v_evidence.value->'blake3')<>'array'
         OR jsonb_array_length(v_evidence.value->'blake3')<>32
         OR EXISTS (
           SELECT 1
           FROM jsonb_array_elements_text(v_evidence.value->'blake3') AS digest(value)
           WHERE digest.value !~ '^[0-9]+$'
             OR digest.value::integer NOT BETWEEN 0 AND 255
         ) THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid NFS chunk evidence';
      END IF;
      v_chunk_number := (v_evidence.value->>'chunk_number')::bigint;
      v_chunk_size := (v_evidence.value->>'size_bytes')::bigint;
      IF v_chunk_number<>v_evidence.ordinality-1 THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='unordered NFS chunk evidence';
      END IF;
      v_represented_size := v_represented_size+v_chunk_size;
      SELECT decode(string_agg(lpad(to_hex(digest.value::integer),2,'0'),''),'hex')
      INTO v_chunk_digest
      FROM jsonb_array_elements_text(v_evidence.value->'blake3') AS digest(value);
      IF p_operation='flush' THEN
        UPDATE filebelt_mount.write_chunks AS chunk
        SET size_bytes=v_chunk_size,blake3=v_chunk_digest,state='ready',
            updated_at=statement_timestamp()
        WHERE chunk.tenant_id=p_tenant_id
          AND chunk.write_session_id=p_write_session_id
          AND chunk.chunk_number=v_chunk_number
          AND chunk.staging_locator IS NOT NULL
          AND (chunk.state='writing' OR (
            chunk.state='ready' AND chunk.size_bytes=v_chunk_size
              AND chunk.blake3=v_chunk_digest
          ));
      ELSE
        UPDATE filebelt_mount.write_chunks AS chunk
        SET state='published',updated_at=statement_timestamp()
        WHERE chunk.tenant_id=p_tenant_id
          AND chunk.write_session_id=p_write_session_id
          AND chunk.chunk_number=v_chunk_number
          AND chunk.staging_locator IS NOT NULL
          AND chunk.size_bytes=v_chunk_size AND chunk.blake3=v_chunk_digest
          AND chunk.state IN ('ready','published');
      END IF;
      IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS chunk evidence';
      END IF;
    END LOOP;
    IF v_represented_size<>v_writer_logical_size THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='incomplete NFS chunk evidence';
    END IF;
    IF p_operation='flush' THEN
      UPDATE filebelt_mount.write_sessions AS writer
      SET state='flushing',heartbeat_at=statement_timestamp(),
          lease_expires_at=LEAST(writer.expires_at,statement_timestamp()+interval '30 seconds')
      WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
        AND writer.fencing_token=p_fencing_token
        AND writer.logical_size_bytes=v_writer_logical_size
        AND writer.state IN ('open','flushing');
      IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS flush transition';
      END IF;
    ELSE
      IF v_writer_state='flushing' THEN
        UPDATE public.payload_objects AS payload
        SET state='finalized',size_bytes=v_writer_logical_size,
            blake3=v_overall_digest,finalized_at=statement_timestamp()
        WHERE payload.tenant_id=p_tenant_id AND payload.id=v_staging_payload_id
          AND payload.drive_id=p_drive_id AND payload.state='staging';
        IF NOT FOUND THEN
          RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS finalize payload';
        END IF;
        UPDATE filebelt_mount.write_sessions AS writer
        SET state='committing',heartbeat_at=statement_timestamp(),
            lease_expires_at=LEAST(writer.expires_at,statement_timestamp()+interval '30 seconds')
        WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
          AND writer.fencing_token=p_fencing_token
          AND writer.logical_size_bytes=v_writer_logical_size
          AND writer.state='flushing';
        IF NOT FOUND THEN
          RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS finalize writer';
        END IF;
      ELSIF v_writer_state<>'committing' OR v_staging_payload_state<>'finalized'
            OR NOT EXISTS (
              SELECT 1 FROM public.payload_objects AS payload
              WHERE payload.tenant_id=p_tenant_id AND payload.id=v_staging_payload_id
                AND payload.size_bytes=v_writer_logical_size
                AND payload.blake3=v_overall_digest
            ) THEN
        RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='inconsistent NFS finalize retry';
      END IF;
      PERFORM filebelt_mount.enqueue_nfs_write_lock_cleanup(
        p_tenant_id,p_write_session_id
      );
    END IF;
  ELSIF p_operation='abort' AND (
      p_outcome<>'{"kind":"abort"}'::jsonb
    ) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid NFS abort outcome';
  ELSIF p_operation='delete_staging'
        AND p_outcome<>'{"kind":"delete_staging"}'::jsonb THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid NFS deletion outcome';
  END IF;
  IF p_operation='abort' THEN
    PERFORM filebelt_mount.finish_nfs_write_abort(
      p_tenant_id,p_write_session_id,p_fencing_token
    );
  END IF;
  IF v_receipt.operation_id IS NOT NULL THEN
    UPDATE filebelt_mount.nfs_write_operations AS operation
    SET state='io_completed'
    WHERE operation.tenant_id=p_tenant_id
      AND operation.write_session_id=p_write_session_id
      AND operation.operation_id=v_receipt.operation_id AND operation.operation=p_operation
      AND operation.operation_ordinal=v_receipt.operation_ordinal
      AND operation.state='executing';
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale executing NFS I/O operation';
    END IF;
  END IF;
  UPDATE filebelt_mount.nfs_io_receipts AS receipt
  SET state='completed',outcome=p_outcome,completed_at=statement_timestamp()
  WHERE receipt.tenant_id=p_tenant_id AND receipt.nonce_digest=p_nonce_digest
    AND receipt.state='pending';
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale pending NFS I/O receipt';
  END IF;
  RETURN p_outcome;
END
$$;

CREATE FUNCTION filebelt_mount.fence_pending_nfs_io_cleanup(
  p_tenant_id uuid,
  p_write_session_id uuid,
  p_fencing_token bigint,
  p_nonce_digest bytea,
  p_claims_digest bytea,
  p_operation text,
  p_content_blake3 bytea
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_writer_state text;
  v_operation_id uuid;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_io','MEMBER')
     OR p_fencing_token<=0 OR p_nonce_digest IS NULL
     OR octet_length(p_nonce_digest)<>32 OR p_claims_digest IS NULL
     OR octet_length(p_claims_digest)<>32
     OR (p_content_blake3 IS NOT NULL AND octet_length(p_content_blake3)<>32) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid pending NFS cleanup caller';
  END IF;
  SELECT receipt.operation_id INTO v_operation_id
  FROM filebelt_mount.nfs_io_receipts AS receipt
  WHERE receipt.tenant_id=p_tenant_id AND receipt.nonce_digest=p_nonce_digest
    AND receipt.write_session_id=p_write_session_id
    AND (receipt.operation_id IS NOT NULL)=(p_operation IN (
      'write_data','hole_deallocate','allocate','seek_data','seek_hole'
    ))
    AND receipt.operation=p_operation AND receipt.claims_digest=p_claims_digest
    AND receipt.content_blake3 IS NOT DISTINCT FROM p_content_blake3
    AND receipt.state='pending'
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale pending NFS cleanup receipt';
  END IF;
  SELECT writer.state INTO v_writer_state
  FROM filebelt_mount.write_sessions AS writer
  WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
    AND writer.fencing_token=p_fencing_token
  FOR UPDATE;
  IF NOT FOUND OR v_writer_state NOT IN (
    'open','flushing','committing','aborting','aborted','expired','conflicted'
  ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale pending NFS cleanup writer';
  END IF;
  IF v_writer_state IN ('open','flushing','committing','aborting') THEN
    UPDATE filebelt_mount.write_sessions AS writer
    SET state='aborting',heartbeat_at=statement_timestamp()
    WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
      AND writer.fencing_token=p_fencing_token
      AND writer.state IN ('open','flushing','committing','aborting');
  END IF;
  PERFORM filebelt_mount.enqueue_nfs_staging_cleanup(
    p_tenant_id,p_write_session_id,'pending_io_expired',p_nonce_digest,'cleanup'
  );
  RETURN v_operation_id;
END
$$;

-- Physical COW cleanup is an explicit job, never a table scanner. The job is
-- idempotently attached to one writer/payload/backend and may carry the exact
-- unknown I/O receipt that forced fencing.
CREATE TABLE filebelt_mount.nfs_staging_cleanup_jobs (
  tenant_id uuid NOT NULL,
  write_session_id uuid NOT NULL,
  backend_id uuid NOT NULL,
  payload_id uuid NOT NULL,
  source_nonce_digest bytea CHECK (
    source_nonce_digest IS NULL OR octet_length(source_nonce_digest)=32
  ),
  reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 64),
  completion_kind text NOT NULL DEFAULT 'cleanup'
    CHECK (completion_kind IN ('cleanup','delete_staging')),
  state text NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending','leased','physical_deleted','completed')),
  fencing_token bigint NOT NULL DEFAULT 1 CHECK (fencing_token>0),
  lease_owner uuid,
  lease_expires_at timestamptz,
  attempts bigint NOT NULL DEFAULT 0 CHECK (attempts>=0),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  completed_by uuid,
  completed_fencing_token bigint CHECK (
    completed_fencing_token IS NULL OR completed_fencing_token>0
  ),
  completed_at timestamptz,
  PRIMARY KEY (tenant_id,write_session_id),
  UNIQUE (tenant_id,payload_id),
  FOREIGN KEY (tenant_id,write_session_id)
    REFERENCES filebelt_mount.write_sessions(tenant_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,payload_id)
    REFERENCES public.payload_objects(tenant_id,id),
  FOREIGN KEY (tenant_id,backend_id)
    REFERENCES public.storage_backends(tenant_id,id),
  FOREIGN KEY (tenant_id,source_nonce_digest)
    REFERENCES filebelt_mount.nfs_io_receipts(tenant_id,nonce_digest),
  CHECK ((state IN ('leased','physical_deleted'))=
    (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CHECK ((state='completed')=(
    completed_at IS NOT NULL AND completed_by IS NOT NULL
    AND completed_fencing_token IS NOT NULL
  ))
);
CREATE INDEX nfs_staging_cleanup_pending_index
  ON filebelt_mount.nfs_staging_cleanup_jobs (tenant_id,backend_id,created_at)
  WHERE state IN ('pending','leased','physical_deleted');

-- A cleanup job is the durable pre-delete fence for never-finalized payloads,
-- which cannot enter the common digest-required delete-intent state. Every
-- file-version publication locks the same payload row as enqueue/claim and
-- rejects a nonterminal cleanup job. Whichever transaction wins first makes
-- the other recheck and fail before external bytes can be deleted or linked.
CREATE FUNCTION filebelt_mount.protect_nfs_cleanup_payload_reference()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_payload_state text;
BEGIN
  SELECT payload.state INTO v_payload_state
  FROM public.payload_objects AS payload
  WHERE payload.tenant_id=NEW.tenant_id AND payload.id=NEW.payload_id
  FOR SHARE;
  IF NOT FOUND OR v_payload_state NOT IN ('finalized','referenced')
     OR EXISTS (
       SELECT 1 FROM filebelt_mount.nfs_staging_cleanup_jobs AS cleanup
       WHERE cleanup.tenant_id=NEW.tenant_id
         AND cleanup.payload_id=NEW.payload_id
         AND cleanup.state IN ('pending','leased','physical_deleted')
     ) THEN
    RAISE EXCEPTION USING ERRCODE='55000',
      MESSAGE='payload is not eligible for file-version publication';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER protect_nfs_cleanup_payload_reference
BEFORE INSERT OR UPDATE OF payload_id ON public.file_versions
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.protect_nfs_cleanup_payload_reference();

CREATE FUNCTION filebelt_mount.enqueue_nfs_staging_cleanup(
  p_tenant_id uuid,
  p_write_session_id uuid,
  p_reason text,
  p_source_nonce_digest bytea DEFAULT NULL,
  p_completion_kind text DEFAULT 'cleanup'
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_writer record;
BEGIN
  IF NOT (
       pg_has_role(session_user,'filebelt_vfs','MEMBER')
       OR pg_has_role(session_user,'filebelt_io','MEMBER')
       OR pg_has_role(session_user,'filebelt_api','MEMBER')
       OR pg_has_role(session_user,'filebelt_maintenance','MEMBER')
       OR pg_has_role(session_user,'filebelt_recovery','MEMBER')
     ) OR p_reason !~ '^[a-z0-9_]{1,64}$'
     OR p_completion_kind NOT IN ('cleanup','delete_staging')
     OR (p_source_nonce_digest IS NOT NULL
       AND octet_length(p_source_nonce_digest)<>32) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS cleanup enqueue caller';
  END IF;
  SELECT writer.state,writer.staging_payload_id,payload.backend_id,payload.state AS payload_state
  INTO v_writer
  FROM filebelt_mount.write_sessions AS writer
  JOIN public.payload_objects AS payload
    ON payload.tenant_id=writer.tenant_id AND payload.id=writer.staging_payload_id
  WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
    AND writer.state IN ('aborting','aborted','expired','conflicted')
    AND payload.state IN ('staging','finalized','abandoned','deleting','deleted')
  FOR UPDATE OF writer,payload;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS staging cleanup is not eligible';
  END IF;
  -- Use a new READ COMMITTED statement after taking the payload lock. If a
  -- concurrent publisher held the payload SHARE lock, the SELECT above waits;
  -- this statement must then observe the committed file-version reference.
  IF EXISTS (
       SELECT 1 FROM public.file_versions AS version
       WHERE version.tenant_id=p_tenant_id
         AND version.payload_id=v_writer.staging_payload_id
     ) OR EXISTS (
       SELECT 1 FROM filebelt_mount.nfs_write_conflicts AS conflict
       WHERE conflict.tenant_id=p_tenant_id
         AND conflict.staging_payload_id=v_writer.staging_payload_id
         AND conflict.state='retained'
     ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='NFS staging cleanup payload became referenced';
  END IF;
  IF p_completion_kind='delete_staging' AND p_source_nonce_digest IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='22023',
      MESSAGE='DeleteStaging cleanup requires an exact pending receipt';
  END IF;
  INSERT INTO filebelt_mount.nfs_staging_cleanup_jobs (
    tenant_id,write_session_id,backend_id,payload_id,source_nonce_digest,reason,
    completion_kind
  ) VALUES (
    p_tenant_id,p_write_session_id,v_writer.backend_id,
    v_writer.staging_payload_id,p_source_nonce_digest,p_reason,p_completion_kind
  ) ON CONFLICT (tenant_id,write_session_id) DO UPDATE
    SET source_nonce_digest=CASE
          WHEN filebelt_mount.nfs_staging_cleanup_jobs.state='completed'
            THEN filebelt_mount.nfs_staging_cleanup_jobs.source_nonce_digest
          ELSE COALESCE(
            filebelt_mount.nfs_staging_cleanup_jobs.source_nonce_digest,
            EXCLUDED.source_nonce_digest
          )
        END,
        reason=CASE
          WHEN filebelt_mount.nfs_staging_cleanup_jobs.state='completed'
            THEN filebelt_mount.nfs_staging_cleanup_jobs.reason
          ELSE EXCLUDED.reason
        END,
        completion_kind=CASE
          WHEN filebelt_mount.nfs_staging_cleanup_jobs.state='completed'
            THEN filebelt_mount.nfs_staging_cleanup_jobs.completion_kind
          WHEN filebelt_mount.nfs_staging_cleanup_jobs.state='physical_deleted'
            AND filebelt_mount.nfs_staging_cleanup_jobs.source_nonce_digest IS NOT NULL
            THEN filebelt_mount.nfs_staging_cleanup_jobs.completion_kind
          WHEN EXCLUDED.completion_kind='cleanup' THEN 'cleanup'
          WHEN filebelt_mount.nfs_staging_cleanup_jobs.source_nonce_digest IS NULL
            OR filebelt_mount.nfs_staging_cleanup_jobs.source_nonce_digest=EXCLUDED.source_nonce_digest
            THEN 'delete_staging'
          ELSE filebelt_mount.nfs_staging_cleanup_jobs.completion_kind
        END
    WHERE filebelt_mount.nfs_staging_cleanup_jobs.backend_id=EXCLUDED.backend_id
      AND filebelt_mount.nfs_staging_cleanup_jobs.payload_id=EXCLUDED.payload_id
      AND (filebelt_mount.nfs_staging_cleanup_jobs.source_nonce_digest IS NULL
        OR EXCLUDED.source_nonce_digest IS NULL
        OR filebelt_mount.nfs_staging_cleanup_jobs.source_nonce_digest=EXCLUDED.source_nonce_digest);
  PERFORM 1 FROM filebelt_mount.nfs_staging_cleanup_jobs AS job
  WHERE job.tenant_id=p_tenant_id AND job.write_session_id=p_write_session_id
    AND job.backend_id=v_writer.backend_id AND job.payload_id=v_writer.staging_payload_id
    AND (p_source_nonce_digest IS NULL OR job.source_nonce_digest=p_source_nonce_digest)
    AND job.completion_kind=p_completion_kind;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='NFS cleanup identity or completion mode is already bound';
  END IF;
  IF p_source_nonce_digest IS NOT NULL THEN
    PERFORM 1 FROM filebelt_mount.nfs_io_receipts AS receipt
    WHERE receipt.tenant_id=p_tenant_id
      AND receipt.nonce_digest=p_source_nonce_digest
      AND receipt.write_session_id=p_write_session_id AND receipt.state='pending'
      AND (p_completion_kind<>'delete_staging' OR receipt.operation='delete_staging')
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS cleanup receipt';
    END IF;
  END IF;
END
$$;

CREATE FUNCTION filebelt_mount.claim_nfs_staging_cleanup(
  p_tenant_id uuid,
  p_backend_id uuid,
  p_write_session_id uuid,
  p_worker_id uuid
)
RETURNS TABLE (
  payload_id uuid,
  drive_id uuid,
  backend_id uuid,
  locator uuid,
  layout text,
  payload_state text,
  size_bytes bigint,
  blake3 bytea,
  job_fencing_token bigint,
  job_state text,
  reason text,
  completion_kind text,
  source_nonce_digest bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_job filebelt_mount.nfs_staging_cleanup_jobs%ROWTYPE;
  v_writer record;
BEGIN
  IF NOT (
       pg_has_role(session_user,'filebelt_io','MEMBER')
       OR pg_has_role(session_user,'filebelt_maintenance','MEMBER')
     ) OR p_worker_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS cleanup worker';
  END IF;
  SELECT payload.id AS payload_id,payload.drive_id,payload.backend_id,
         payload.locator,payload.layout,payload.state AS payload_state,
         payload.size_bytes,payload.blake3
  INTO v_writer
  FROM filebelt_mount.write_sessions AS writer
  JOIN public.payload_objects AS payload
    ON payload.tenant_id=writer.tenant_id AND payload.id=writer.staging_payload_id
  WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
    AND writer.state IN ('aborting','aborted','expired','conflicted')
    AND payload.backend_id=p_backend_id
    AND payload.state IN ('staging','finalized','abandoned','deleting','deleted')
  FOR UPDATE OF writer,payload;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS cleanup authority became stale';
  END IF;
  IF EXISTS (
       SELECT 1 FROM public.file_versions AS version
       WHERE version.tenant_id=p_tenant_id
         AND version.payload_id=v_writer.payload_id
     ) OR EXISTS (
       SELECT 1 FROM filebelt_mount.nfs_write_conflicts AS conflict
       WHERE conflict.tenant_id=p_tenant_id
         AND conflict.staging_payload_id=v_writer.payload_id
         AND conflict.state='retained'
     ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='NFS cleanup payload became referenced';
  END IF;
  SELECT * INTO v_job FROM filebelt_mount.nfs_staging_cleanup_jobs AS job
  WHERE job.tenant_id=p_tenant_id AND job.backend_id=p_backend_id
    AND job.write_session_id=p_write_session_id
  FOR UPDATE;
  IF NOT FOUND OR v_job.state='completed'
     OR v_job.payload_id IS DISTINCT FROM v_writer.payload_id THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS cleanup job is unavailable';
  END IF;
  IF v_job.state IN ('leased','physical_deleted')
     AND v_job.lease_expires_at>statement_timestamp()
     AND v_job.lease_owner IS DISTINCT FROM p_worker_id THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS cleanup job is already leased';
  END IF;
  IF v_job.state NOT IN ('leased','physical_deleted')
     OR v_job.lease_owner IS DISTINCT FROM p_worker_id
     OR v_job.lease_expires_at<=statement_timestamp() THEN
    UPDATE filebelt_mount.nfs_staging_cleanup_jobs
    SET state=CASE WHEN state='physical_deleted' THEN state ELSE 'leased' END,
        lease_owner=p_worker_id,
        lease_expires_at=statement_timestamp()+interval '30 seconds',
        fencing_token=fencing_token+1,attempts=attempts+1
    WHERE tenant_id=p_tenant_id AND write_session_id=p_write_session_id
    RETURNING * INTO v_job;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS cleanup lease changed';
    END IF;
  END IF;
  RETURN QUERY SELECT v_writer.payload_id,v_writer.drive_id,v_writer.backend_id,
    v_writer.locator,v_writer.layout,v_writer.payload_state,v_writer.size_bytes,
    v_writer.blake3,v_job.fencing_token,v_job.state,v_job.reason,
    v_job.completion_kind,v_job.source_nonce_digest;
END
$$;

CREATE FUNCTION filebelt_mount.mark_nfs_staging_cleanup_physical_deleted(
  p_tenant_id uuid,
  p_backend_id uuid,
  p_write_session_id uuid,
  p_worker_id uuid,
  p_job_fencing_token bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_job filebelt_mount.nfs_staging_cleanup_jobs%ROWTYPE;
  v_writer record;
BEGIN
  IF NOT (
       pg_has_role(session_user,'filebelt_io','MEMBER')
       OR pg_has_role(session_user,'filebelt_maintenance','MEMBER')
     ) OR p_job_fencing_token<=0 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS physical-delete caller';
  END IF;
  SELECT writer.state,writer.drive_id,writer.reserved_bytes,
         payload.id AS payload_id,payload.state AS payload_state
  INTO v_writer
  FROM filebelt_mount.write_sessions AS writer
  JOIN public.payload_objects AS payload
    ON payload.tenant_id=writer.tenant_id AND payload.id=writer.staging_payload_id
  JOIN public.drives AS drive
    ON drive.tenant_id=writer.tenant_id AND drive.id=writer.drive_id
  WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
    AND payload.backend_id=p_backend_id
    AND writer.state IN ('aborting','aborted','expired','conflicted')
    AND payload.state IN ('staging','finalized','abandoned','deleting','deleted')
  FOR UPDATE OF writer,payload,drive;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS cleanup writer';
  END IF;
  IF EXISTS (
       SELECT 1 FROM public.file_versions AS version
       WHERE version.tenant_id=p_tenant_id
         AND version.payload_id=v_writer.payload_id
     ) OR EXISTS (
       SELECT 1 FROM filebelt_mount.nfs_write_conflicts AS conflict
       WHERE conflict.tenant_id=p_tenant_id
         AND conflict.staging_payload_id=v_writer.payload_id
         AND conflict.state='retained'
     ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='NFS cleanup payload became referenced';
  END IF;
  SELECT * INTO v_job FROM filebelt_mount.nfs_staging_cleanup_jobs AS job
  WHERE job.tenant_id=p_tenant_id AND job.backend_id=p_backend_id
    AND job.write_session_id=p_write_session_id
  FOR UPDATE;
  IF NOT FOUND OR v_job.payload_id IS DISTINCT FROM v_writer.payload_id THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS cleanup job is missing';
  END IF;
  IF v_job.state='completed' THEN
    IF v_job.completed_by IS DISTINCT FROM p_worker_id
       OR v_job.completed_fencing_token IS DISTINCT FROM p_job_fencing_token THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale completed NFS cleanup identity';
    END IF;
    RETURN;
  END IF;
  IF v_job.state='physical_deleted' THEN
    IF v_job.lease_owner IS DISTINCT FROM p_worker_id
       OR v_job.fencing_token<>p_job_fencing_token
       OR v_job.lease_expires_at<=statement_timestamp() THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS physical-delete retry';
    END IF;
    RETURN;
  END IF;
  IF v_job.state<>'leased' OR v_job.lease_owner IS DISTINCT FROM p_worker_id
     OR v_job.fencing_token<>p_job_fencing_token
     OR v_job.lease_expires_at<=statement_timestamp() THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS physical-delete authority';
  END IF;
  IF v_writer.state IN ('aborting','expired')
     AND v_writer.payload_state IN ('staging','finalized') THEN
    UPDATE public.drives SET reserved_bytes=reserved_bytes-v_writer.reserved_bytes
    WHERE tenant_id=p_tenant_id AND id=v_writer.drive_id
      AND reserved_bytes>=v_writer.reserved_bytes;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS cleanup reservation';
    END IF;
  END IF;
  UPDATE public.payload_objects
  SET state='deleted',deletion_intent_at=COALESCE(deletion_intent_at,statement_timestamp())
  WHERE tenant_id=p_tenant_id AND id=v_job.payload_id
    AND state IN ('staging','finalized','abandoned','deleting','deleted');
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS cleanup payload';
  END IF;
  UPDATE filebelt_mount.write_sessions
  SET state=CASE WHEN state='aborting' THEN 'aborted' ELSE state END,
      finished_at=COALESCE(finished_at,statement_timestamp()),
      heartbeat_at=statement_timestamp()
  WHERE tenant_id=p_tenant_id AND id=p_write_session_id;
  IF v_job.source_nonce_digest IS NOT NULL THEN
    PERFORM 1 FROM filebelt_mount.nfs_io_receipts AS receipt
    WHERE receipt.tenant_id=p_tenant_id
      AND receipt.nonce_digest=v_job.source_nonce_digest
      AND receipt.write_session_id=p_write_session_id
      AND receipt.state IN ('pending','completed')
      AND ((v_job.completion_kind='cleanup')
        OR (v_job.completion_kind='delete_staging'
          AND receipt.operation='delete_staging'));
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='40001',
        MESSAGE='NFS cleanup receipt completion mode is stale';
    END IF;
  END IF;
  UPDATE filebelt_mount.nfs_write_operations
  SET state='cancelled'
  WHERE tenant_id=p_tenant_id AND write_session_id=p_write_session_id
    AND state IN ('planned','executing','io_completed');
  UPDATE filebelt_mount.nfs_staging_cleanup_jobs
  SET state='physical_deleted'
  WHERE tenant_id=p_tenant_id AND write_session_id=p_write_session_id
    AND state='leased' AND fencing_token=p_job_fencing_token;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS physical-delete transition';
  END IF;
END
$$;

CREATE FUNCTION filebelt_mount.complete_nfs_staging_cleanup(
  p_tenant_id uuid,
  p_backend_id uuid,
  p_write_session_id uuid,
  p_worker_id uuid,
  p_job_fencing_token bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_job filebelt_mount.nfs_staging_cleanup_jobs%ROWTYPE;
  v_payload_id uuid;
BEGIN
  IF NOT (
       pg_has_role(session_user,'filebelt_io','MEMBER')
       OR pg_has_role(session_user,'filebelt_maintenance','MEMBER')
     ) OR p_job_fencing_token<=0 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS cleanup completion caller';
  END IF;
  SELECT payload.id INTO v_payload_id
  FROM filebelt_mount.write_sessions AS writer
  JOIN public.payload_objects AS payload
    ON payload.tenant_id=writer.tenant_id AND payload.id=writer.staging_payload_id
  WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
    AND payload.backend_id=p_backend_id
  FOR UPDATE OF writer,payload;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS cleanup writer is missing';
  END IF;
  SELECT * INTO v_job FROM filebelt_mount.nfs_staging_cleanup_jobs AS job
  WHERE job.tenant_id=p_tenant_id AND job.backend_id=p_backend_id
    AND job.write_session_id=p_write_session_id
  FOR UPDATE;
  IF NOT FOUND OR v_job.payload_id IS DISTINCT FROM v_payload_id THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS cleanup job is missing';
  END IF;
  IF v_job.state='completed' THEN
    IF v_job.completed_by IS DISTINCT FROM p_worker_id
       OR v_job.completed_fencing_token IS DISTINCT FROM p_job_fencing_token THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale completed NFS cleanup identity';
    END IF;
    RETURN;
  END IF;
  IF v_job.state<>'physical_deleted'
     OR v_job.lease_owner IS DISTINCT FROM p_worker_id
     OR v_job.fencing_token<>p_job_fencing_token
     OR v_job.lease_expires_at<=statement_timestamp() THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS cleanup completion';
  END IF;
  IF v_job.source_nonce_digest IS NOT NULL THEN
    UPDATE filebelt_mount.nfs_io_receipts
    SET state='completed',outcome=CASE v_job.completion_kind
          WHEN 'delete_staging' THEN '{"kind":"delete_staging"}'::jsonb
          ELSE '{"kind":"cleanup"}'::jsonb
        END,
        completed_at=statement_timestamp()
    WHERE tenant_id=p_tenant_id AND nonce_digest=v_job.source_nonce_digest
      AND write_session_id=p_write_session_id AND state='pending'
      AND (v_job.completion_kind<>'delete_staging' OR operation='delete_staging');
    IF NOT FOUND AND NOT EXISTS (
      SELECT 1 FROM filebelt_mount.nfs_io_receipts AS receipt
      WHERE receipt.tenant_id=p_tenant_id
        AND receipt.nonce_digest=v_job.source_nonce_digest
        AND receipt.write_session_id=p_write_session_id
        AND receipt.state='completed'
        AND receipt.outcome=CASE v_job.completion_kind
          WHEN 'delete_staging' THEN '{"kind":"delete_staging"}'::jsonb
          ELSE '{"kind":"cleanup"}'::jsonb
        END
    ) THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS cleanup receipt';
    END IF;
  END IF;
  UPDATE filebelt_mount.nfs_staging_cleanup_jobs
  SET state='completed',completed_at=statement_timestamp(),
      completed_by=p_worker_id,completed_fencing_token=p_job_fencing_token,
      lease_owner=NULL,lease_expires_at=NULL
  WHERE tenant_id=p_tenant_id AND write_session_id=p_write_session_id
    AND state='physical_deleted' AND fencing_token=p_job_fencing_token;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS cleanup completion';
  END IF;
END
$$;

-- Atomically discovers and leases the oldest eligible cleanup for one
-- tenant/backend. An already-live lease owned by this worker is returned first
-- so a retry cannot silently move on to another staging tree.
CREATE FUNCTION filebelt_mount.claim_next_nfs_staging_cleanup(
  p_tenant_id uuid,
  p_backend_id uuid,
  p_worker_id uuid
)
RETURNS TABLE (
  write_session_id uuid,
  payload_id uuid,
  drive_id uuid,
  backend_id uuid,
  locator uuid,
  layout text,
  payload_state text,
  size_bytes bigint,
  blake3 bytea,
  job_fencing_token bigint,
  job_state text,
  reason text,
  completion_kind text,
  source_nonce_digest bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_write_session_id uuid;
BEGIN
  IF NOT (
       pg_has_role(session_user,'filebelt_io','MEMBER')
       OR pg_has_role(session_user,'filebelt_maintenance','MEMBER')
     ) OR p_worker_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS cleanup worker';
  END IF;
  -- Candidate discovery must not retain a job-row lock before the exact
  -- claim takes writer/payload locks. Serialize discovery per backend, then
  -- let claim_nfs_staging_cleanup acquire the canonical lock order.
  PERFORM pg_advisory_xact_lock(hashtextextended(
    p_tenant_id::text || ':nfs-staging-cleanup:' || p_backend_id::text,0
  ));
  SELECT job.write_session_id INTO v_write_session_id
  FROM filebelt_mount.nfs_staging_cleanup_jobs AS job
  WHERE job.tenant_id=p_tenant_id AND job.backend_id=p_backend_id
    AND (
      job.state='pending'
      OR (job.state IN ('leased','physical_deleted') AND (
        job.lease_expires_at<=statement_timestamp()
        OR (job.lease_owner=p_worker_id
          AND job.lease_expires_at>statement_timestamp())
      ))
    )
  ORDER BY
    (job.state IN ('leased','physical_deleted') AND job.lease_owner=p_worker_id
      AND job.lease_expires_at>statement_timestamp()) DESC,
    job.created_at,job.write_session_id
  LIMIT 1;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  RETURN QUERY
  SELECT v_write_session_id,claim.payload_id,claim.drive_id,claim.backend_id,
         claim.locator,claim.layout,claim.payload_state,claim.size_bytes,
         claim.blake3,claim.job_fencing_token,claim.job_state,claim.reason,
         claim.completion_kind,claim.source_nonce_digest
  FROM filebelt_mount.claim_nfs_staging_cleanup(
    p_tenant_id,p_backend_id,v_write_session_id,p_worker_id
  ) AS claim;
END
$$;

CREATE FUNCTION filebelt_mount.heartbeat_nfs_staging_cleanup(
  p_tenant_id uuid,
  p_backend_id uuid,
  p_write_session_id uuid,
  p_worker_id uuid,
  p_job_fencing_token bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
BEGIN
  IF NOT (
       pg_has_role(session_user,'filebelt_io','MEMBER')
       OR pg_has_role(session_user,'filebelt_maintenance','MEMBER')
     ) OR p_job_fencing_token<=0 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS cleanup heartbeat caller';
  END IF;
  UPDATE filebelt_mount.nfs_staging_cleanup_jobs
  SET lease_expires_at=statement_timestamp()+interval '30 seconds'
  WHERE tenant_id=p_tenant_id AND backend_id=p_backend_id
    AND write_session_id=p_write_session_id
    AND state IN ('leased','physical_deleted')
    AND lease_owner=p_worker_id AND fencing_token=p_job_fencing_token
    AND lease_expires_at>statement_timestamp();
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS cleanup heartbeat';
  END IF;
END
$$;

-- Fence abandoned writers and enqueue the same two-phase physical cleanup
-- used by explicit Abort/Delete. A byte-plane-completed range remains
-- recoverable past the short worker lease; it is swept only at the writer's
-- absolute expiry. Unknown pending I/O is instead fenced as soon as its worker
-- lease expires so no later operation can overtake uncertain bytes.
CREATE FUNCTION filebelt_mount.sweep_expired_nfs_writers(
  p_tenant_id uuid,
  p_limit integer
)
RETURNS TABLE (
  write_session_id uuid,
  backend_id uuid,
  staging_payload_id uuid,
  fencing_token bigint,
  source_nonce_digest bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_writer record;
  v_pending_count integer;
  v_source_nonce bytea;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_maintenance','MEMBER')
     OR p_limit NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS writer sweep caller';
  END IF;
  FOR v_writer IN
    SELECT writer.id,writer.fencing_token,payload.backend_id,
           writer.staging_payload_id
    FROM filebelt_mount.write_sessions AS writer
    JOIN filebelt_mount.sessions AS session
      ON session.tenant_id=writer.tenant_id AND session.id=writer.mount_session_id
    JOIN public.payload_objects AS payload
      ON payload.tenant_id=writer.tenant_id AND payload.id=writer.staging_payload_id
    WHERE writer.tenant_id=p_tenant_id AND session.protocol='nfs'
      AND writer.state IN ('open','flushing','committing','aborting')
      AND (
        writer.expires_at<=statement_timestamp()
        OR (writer.state IN ('open','flushing','aborting')
          AND writer.lease_expires_at<=statement_timestamp()
          AND NOT EXISTS (
            SELECT 1 FROM filebelt_mount.nfs_write_operations AS operation
            JOIN filebelt_mount.nfs_io_receipts AS receipt
              ON receipt.tenant_id=operation.tenant_id
             AND receipt.write_session_id=operation.write_session_id
             AND receipt.operation_id=operation.operation_id
            WHERE operation.tenant_id=writer.tenant_id
              AND operation.write_session_id=writer.id
              AND operation.state='io_completed' AND receipt.state='completed'
          ))
      )
    ORDER BY writer.expires_at,writer.id
    FOR UPDATE OF writer SKIP LOCKED
    LIMIT p_limit
  LOOP
    SELECT count(*)::integer,min(receipt.nonce_digest)
    INTO v_pending_count,v_source_nonce
    FROM filebelt_mount.nfs_io_receipts AS receipt
    WHERE receipt.tenant_id=p_tenant_id
      AND receipt.write_session_id=v_writer.id AND receipt.state='pending';
    IF v_pending_count>1 THEN
      RAISE EXCEPTION USING ERRCODE='55000',
        MESSAGE='NFS writer has multiple pending byte-plane receipts';
    END IF;
    UPDATE filebelt_mount.write_sessions AS expiring_writer
    SET state='expired',fencing_token=expiring_writer.fencing_token+1,
        finished_at=COALESCE(expiring_writer.finished_at,statement_timestamp()),
        heartbeat_at=statement_timestamp()
    WHERE expiring_writer.tenant_id=p_tenant_id AND expiring_writer.id=v_writer.id
      AND expiring_writer.fencing_token=v_writer.fencing_token
      AND expiring_writer.state IN ('open','flushing','committing','aborting')
    RETURNING expiring_writer.fencing_token
      INTO v_writer.fencing_token;
    IF NOT FOUND THEN
      CONTINUE;
    END IF;
    PERFORM filebelt_mount.enqueue_nfs_staging_cleanup(
      p_tenant_id,v_writer.id,'writer_expired',v_source_nonce,'cleanup'
    );
    write_session_id := v_writer.id;
    backend_id := v_writer.backend_id;
    staging_payload_id := v_writer.staging_payload_id;
    fencing_token := v_writer.fencing_token;
    source_nonce_digest := v_source_nonce;
    RETURN NEXT;
  END LOOP;
END
$$;

-- Conflict state changes are caller-bound transitions, never raw API table
-- updates. Copy completion validates the already-created common namespace
-- object/version in the same outer transaction before making it discoverable
-- as the retained conflict's resolution.
CREATE FUNCTION filebelt_mount.complete_nfs_write_conflict_copy(
  p_tenant_id uuid,
  p_actor_principal_id uuid,
  p_api_session_id uuid,
  p_conflict_id uuid,
  p_parent_id uuid,
  p_display_name text,
  p_name_key text,
  p_node_id uuid,
  p_version_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_conflict record;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_api','MEMBER')
     OR p_display_name IS NULL OR p_name_key IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS conflict-copy caller';
  END IF;
  SELECT conflict.state,conflict.drive_id,conflict.staging_payload_id,
         conflict.conflict_copy_node_id,conflict.conflict_copy_version_id
  INTO v_conflict
  FROM filebelt_mount.nfs_write_conflicts AS conflict
  JOIN filebelt_mount.sessions AS mount_session
    ON mount_session.tenant_id=conflict.tenant_id
   AND mount_session.id=conflict.mount_session_id
  JOIN public.api_sessions AS api_session
    ON api_session.tenant_id=conflict.tenant_id AND api_session.id=p_api_session_id
   AND api_session.principal_id=p_actor_principal_id
  WHERE conflict.tenant_id=p_tenant_id AND conflict.id=p_conflict_id
    AND mount_session.user_principal_id=p_actor_principal_id
    AND api_session.revoked_at IS NULL
    AND api_session.idle_expires_at>statement_timestamp()
    AND api_session.absolute_expires_at>statement_timestamp()
    AND conflict.state IN ('retained','copied')
    AND (conflict.state='copied' OR conflict.expires_at>statement_timestamp())
  FOR UPDATE OF conflict,api_session;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS conflict-copy authority';
  END IF;
  IF v_conflict.state='copied' THEN
    IF v_conflict.conflict_copy_node_id IS DISTINCT FROM p_node_id
       OR v_conflict.conflict_copy_version_id IS DISTINCT FROM p_version_id THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS conflict-copy replay mismatch';
    END IF;
    RETURN;
  END IF;
  PERFORM 1 FROM public.nodes AS node
  JOIN public.file_versions AS version
    ON version.tenant_id=node.tenant_id AND version.node_id=node.id
   AND version.id=p_version_id
  JOIN public.payload_objects AS payload
    ON payload.tenant_id=version.tenant_id AND payload.id=version.payload_id
  JOIN filebelt_mount.write_sessions AS writer
    ON writer.tenant_id=node.tenant_id
   AND writer.id=(SELECT conflict.write_session_id
     FROM filebelt_mount.nfs_write_conflicts AS conflict
     WHERE conflict.tenant_id=p_tenant_id AND conflict.id=p_conflict_id)
  WHERE node.tenant_id=p_tenant_id AND node.drive_id=v_conflict.drive_id
    AND node.id=p_node_id AND node.parent_id=p_parent_id
    AND node.display_name=p_display_name AND node.name_key=p_name_key
    AND node.head_version_id=p_version_id AND node.trash_root_id IS NULL
    AND version.payload_id=v_conflict.staging_payload_id
    AND version.created_by=p_actor_principal_id AND version.origin_kind='nfs'
    AND payload.state='referenced' AND writer.state='conflicted'
  FOR SHARE OF node,version,payload,writer;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='incomplete NFS conflict-copy publication';
  END IF;
  UPDATE filebelt_mount.nfs_write_conflicts
  SET state='copied',conflict_copy_node_id=p_node_id,
      conflict_copy_version_id=p_version_id,resolved_at=statement_timestamp()
  WHERE tenant_id=p_tenant_id AND id=p_conflict_id AND state='retained';
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS conflict-copy transition';
  END IF;
END
$$;

CREATE FUNCTION filebelt_mount.discard_nfs_write_conflict(
  p_tenant_id uuid,
  p_actor_principal_id uuid,
  p_api_session_id uuid,
  p_conflict_id uuid
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_conflict record;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_api','MEMBER') THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS conflict-discard caller';
  END IF;
  SELECT conflict.state,conflict.drive_id,conflict.staging_payload_id,
         conflict.write_session_id,writer.reserved_bytes,payload.state AS payload_state
  INTO v_conflict
  FROM filebelt_mount.nfs_write_conflicts AS conflict
  JOIN filebelt_mount.sessions AS mount_session
    ON mount_session.tenant_id=conflict.tenant_id
   AND mount_session.id=conflict.mount_session_id
  JOIN filebelt_mount.write_sessions AS writer
    ON writer.tenant_id=conflict.tenant_id AND writer.id=conflict.write_session_id
  JOIN public.payload_objects AS payload
    ON payload.tenant_id=conflict.tenant_id AND payload.id=conflict.staging_payload_id
  JOIN public.drives AS drive
    ON drive.tenant_id=conflict.tenant_id AND drive.id=conflict.drive_id
  JOIN public.api_sessions AS api_session
    ON api_session.tenant_id=conflict.tenant_id AND api_session.id=p_api_session_id
   AND api_session.principal_id=p_actor_principal_id
  WHERE conflict.tenant_id=p_tenant_id AND conflict.id=p_conflict_id
    AND mount_session.user_principal_id=p_actor_principal_id
    AND api_session.revoked_at IS NULL
    AND api_session.idle_expires_at>statement_timestamp()
    AND api_session.absolute_expires_at>statement_timestamp()
    AND conflict.state IN ('retained','discarded')
    AND (conflict.state='discarded' OR conflict.expires_at>statement_timestamp())
  FOR UPDATE OF conflict,writer,payload,drive,api_session;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS conflict-discard authority';
  END IF;
  IF v_conflict.state='discarded' THEN
    RETURN v_conflict.write_session_id;
  END IF;
  IF v_conflict.payload_state<>'finalized' THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS conflict payload';
  END IF;
  UPDATE public.payload_objects SET state='abandoned'
  WHERE tenant_id=p_tenant_id AND id=v_conflict.staging_payload_id
    AND state='finalized';
  UPDATE public.drives SET reserved_bytes=reserved_bytes-v_conflict.reserved_bytes
  WHERE tenant_id=p_tenant_id AND id=v_conflict.drive_id
    AND reserved_bytes>=v_conflict.reserved_bytes;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS conflict reservation';
  END IF;
  UPDATE filebelt_mount.write_sessions
  SET state='expired',fencing_token=fencing_token+1,
      finished_at=statement_timestamp(),heartbeat_at=statement_timestamp()
  WHERE tenant_id=p_tenant_id AND id=v_conflict.write_session_id
    AND state='conflicted';
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS conflict writer';
  END IF;
  UPDATE filebelt_mount.nfs_write_conflicts
  SET state='discarded',resolved_at=statement_timestamp()
  WHERE tenant_id=p_tenant_id AND id=p_conflict_id AND state='retained';
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS conflict discard';
  END IF;
  PERFORM filebelt_mount.enqueue_nfs_staging_cleanup(
    p_tenant_id,v_conflict.write_session_id,'conflict_discarded',NULL,'cleanup'
  );
  RETURN v_conflict.write_session_id;
END
$$;

CREATE FUNCTION filebelt_mount.sweep_expired_nfs_write_conflicts(
  p_tenant_id uuid,
  p_limit integer
)
RETURNS TABLE (
  conflict_id uuid,
  write_session_id uuid,
  backend_id uuid,
  staging_payload_id uuid
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_conflict record;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_maintenance','MEMBER')
     OR p_limit NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS conflict sweep caller';
  END IF;
  FOR v_conflict IN
    SELECT conflict.id,conflict.write_session_id,conflict.drive_id,
           conflict.staging_payload_id,writer.reserved_bytes,payload.backend_id
    FROM filebelt_mount.nfs_write_conflicts AS conflict
    JOIN filebelt_mount.write_sessions AS writer
      ON writer.tenant_id=conflict.tenant_id AND writer.id=conflict.write_session_id
    JOIN public.payload_objects AS payload
      ON payload.tenant_id=conflict.tenant_id AND payload.id=conflict.staging_payload_id
    JOIN public.drives AS drive
      ON drive.tenant_id=conflict.tenant_id AND drive.id=conflict.drive_id
    WHERE conflict.tenant_id=p_tenant_id AND conflict.state='retained'
      AND conflict.expires_at<=statement_timestamp()
      AND writer.state='conflicted' AND payload.state='finalized'
    ORDER BY conflict.expires_at,conflict.id
    FOR UPDATE OF conflict,writer,payload,drive SKIP LOCKED
    LIMIT p_limit
  LOOP
    UPDATE public.payload_objects SET state='abandoned'
    WHERE tenant_id=p_tenant_id AND id=v_conflict.staging_payload_id
      AND state='finalized';
    UPDATE public.drives SET reserved_bytes=reserved_bytes-v_conflict.reserved_bytes
    WHERE tenant_id=p_tenant_id AND id=v_conflict.drive_id
      AND reserved_bytes>=v_conflict.reserved_bytes;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale expired conflict reservation';
    END IF;
    UPDATE filebelt_mount.write_sessions
    SET state='expired',fencing_token=fencing_token+1,
        finished_at=statement_timestamp(),heartbeat_at=statement_timestamp()
    WHERE tenant_id=p_tenant_id AND id=v_conflict.write_session_id
      AND state='conflicted';
    UPDATE filebelt_mount.nfs_write_conflicts
    SET state='expired',resolved_at=statement_timestamp()
    WHERE tenant_id=p_tenant_id AND id=v_conflict.id AND state='retained';
    PERFORM filebelt_mount.enqueue_nfs_staging_cleanup(
      p_tenant_id,v_conflict.write_session_id,'conflict_expired',NULL,'cleanup'
    );
    conflict_id := v_conflict.id;
    write_session_id := v_conflict.write_session_id;
    backend_id := v_conflict.backend_id;
    staging_payload_id := v_conflict.staging_payload_id;
    RETURN NEXT;
  END LOOP;
END
$$;

-- Finalize returns while the per-writer COW lock is still held. Removing that
-- inode is a distinct terminal action: it must never imply payload deletion.
-- This lease makes crash-after-finalize/before-unlink recoverable by either the
-- request worker or maintenance without exposing a staging locator.
CREATE TABLE filebelt_mount.nfs_write_lock_cleanup_jobs (
  tenant_id uuid NOT NULL,
  write_session_id uuid NOT NULL,
  backend_id uuid NOT NULL,
  staging_payload_id uuid NOT NULL,
  state text NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending','leased','completed')),
  fencing_token bigint NOT NULL DEFAULT 1 CHECK (fencing_token>0),
  lease_owner uuid,
  lease_expires_at timestamptz,
  attempts bigint NOT NULL DEFAULT 0 CHECK (attempts>=0),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  completed_by uuid,
  completed_fencing_token bigint CHECK (
    completed_fencing_token IS NULL OR completed_fencing_token>0
  ),
  completed_at timestamptz,
  PRIMARY KEY (tenant_id,write_session_id),
  FOREIGN KEY (tenant_id,write_session_id)
    REFERENCES filebelt_mount.write_sessions(tenant_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,staging_payload_id)
    REFERENCES public.payload_objects(tenant_id,id),
  FOREIGN KEY (tenant_id,backend_id)
    REFERENCES public.storage_backends(tenant_id,id),
  CHECK ((state='leased')=(lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CHECK ((state='completed')=(
    completed_by IS NOT NULL AND completed_fencing_token IS NOT NULL
    AND completed_at IS NOT NULL
  ))
);

CREATE FUNCTION filebelt_mount.enqueue_nfs_write_lock_cleanup(
  p_tenant_id uuid,
  p_write_session_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_writer record;
  v_job filebelt_mount.nfs_write_lock_cleanup_jobs%ROWTYPE;
BEGIN
  IF NOT (
       pg_has_role(session_user,'filebelt_io','MEMBER')
       OR pg_has_role(session_user,'filebelt_vfs','MEMBER')
       OR pg_has_role(session_user,'filebelt_maintenance','MEMBER')
       OR pg_has_role(session_user,'filebelt_recovery','MEMBER')
     ) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS lock-cleanup caller';
  END IF;
  SELECT payload.backend_id,writer.staging_payload_id INTO v_writer
  FROM filebelt_mount.write_sessions AS writer
  JOIN public.payload_objects AS payload
    ON payload.tenant_id=writer.tenant_id AND payload.id=writer.staging_payload_id
  WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
    AND writer.state IN ('committing','committed','conflicted','aborted','expired')
  FOR SHARE OF writer,payload;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS lock-cleanup writer';
  END IF;
  INSERT INTO filebelt_mount.nfs_write_lock_cleanup_jobs (
    tenant_id,write_session_id,backend_id,staging_payload_id
  ) VALUES (
    p_tenant_id,p_write_session_id,v_writer.backend_id,v_writer.staging_payload_id
  ) ON CONFLICT (tenant_id,write_session_id) DO NOTHING;
  SELECT * INTO STRICT v_job
  FROM filebelt_mount.nfs_write_lock_cleanup_jobs AS job
  WHERE job.tenant_id=p_tenant_id AND job.write_session_id=p_write_session_id
  FOR SHARE;
  IF v_job.backend_id IS DISTINCT FROM v_writer.backend_id
     OR v_job.staging_payload_id IS DISTINCT FROM v_writer.staging_payload_id THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS lock-cleanup identity mismatch';
  END IF;
END
$$;

CREATE FUNCTION filebelt_mount.claim_nfs_write_lock_cleanup(
  p_tenant_id uuid,
  p_backend_id uuid,
  p_write_session_id uuid,
  p_worker_id uuid
)
RETURNS TABLE (
  backend_id uuid,
  staging_payload_id uuid,
  job_fencing_token bigint,
  job_state text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_job filebelt_mount.nfs_write_lock_cleanup_jobs%ROWTYPE;
  v_staging_payload_id uuid;
BEGIN
  IF NOT (
       pg_has_role(session_user,'filebelt_io','MEMBER')
       OR pg_has_role(session_user,'filebelt_maintenance','MEMBER')
     ) OR p_worker_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS lock-cleanup worker';
  END IF;
  SELECT writer.staging_payload_id INTO v_staging_payload_id
  FROM filebelt_mount.write_sessions AS writer
  JOIN public.payload_objects AS payload
    ON payload.tenant_id=writer.tenant_id AND payload.id=writer.staging_payload_id
  WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
    AND payload.backend_id=p_backend_id
    AND writer.state IN ('committing','committed','conflicted','aborted','expired')
  FOR SHARE OF writer,payload;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS lock-cleanup identity';
  END IF;
  SELECT * INTO v_job FROM filebelt_mount.nfs_write_lock_cleanup_jobs AS job
  WHERE job.tenant_id=p_tenant_id AND job.backend_id=p_backend_id
    AND job.write_session_id=p_write_session_id
  FOR UPDATE;
  IF NOT FOUND OR v_job.staging_payload_id IS DISTINCT FROM v_staging_payload_id THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS lock-cleanup job is unavailable';
  END IF;
  IF v_job.state='completed' THEN
    RETURN QUERY SELECT v_job.backend_id,v_job.staging_payload_id,
      v_job.fencing_token,v_job.state;
    RETURN;
  END IF;
  IF v_job.state='leased' AND v_job.lease_expires_at>statement_timestamp()
     AND v_job.lease_owner IS DISTINCT FROM p_worker_id THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS lock-cleanup job is already leased';
  END IF;
  IF v_job.state<>'leased' OR v_job.lease_owner IS DISTINCT FROM p_worker_id
     OR v_job.lease_expires_at<=statement_timestamp() THEN
    UPDATE filebelt_mount.nfs_write_lock_cleanup_jobs
    SET state='leased',lease_owner=p_worker_id,
        lease_expires_at=statement_timestamp()+interval '30 seconds',
        fencing_token=fencing_token+1,attempts=attempts+1
    WHERE tenant_id=p_tenant_id AND write_session_id=p_write_session_id
      AND state IN ('pending','leased')
    RETURNING * INTO v_job;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS lock-cleanup lease changed';
    END IF;
  END IF;
  RETURN QUERY SELECT v_job.backend_id,v_job.staging_payload_id,
    v_job.fencing_token,v_job.state;
END
$$;

CREATE FUNCTION filebelt_mount.claim_next_nfs_write_lock_cleanup(
  p_tenant_id uuid,
  p_backend_id uuid,
  p_worker_id uuid
)
RETURNS TABLE (
  write_session_id uuid,
  backend_id uuid,
  staging_payload_id uuid,
  job_fencing_token bigint,
  job_state text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_write_session_id uuid;
BEGIN
  IF NOT (
       pg_has_role(session_user,'filebelt_io','MEMBER')
       OR pg_has_role(session_user,'filebelt_maintenance','MEMBER')
     ) OR p_worker_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS lock-cleanup worker';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    p_tenant_id::text || ':nfs-lock-cleanup:' || p_backend_id::text,0
  ));
  SELECT job.write_session_id INTO v_write_session_id
  FROM filebelt_mount.nfs_write_lock_cleanup_jobs AS job
  WHERE job.tenant_id=p_tenant_id AND job.backend_id=p_backend_id
    AND (job.state='pending' OR (job.state='leased' AND (
      job.lease_expires_at<=statement_timestamp()
      OR (job.lease_owner=p_worker_id AND job.lease_expires_at>statement_timestamp())
    )))
  ORDER BY (job.state='leased' AND job.lease_owner=p_worker_id
    AND job.lease_expires_at>statement_timestamp()) DESC,
    job.created_at,job.write_session_id
  LIMIT 1;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  RETURN QUERY SELECT v_write_session_id,claim.backend_id,
    claim.staging_payload_id,claim.job_fencing_token,claim.job_state
  FROM filebelt_mount.claim_nfs_write_lock_cleanup(
    p_tenant_id,p_backend_id,v_write_session_id,p_worker_id
  ) AS claim;
END
$$;

CREATE FUNCTION filebelt_mount.heartbeat_nfs_write_lock_cleanup(
  p_tenant_id uuid,
  p_backend_id uuid,
  p_write_session_id uuid,
  p_worker_id uuid,
  p_job_fencing_token bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
BEGIN
  IF NOT (
       pg_has_role(session_user,'filebelt_io','MEMBER')
       OR pg_has_role(session_user,'filebelt_maintenance','MEMBER')
     ) OR p_job_fencing_token<=0 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS lock-cleanup heartbeat caller';
  END IF;
  UPDATE filebelt_mount.nfs_write_lock_cleanup_jobs
  SET lease_expires_at=statement_timestamp()+interval '30 seconds'
  WHERE tenant_id=p_tenant_id AND backend_id=p_backend_id
    AND write_session_id=p_write_session_id AND state='leased'
    AND lease_owner=p_worker_id AND fencing_token=p_job_fencing_token
    AND lease_expires_at>statement_timestamp();
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS lock-cleanup heartbeat';
  END IF;
END
$$;

CREATE FUNCTION filebelt_mount.complete_nfs_write_lock_cleanup(
  p_tenant_id uuid,
  p_backend_id uuid,
  p_write_session_id uuid,
  p_worker_id uuid,
  p_job_fencing_token bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_job filebelt_mount.nfs_write_lock_cleanup_jobs%ROWTYPE;
  v_staging_payload_id uuid;
BEGIN
  IF NOT (
       pg_has_role(session_user,'filebelt_io','MEMBER')
       OR pg_has_role(session_user,'filebelt_maintenance','MEMBER')
     ) OR p_job_fencing_token<=0 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS lock-cleanup completion caller';
  END IF;
  SELECT writer.staging_payload_id INTO v_staging_payload_id
  FROM filebelt_mount.write_sessions AS writer
  JOIN public.payload_objects AS payload
    ON payload.tenant_id=writer.tenant_id AND payload.id=writer.staging_payload_id
  WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
    AND payload.backend_id=p_backend_id
  FOR SHARE OF writer,payload;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS lock-cleanup writer is missing';
  END IF;
  SELECT * INTO v_job FROM filebelt_mount.nfs_write_lock_cleanup_jobs AS job
  WHERE job.tenant_id=p_tenant_id AND job.backend_id=p_backend_id
    AND job.write_session_id=p_write_session_id
  FOR UPDATE;
  IF NOT FOUND OR v_job.staging_payload_id IS DISTINCT FROM v_staging_payload_id THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS lock-cleanup job is missing';
  END IF;
  IF v_job.state='completed' THEN
    IF v_job.completed_by IS DISTINCT FROM p_worker_id
       OR v_job.completed_fencing_token IS DISTINCT FROM p_job_fencing_token THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale completed NFS lock cleanup';
    END IF;
    RETURN;
  END IF;
  IF v_job.state<>'leased' OR v_job.lease_owner IS DISTINCT FROM p_worker_id
     OR v_job.fencing_token<>p_job_fencing_token
     OR v_job.lease_expires_at<=statement_timestamp() THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS lock-cleanup completion';
  END IF;
  UPDATE filebelt_mount.nfs_write_lock_cleanup_jobs
  SET state='completed',completed_at=statement_timestamp(),
      completed_by=p_worker_id,completed_fencing_token=p_job_fencing_token,
      lease_owner=NULL,lease_expires_at=NULL
  WHERE tenant_id=p_tenant_id AND write_session_id=p_write_session_id
    AND state='leased' AND fencing_token=p_job_fencing_token;
END
$$;

ALTER TABLE filebelt_mount.nfs_write_extents
  ADD CONSTRAINT nfs_write_extents_hole_digest_check
    CHECK (NOT is_hole OR digest IS NULL);

-- Replace the complete normalized sparse map under the exact writer fence.
-- VFS has no raw extent DML grant: every representation begins at byte zero,
-- is gap-free/non-overlapping, and covers the current logical size exactly.
CREATE FUNCTION filebelt_mount.replace_nfs_write_extents(
  p_tenant_id uuid,
  p_write_session_id uuid,
  p_fencing_token bigint,
  p_operation_id uuid,
  p_offsets bigint[],
  p_lengths bigint[],
  p_holes boolean[],
  p_digests bytea[]
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_logical_size bigint;
  v_count integer;
  v_index integer;
  v_expected_offset bigint := 0;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER')
     OR p_fencing_token<=0
     OR p_operation_id IS NULL
     OR p_offsets IS NULL OR p_lengths IS NULL OR p_holes IS NULL OR p_digests IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS extent caller';
  END IF;
  v_count := cardinality(p_offsets);
  IF v_count<>cardinality(p_lengths) OR v_count<>cardinality(p_holes)
     OR v_count<>cardinality(p_digests) OR v_count>1048576 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid NFS extent vector';
  END IF;
  SELECT writer.logical_size_bytes INTO v_logical_size
  FROM filebelt_mount.write_sessions AS writer
  JOIN filebelt_mount.nfs_write_operations AS operation
    ON operation.tenant_id=writer.tenant_id
   AND operation.write_session_id=writer.id
   AND operation.operation_id=p_operation_id
  WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
    AND writer.fencing_token=p_fencing_token AND writer.state='open'
    AND writer.expires_at>statement_timestamp()
    AND operation.state='io_completed'
  FOR UPDATE OF writer,operation;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS extent writer';
  END IF;
  IF v_count=0 AND v_logical_size<>0 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='nonempty NFS writer requires extents';
  END IF;
  FOR v_index IN 1..v_count LOOP
    IF p_offsets[v_index]<>v_expected_offset OR p_lengths[v_index]<=0
       OR (p_holes[v_index] AND p_digests[v_index] IS NOT NULL)
       OR (p_digests[v_index] IS NOT NULL AND octet_length(p_digests[v_index])<>32) THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='NFS extents are not normalized';
    END IF;
    v_expected_offset := v_expected_offset+p_lengths[v_index];
    IF v_expected_offset<0 OR v_expected_offset>v_logical_size THEN
      RAISE EXCEPTION USING ERRCODE='22003',MESSAGE='NFS extent length overflow';
    END IF;
  END LOOP;
  IF v_expected_offset<>v_logical_size THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='NFS extents do not cover logical size';
  END IF;
  DELETE FROM filebelt_mount.nfs_write_extents
  WHERE tenant_id=p_tenant_id AND write_session_id=p_write_session_id;
  INSERT INTO filebelt_mount.nfs_write_extents (
    tenant_id,write_session_id,offset_bytes,length_bytes,is_hole,digest
  )
  SELECT p_tenant_id,p_write_session_id,p_offsets[index_value],p_lengths[index_value],
         p_holes[index_value],p_digests[index_value]
  FROM generate_subscripts(p_offsets,1) AS subscript(index_value);
END
$$;

-- VFS is the only actor that may publish a completed byte-plane range result
-- into the protocol-visible sparse authority.  The worker receipt, immutable
-- pending protocol identity, writer fence, and planned operation are locked as
-- one unit.  The caller records the sole NFS replay receipt later in the same
-- PostgreSQL transaction; that INSERT removes the matching pending identity,
-- so a failure to persist the final protocol response rolls this transition
-- back as well.
CREATE FUNCTION filebelt_mount.apply_completed_nfs_write_operation(
  p_tenant_id uuid,
  p_write_session_id uuid,
  p_fencing_token bigint,
  p_operation_id uuid,
  p_operation text,
  p_content_blake3 bytea
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_operation_ordinal bigint;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER')
     OR p_fencing_token<=0 OR p_operation_id IS NULL
     OR p_operation NOT IN (
       'write_data','hole_deallocate','allocate','seek_data','seek_hole'
     )
     OR (p_operation='write_data')<>(p_content_blake3 IS NOT NULL)
     OR (p_content_blake3 IS NOT NULL AND octet_length(p_content_blake3)<>32) THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='invalid completed NFS range apply caller';
  END IF;
  SELECT operation.operation_ordinal INTO v_operation_ordinal
  FROM filebelt_mount.write_sessions AS writer
  JOIN filebelt_mount.nfs_write_operations AS operation
    ON operation.tenant_id=writer.tenant_id
   AND operation.write_session_id=writer.id
   AND operation.operation_id=p_operation_id
  JOIN filebelt_mount.nfs_io_receipts AS receipt
    ON receipt.tenant_id=operation.tenant_id
   AND receipt.write_session_id=operation.write_session_id
   AND receipt.operation_id=operation.operation_id
   AND receipt.operation_ordinal=operation.operation_ordinal
  JOIN filebelt_mount.nfs_pending_protocol_operations AS pending
    ON pending.tenant_id=receipt.tenant_id
   AND pending.write_session_id=receipt.write_session_id
   AND pending.protocol_operation_id=operation.operation_id
   AND pending.capability_id=receipt.capability_id
   AND pending.nonce_digest=receipt.nonce_digest
   AND pending.claims_digest=receipt.claims_digest
   AND pending.io_operation=receipt.operation
   AND pending.operation_id=receipt.operation_id
   AND pending.content_blake3 IS NOT DISTINCT FROM receipt.content_blake3
  WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
    AND writer.fencing_token=p_fencing_token AND writer.state='open'
    AND writer.expires_at>statement_timestamp()
    AND operation.operation=p_operation
    AND operation.content_blake3 IS NOT DISTINCT FROM p_content_blake3
    AND operation.state='io_completed'
    AND receipt.operation=p_operation AND receipt.state='completed'
    AND receipt.content_blake3 IS NOT DISTINCT FROM p_content_blake3
  FOR UPDATE OF writer,operation,receipt,pending;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='stale completed NFS range apply authority';
  END IF;
  UPDATE filebelt_mount.nfs_write_operations AS operation
  SET state='applied'
  WHERE operation.tenant_id=p_tenant_id
    AND operation.write_session_id=p_write_session_id
    AND operation.operation_id=p_operation_id
    AND operation.operation_ordinal=v_operation_ordinal
    AND operation.state='io_completed';
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='stale completed NFS range operation';
  END IF;
  UPDATE filebelt_mount.write_sessions AS writer
  SET heartbeat_at=statement_timestamp(),
      lease_expires_at=LEAST(writer.expires_at,statement_timestamp()+interval '30 seconds')
  WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
    AND writer.fencing_token=p_fencing_token AND writer.state='open'
    AND writer.expires_at>statement_timestamp();
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS range writer';
  END IF;
END
$$;

-- Flush has no namespace/version CAS of its own. Its client-visible success is
-- finalized here only after an exact completed worker receipt and a fresh
-- common authority check. Finalize is published by commit_nfs_write, while
-- Abort/DeleteStaging are internal phases consumed by Close/EndSession/error
-- authority and never invent an NFS client response.
CREATE FUNCTION filebelt_mount.finalize_nfs_internal_io_replay(
  p_tenant_id uuid,
  p_principal_id uuid,
  p_mount_session_id uuid,
  p_credential_id uuid,
  p_handle_id uuid,
  p_drive_id uuid,
  p_node_id uuid,
  p_version_id uuid,
  p_write_session_id uuid,
  p_credential_generation bigint,
  p_authorization_generation bigint,
  p_membership_generation bigint,
  p_drive_acl_generation bigint,
  p_namespace_generation bigint,
  p_resource_acl_generation bigint,
  p_gateway_epoch bigint,
  p_fencing_token bigint,
  p_gss_binding_digest bytea,
  p_client_id text,
  p_nfs_session_id text,
  p_slot_id integer,
  p_sequence_id bigint,
  p_operation_index integer,
  p_protocol_operation text,
  p_request_digest bytea,
  p_io_operation text,
  p_response_bytes bytea,
  p_response_digest bytea
)
RETURNS TABLE (
  response_bytes bytea,
  response_digest bytea,
  receipt_gateway_epoch bigint,
  expires_at timestamptz,
  replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_pending filebelt_mount.nfs_pending_protocol_operations%ROWTYPE;
  v_receipt filebelt_mount.nfs_replay_receipts%ROWTYPE;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER')
     OR p_io_operation<>'flush' THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='invalid NFS internal I/O finalizer caller';
  END IF;
  PERFORM filebelt_mount.validate_nfs_mutation_envelope(
    p_client_id,p_nfs_session_id,p_slot_id,p_sequence_id,p_operation_index,
    p_protocol_operation,p_request_digest,p_gateway_epoch,p_gss_binding_digest,
    p_response_bytes,p_response_digest
  );
  PERFORM filebelt_mount.prepare_nfs_replay_sequence(
    p_tenant_id,p_mount_session_id,p_client_id,p_nfs_session_id,p_slot_id,
    p_sequence_id,p_operation_index,p_gateway_epoch
  );
  SELECT * INTO v_receipt FROM filebelt_mount.nfs_replay_receipts AS receipt
  WHERE receipt.tenant_id=p_tenant_id
    AND receipt.mount_session_id=p_mount_session_id
    AND receipt.nfs_session_id=p_nfs_session_id AND receipt.slot_id=p_slot_id
    AND receipt.sequence_id=p_sequence_id
    AND receipt.operation_index=p_operation_index
  FOR UPDATE;
  IF FOUND THEN
    IF v_receipt.client_id IS DISTINCT FROM p_client_id
       OR v_receipt.operation IS DISTINCT FROM p_protocol_operation
       OR v_receipt.request_digest IS DISTINCT FROM p_request_digest
       OR v_receipt.gateway_epoch IS DISTINCT FROM p_gateway_epoch THEN
      RAISE EXCEPTION USING ERRCODE='40001',
        MESSAGE='conflicting NFS internal I/O replay';
    END IF;
    RETURN QUERY SELECT v_receipt.response_bytes,v_receipt.response_digest,
      v_receipt.gateway_epoch,v_receipt.expires_at,true;
    RETURN;
  END IF;
  IF p_gss_binding_digest IS NULL OR octet_length(p_gss_binding_digest)<>32
     OR NOT filebelt_mount.nfs_io_fence_live(
       p_tenant_id,p_principal_id,p_mount_session_id,p_credential_id,
       p_handle_id,p_drive_id,p_node_id,p_version_id,p_write_session_id,
       p_credential_generation,p_authorization_generation,p_membership_generation,
       p_drive_acl_generation,p_namespace_generation,p_resource_acl_generation,
       p_gateway_epoch,p_fencing_token,p_io_operation,false
     ) OR NOT EXISTS (
       SELECT 1 FROM filebelt_mount.sessions AS mount_session
       WHERE mount_session.tenant_id=p_tenant_id
         AND mount_session.id=p_mount_session_id
         AND mount_session.nfs_gss_binding_digest=p_gss_binding_digest
     ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='stale NFS internal I/O finalizer fence';
  END IF;
  SELECT * INTO v_pending
  FROM filebelt_mount.nfs_pending_protocol_operations AS pending
  WHERE pending.tenant_id=p_tenant_id
    AND pending.mount_session_id=p_mount_session_id
    AND pending.client_id=p_client_id
    AND pending.nfs_session_id=p_nfs_session_id AND pending.slot_id=p_slot_id
    AND pending.sequence_id=p_sequence_id
    AND pending.operation_index=p_operation_index
    AND pending.protocol_operation=p_protocol_operation
    AND pending.request_digest=p_request_digest
    AND pending.gateway_epoch=p_gateway_epoch
    AND pending.write_session_id=p_write_session_id
    AND pending.io_operation=p_io_operation
    AND pending.operation_id IS NULL
    AND pending.fencing_token=p_fencing_token
  FOR UPDATE;
  IF NOT FOUND OR NOT EXISTS (
    SELECT 1 FROM filebelt_mount.nfs_io_receipts AS worker_receipt
    WHERE worker_receipt.tenant_id=p_tenant_id
      AND worker_receipt.capability_id=v_pending.capability_id
      AND worker_receipt.nonce_digest=v_pending.nonce_digest
      AND worker_receipt.write_session_id=p_write_session_id
      AND worker_receipt.operation=p_io_operation
      AND worker_receipt.operation_id IS NULL
      AND worker_receipt.claims_digest=v_pending.claims_digest
      AND worker_receipt.state='completed'
      AND worker_receipt.outcome->>'kind'=p_io_operation
  ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='NFS internal I/O has no completed worker outcome';
  END IF;
  INSERT INTO filebelt_mount.nfs_replay_receipts (
    tenant_id,mount_session_id,client_id,nfs_session_id,slot_id,sequence_id,
    operation_index,operation,request_digest,response_bytes,response_digest,
    gateway_epoch,expires_at,mutation_outcome
  ) SELECT p_tenant_id,p_mount_session_id,p_client_id,p_nfs_session_id,p_slot_id,
           p_sequence_id,p_operation_index,p_protocol_operation,p_request_digest,
           p_response_bytes,p_response_digest,p_gateway_epoch,
           mount_session.absolute_expires_at,'applied'
    FROM filebelt_mount.sessions AS mount_session
    WHERE mount_session.tenant_id=p_tenant_id
      AND mount_session.id=p_mount_session_id
  RETURNING * INTO v_receipt;
  RETURN QUERY SELECT v_receipt.response_bytes,v_receipt.response_digest,
    v_receipt.gateway_epoch,v_receipt.expires_at,false;
END
$$;

-- Close and EndSession own the client-visible response for internal Abort or
-- cleanup work. If such work is pending for the same NFS operation, require
-- its exact byte-plane receipt to be complete and lock it until the caller's
-- final replay INSERT removes the pending protocol identity.
CREATE FUNCTION filebelt_mount.require_completed_nfs_internal_terminal(
  p_tenant_id uuid,
  p_mount_session_id uuid,
  p_client_id text,
  p_nfs_session_id text,
  p_slot_id integer,
  p_sequence_id bigint,
  p_operation_index integer,
  p_protocol_operation text,
  p_request_digest bytea,
  p_gateway_epoch bigint,
  p_handle_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_pending filebelt_mount.nfs_pending_protocol_operations%ROWTYPE;
  v_outcome_kind text;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER')
     OR p_request_digest IS NULL OR octet_length(p_request_digest)<>32 THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='invalid NFS internal terminal verifier caller';
  END IF;
  SELECT pending.* INTO v_pending
  FROM filebelt_mount.nfs_pending_protocol_operations AS pending
  JOIN filebelt_mount.write_sessions AS writer
    ON writer.tenant_id=pending.tenant_id AND writer.id=pending.write_session_id
  WHERE pending.tenant_id=p_tenant_id
    AND pending.mount_session_id=p_mount_session_id
    AND pending.client_id=p_client_id
    AND pending.nfs_session_id=p_nfs_session_id AND pending.slot_id=p_slot_id
    AND pending.sequence_id=p_sequence_id
    AND pending.operation_index=p_operation_index
    AND pending.protocol_operation=p_protocol_operation
    AND pending.request_digest=p_request_digest
    AND pending.gateway_epoch=p_gateway_epoch
    AND pending.io_operation IN ('abort','delete_staging')
    AND writer.mount_session_id=p_mount_session_id
    AND (p_handle_id IS NULL OR writer.handle_id=p_handle_id)
  FOR UPDATE OF pending,writer;
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  SELECT receipt.outcome->>'kind' INTO v_outcome_kind
  FROM filebelt_mount.nfs_io_receipts AS receipt
  WHERE receipt.tenant_id=p_tenant_id
    AND receipt.capability_id=v_pending.capability_id
    AND receipt.nonce_digest=v_pending.nonce_digest
    AND receipt.write_session_id=v_pending.write_session_id
    AND receipt.operation=v_pending.io_operation
    AND receipt.operation_id IS NULL
    AND receipt.claims_digest=v_pending.claims_digest
    AND receipt.content_blake3 IS NULL
    AND receipt.state='completed'
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='NFS internal terminal work is not complete';
  END IF;
  IF v_pending.io_operation='delete_staging' THEN
    PERFORM 1 FROM filebelt_mount.nfs_staging_cleanup_jobs AS cleanup
    WHERE cleanup.tenant_id=p_tenant_id
      AND cleanup.write_session_id=v_pending.write_session_id
      AND cleanup.source_nonce_digest=v_pending.nonce_digest
      AND cleanup.completion_kind='delete_staging'
      AND cleanup.state='completed'
    FOR SHARE;
    IF NOT FOUND OR v_outcome_kind<>'delete_staging' THEN
      RAISE EXCEPTION USING ERRCODE='40001',
        MESSAGE='NFS DeleteStaging lacks completed cleanup authority';
    END IF;
  ELSIF v_outcome_kind NOT IN ('abort','cleanup') THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='NFS internal Abort work is not complete';
  END IF;
  RETURN true;
END
$$;

-- Lock and revalidate the same authority rows used during session admission.
-- The supplied generations are the result of the common Virtual ACL decision;
-- holding these rows prevents a concurrent policy or namespace change from
-- racing the mutation.
CREATE FUNCTION filebelt_mount.authorize_nfs_operation(
  p_tenant_id uuid,
  p_mount_session_id uuid,
  p_gateway_epoch bigint,
  p_gss_binding_digest bytea,
  p_drive_id uuid,
  p_resource_id uuid,
  p_membership_generation bigint,
  p_drive_acl_generation bigint,
  p_drive_namespace_generation bigint,
  p_resource_acl_generation bigint,
  p_resource_namespace_generation bigint,
  p_require_writable boolean
)
RETURNS TABLE (user_principal_id uuid,posix_group_id uuid,restore_generation bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER')
     OR p_require_writable IS NULL
     OR p_gss_binding_digest IS NULL
     OR octet_length(p_gss_binding_digest)<>32
     OR p_gateway_epoch<=0
     OR LEAST(
       p_membership_generation,p_drive_acl_generation,
       p_drive_namespace_generation,p_resource_acl_generation,
       p_resource_namespace_generation
     )<=0 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS operation caller or fence';
  END IF;
  RETURN QUERY
  SELECT session.user_principal_id,mapping.posix_group_id,feature.restore_generation
  FROM filebelt_mount.sessions AS session
  JOIN filebelt_mount.credentials AS credential
    ON credential.tenant_id=session.tenant_id AND credential.id=session.credential_id
  JOIN filebelt_mount.policies AS policy
    ON policy.tenant_id=session.tenant_id
   AND policy.principal_id=session.user_principal_id
   AND policy.protocol='nfs'
  JOIN public.principals AS principal
    ON principal.tenant_id=session.tenant_id AND principal.id=session.user_principal_id
  JOIN public.users AS user_account
    ON user_account.tenant_id=principal.tenant_id
   AND user_account.principal_id=principal.id
  JOIN filebelt_mount.nfs_principal_mappings AS mapping
    ON mapping.tenant_id=session.tenant_id
   AND mapping.credential_id=session.credential_id
   AND mapping.principal_id=session.user_principal_id
  JOIN filebelt_mount.nfs_posix_groups AS posix_group
    ON posix_group.tenant_id=mapping.tenant_id
   AND posix_group.group_id=mapping.posix_group_id
   AND posix_group.projected_gid=mapping.projected_gid
  JOIN public.group_memberships AS membership
    ON membership.tenant_id=mapping.tenant_id
   AND membership.group_id=mapping.posix_group_id
   AND membership.user_principal_id=mapping.principal_id
  JOIN filebelt_mount.nfs_feature_state AS feature
    ON feature.tenant_id=session.tenant_id
  JOIN filebelt_mount.gateway_epochs AS gateway
    ON gateway.tenant_id=session.tenant_id
   AND gateway.protocol='nfs'
   AND gateway.gateway_id=session.gateway_id
   AND gateway.epoch=session.gateway_epoch
  JOIN public.drives AS drive
    ON drive.tenant_id=session.tenant_id AND drive.id=p_drive_id
  JOIN public.nodes AS resource
    ON resource.tenant_id=drive.tenant_id
   AND resource.drive_id=drive.id AND resource.id=p_resource_id
  JOIN filebelt_mount.nfs_exports AS export
    ON export.tenant_id=drive.tenant_id AND export.drive_id=drive.id
  WHERE session.tenant_id=p_tenant_id
    AND session.id=p_mount_session_id
    AND session.protocol='nfs'
    AND session.gateway_epoch=p_gateway_epoch
    AND session.nfs_gss_binding_digest=p_gss_binding_digest
    AND session.state IN ('active','draining')
    AND session.idle_expires_at>clock_timestamp()
    AND session.absolute_expires_at>clock_timestamp()
    AND credential.revoked_at IS NULL
    AND credential.expires_at>clock_timestamp()
    AND (NOT p_require_writable OR NOT credential.read_only)
    AND p_drive_id=ANY(credential.allowed_drive_ids)
    AND credential.credential_generation=session.credential_generation
    AND credential.authorization_generation=session.authorization_generation
    AND policy.enabled AND (NOT p_require_writable OR NOT policy.read_only)
    AND p_drive_id=ANY(policy.allowed_drive_ids)
    AND policy.authorization_generation=session.authorization_generation
    AND principal.disabled_at IS NULL
    AND principal.generation=session.membership_generation
    AND principal.generation=p_membership_generation
    AND user_account.status='active'
    AND mapping.revoked_at IS NULL
    AND mapping.generation=session.nfs_mapping_generation
    AND feature.generation=session.nfs_feature_generation
    AND feature.restore_generation=session.nfs_restore_generation
    AND session.nfs_manifest_generation=feature.manifest_generation
    AND feature.applied_manifest_generation=feature.manifest_generation
    AND feature.applied_manifest_digest IS NOT NULL
    AND feature.applied_gateway_id=session.gateway_id
    AND feature.applied_gateway_epoch=session.gateway_epoch
    AND ((session.state='active' AND feature.state='active'
          AND NOT gateway.draining AND gateway.lease_expires_at>clock_timestamp())
      OR (session.state='draining' AND feature.state IN ('active','draining')
          AND gateway.draining AND gateway.drain_deadline>clock_timestamp()))
    AND export.desired_state='active'
    AND export.applied_state='active'
    AND export.desired_generation=export.applied_generation
    AND export.export_id=ANY(session.nfs_allowed_export_ids)
    AND drive.acl_generation=p_drive_acl_generation
    AND drive.namespace_generation=p_drive_namespace_generation
    AND resource.acl_generation=p_resource_acl_generation
    AND resource.namespace_generation=p_resource_namespace_generation
    AND resource.trash_root_id IS NULL
  FOR SHARE OF session,credential,policy,principal,user_account,mapping,
    posix_group,membership,feature,gateway,drive,resource,export;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS mutation authority';
  END IF;
  UPDATE filebelt_mount.sessions
  SET last_activity_at=clock_timestamp(),
      idle_expires_at=LEAST(absolute_expires_at,clock_timestamp()+interval '15 minutes')
  WHERE tenant_id=p_tenant_id AND id=p_mount_session_id;
END
$$;

-- Preserve the established writable authority signature for every namespace,
-- lock, and content mutation. The read-open wrapper below is intentionally the
-- only path that can set require_writable=false.
CREATE FUNCTION filebelt_mount.authorize_nfs_mutation(
  p_tenant_id uuid,
  p_mount_session_id uuid,
  p_gateway_epoch bigint,
  p_gss_binding_digest bytea,
  p_drive_id uuid,
  p_resource_id uuid,
  p_membership_generation bigint,
  p_drive_acl_generation bigint,
  p_drive_namespace_generation bigint,
  p_resource_acl_generation bigint,
  p_resource_namespace_generation bigint
)
RETURNS TABLE (user_principal_id uuid,posix_group_id uuid,restore_generation bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
BEGIN
  RETURN QUERY
  SELECT * FROM filebelt_mount.authorize_nfs_operation(
    p_tenant_id,p_mount_session_id,p_gateway_epoch,p_gss_binding_digest,
    p_drive_id,p_resource_id,p_membership_generation,p_drive_acl_generation,
    p_drive_namespace_generation,p_resource_acl_generation,
    p_resource_namespace_generation,true
  );
END
$$;

CREATE FUNCTION filebelt_mount.authorize_nfs_handle_open(
  p_tenant_id uuid,
  p_mount_session_id uuid,
  p_gateway_epoch bigint,
  p_gss_binding_digest bytea,
  p_drive_id uuid,
  p_resource_id uuid,
  p_membership_generation bigint,
  p_drive_acl_generation bigint,
  p_drive_namespace_generation bigint,
  p_resource_acl_generation bigint,
  p_resource_namespace_generation bigint,
  p_access_actions text[]
)
RETURNS TABLE (user_principal_id uuid,posix_group_id uuid,restore_generation bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
BEGIN
  IF p_access_actions IS NULL
     OR cardinality(p_access_actions) NOT BETWEEN 1 AND 2
     OR EXISTS (
       SELECT 1 FROM unnest(p_access_actions) AS action
       WHERE action NOT IN ('READ_METADATA','READ_CONTENT')
     )
     OR cardinality(p_access_actions)<>(
       SELECT count(DISTINCT action) FROM unnest(p_access_actions) AS action
     ) THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='NFS read-open authority accepts only unique read actions';
  END IF;
  RETURN QUERY
  SELECT * FROM filebelt_mount.authorize_nfs_operation(
    p_tenant_id,p_mount_session_id,p_gateway_epoch,p_gss_binding_digest,
    p_drive_id,p_resource_id,p_membership_generation,p_drive_acl_generation,
    p_drive_namespace_generation,p_resource_acl_generation,
    p_resource_namespace_generation,false
  );
END
$$;

CREATE FUNCTION filebelt_mount.validate_nfs_mutation_envelope(
  p_client_id text,
  p_nfs_session_id text,
  p_slot_id integer,
  p_sequence_id bigint,
  p_operation_index integer,
  p_operation text,
  p_request_digest bytea,
  p_gateway_epoch bigint,
  p_gss_binding_digest bytea,
  p_response_bytes bytea,
  p_response_digest bytea
)
RETURNS void
LANGUAGE plpgsql
SET search_path=pg_catalog
AS $$
BEGIN
  IF p_client_id IS NULL OR length(p_client_id) NOT BETWEEN 1 AND 255
     OR p_client_id !~ '^[A-Za-z0-9_.:@-]+$'
     OR p_nfs_session_id IS NULL OR length(p_nfs_session_id) NOT BETWEEN 1 AND 255
     OR p_nfs_session_id !~ '^[A-Za-z0-9_.:@-]+$'
     OR p_slot_id NOT BETWEEN 0 AND 1023
     OR p_sequence_id<=0
     OR p_operation_index NOT BETWEEN 0 AND 63
     OR p_operation IS NULL OR p_operation !~ '^[a-z][a-z0-9_]{0,63}$'
     OR p_request_digest IS NULL OR octet_length(p_request_digest)<>32
     OR p_gateway_epoch<=0
     OR p_gss_binding_digest IS NULL OR octet_length(p_gss_binding_digest)<>32
     OR p_response_bytes IS NULL OR octet_length(p_response_bytes) NOT BETWEEN 1 AND 1114112
     OR p_response_digest IS NULL OR octet_length(p_response_digest)<>32 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid NFS mutation replay envelope';
  END IF;
END
$$;

-- Creates the one authoritative writer for a live NFS handle. The stable
-- caller-selected IDs make an exact retry idempotent; a mismatched retry is a
-- conflict. Quota reservation, staging payload, and writer fence commit
-- together so no capability can point at a half-created writer.
CREATE FUNCTION filebelt_mount.start_nfs_write(
  p_tenant_id uuid,
  p_mount_session_id uuid,
  p_gateway_epoch bigint,
  p_gss_binding_digest bytea,
  p_handle_id uuid,
  p_drive_id uuid,
  p_node_id uuid,
  p_membership_generation bigint,
  p_drive_acl_generation bigint,
  p_drive_namespace_generation bigint,
  p_resource_acl_generation bigint,
  p_resource_namespace_generation bigint,
  p_expected_head_version_id uuid,
  p_write_session_id uuid,
  p_staging_payload_id uuid,
  p_backend_id uuid,
  p_staging_locator uuid,
  p_reserved_bytes bigint
)
RETURNS TABLE (
  write_session_id uuid,
  staging_payload_id uuid,
  fencing_token bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_authority record;
  v_existing record;
  v_session_absolute timestamptz;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER')
     OR p_reserved_bytes<0 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS write-session caller';
  END IF;
  SELECT * INTO STRICT v_authority
  FROM filebelt_mount.authorize_nfs_mutation(
    p_tenant_id,p_mount_session_id,p_gateway_epoch,p_gss_binding_digest,
    p_drive_id,p_node_id,p_membership_generation,p_drive_acl_generation,
    p_drive_namespace_generation,p_resource_acl_generation,
    p_resource_namespace_generation
  );
  SELECT write_session.id,write_session.staging_payload_id,
         write_session.fencing_token,write_session.drive_id,write_session.node_id,
         write_session.base_version_id,write_session.expected_head_version_id,
         write_session.reserved_bytes,payload.backend_id,payload.locator
  INTO v_existing
  FROM filebelt_mount.write_sessions AS write_session
  JOIN public.payload_objects AS payload
    ON payload.tenant_id=write_session.tenant_id
   AND payload.id=write_session.staging_payload_id
  WHERE write_session.tenant_id=p_tenant_id
    AND write_session.handle_id=p_handle_id
  FOR UPDATE OF write_session,payload;
  IF FOUND THEN
    IF v_existing.id IS DISTINCT FROM p_write_session_id
       OR v_existing.staging_payload_id IS DISTINCT FROM p_staging_payload_id
       OR v_existing.drive_id IS DISTINCT FROM p_drive_id
       OR v_existing.node_id IS DISTINCT FROM p_node_id
       OR v_existing.base_version_id IS DISTINCT FROM p_expected_head_version_id
       OR v_existing.expected_head_version_id IS DISTINCT FROM p_expected_head_version_id
       OR v_existing.reserved_bytes IS DISTINCT FROM p_reserved_bytes
       OR v_existing.backend_id IS DISTINCT FROM p_backend_id
       OR v_existing.locator IS DISTINCT FROM p_staging_locator THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS write-session retry mismatch';
    END IF;
    RETURN QUERY SELECT v_existing.id,v_existing.staging_payload_id,v_existing.fencing_token;
    RETURN;
  END IF;
  SELECT session.absolute_expires_at INTO v_session_absolute
  FROM filebelt_mount.handles AS handle
  JOIN filebelt_mount.sessions AS session
    ON session.tenant_id=handle.tenant_id AND session.id=handle.session_id
  JOIN public.nodes AS node
    ON node.tenant_id=handle.tenant_id AND node.drive_id=handle.drive_id
   AND node.id=handle.node_id
  WHERE handle.tenant_id=p_tenant_id AND handle.id=p_handle_id
    AND handle.session_id=p_mount_session_id AND handle.drive_id=p_drive_id
    AND handle.node_id=p_node_id AND handle.closed_at IS NULL
    AND handle.expires_at>clock_timestamp()
    AND 'WRITE_CONTENT'=ANY(handle.access_actions)
    AND 'CREATE_VERSION'=ANY(handle.access_actions)
    AND handle.gateway_epoch=p_gateway_epoch
    AND handle.membership_generation=p_membership_generation
    AND handle.drive_acl_generation=p_drive_acl_generation
    AND handle.namespace_generation=p_resource_namespace_generation
    AND handle.resource_acl_generation=p_resource_acl_generation
    AND handle.version_id IS NOT DISTINCT FROM p_expected_head_version_id
    AND node.head_version_id IS NOT DISTINCT FROM p_expected_head_version_id
    AND node.kind='file' AND node.trash_root_id IS NULL
  FOR UPDATE OF handle,session,node;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS writable handle';
  END IF;
  PERFORM 1 FROM public.storage_backends AS backend
  WHERE backend.tenant_id=p_tenant_id AND backend.id=p_backend_id
    AND backend.kind='posix' AND backend.storage_ready
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='NFS staging backend is unavailable';
  END IF;
  UPDATE public.drives SET reserved_bytes=reserved_bytes+p_reserved_bytes
  WHERE tenant_id=p_tenant_id AND id=p_drive_id
    AND used_physical_bytes+reserved_bytes+p_reserved_bytes<=quota_bytes;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='53100',MESSAGE='NFS write reservation exceeds drive quota';
  END IF;
  INSERT INTO public.payload_objects (
    tenant_id,id,drive_id,backend_id,locator,layout,state,size_bytes
  ) VALUES (
    p_tenant_id,p_staging_payload_id,p_drive_id,p_backend_id,
    p_staging_locator,'chunked','staging',0
  );
  INSERT INTO filebelt_mount.write_sessions (
    tenant_id,id,mount_session_id,handle_id,drive_id,node_id,base_version_id,
    expected_head_version_id,staging_payload_id,declared_size_bytes,
    logical_size_bytes,reserved_bytes,state,fencing_token,gateway_epoch,
    authorization_generation,lease_expires_at,expires_at
  ) SELECT
    p_tenant_id,p_write_session_id,p_mount_session_id,p_handle_id,p_drive_id,
    p_node_id,p_expected_head_version_id,p_expected_head_version_id,
    p_staging_payload_id,p_reserved_bytes,0,p_reserved_bytes,'open',1,
    p_gateway_epoch,session.authorization_generation,
    LEAST(v_session_absolute,clock_timestamp()+interval '30 seconds'),
    LEAST(v_session_absolute,clock_timestamp()+interval '4 hours')
  FROM filebelt_mount.sessions AS session
  WHERE session.tenant_id=p_tenant_id AND session.id=p_mount_session_id;
  INSERT INTO filebelt_mount.nfs_write_extents (
    tenant_id,write_session_id,offset_bytes,length_bytes,is_hole,digest
  )
  SELECT p_tenant_id,p_write_session_id,0,version.size_bytes,false,version.blake3
  FROM public.file_versions AS version
  WHERE version.tenant_id=p_tenant_id AND version.node_id=p_node_id
    AND version.id=p_expected_head_version_id AND version.size_bytes>0;
  INSERT INTO public.audit_events (
    tenant_id,id,actor_principal_id,resource_id,action,outcome,reason_code,
    privacy_visible,details
  ) VALUES (
    p_tenant_id,gen_random_uuid(),v_authority.user_principal_id,p_node_id,
    'mount.nfs.write.start','allowed','writable_handle_admitted',false,
    jsonb_build_object('write_session_id',p_write_session_id,
      'reserved_bytes',p_reserved_bytes)
  );
  RETURN QUERY SELECT p_write_session_id,p_staging_payload_id,1::bigint;
END
$$;

-- The byte worker can acknowledge a completed physical abort without gaining
-- writable access to drive quota columns. The exact writer/payload/drive rows
-- are locked and the reservation is released once.
CREATE FUNCTION filebelt_mount.finish_nfs_write_abort(
  p_tenant_id uuid,
  p_write_session_id uuid,
  p_fencing_token bigint
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_write record;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_io','MEMBER') OR p_fencing_token<=0 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid mount write-abort caller';
  END IF;
  SELECT write_session.state,write_session.drive_id,write_session.staging_payload_id,
         write_session.reserved_bytes,payload.state AS payload_state
  INTO v_write
  FROM filebelt_mount.write_sessions AS write_session
  JOIN public.payload_objects AS payload
    ON payload.tenant_id=write_session.tenant_id
   AND payload.id=write_session.staging_payload_id
  JOIN public.drives AS drive
    ON drive.tenant_id=write_session.tenant_id AND drive.id=write_session.drive_id
  WHERE write_session.tenant_id=p_tenant_id
    AND write_session.id=p_write_session_id
    AND write_session.fencing_token=p_fencing_token
    AND write_session.state IN ('aborting','aborted')
  FOR UPDATE OF write_session,payload,drive;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale mount write abort';
  END IF;
  IF v_write.state='aborted' THEN
    IF v_write.payload_state<>'abandoned' THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='inconsistent completed mount abort';
    END IF;
    RETURN v_write.staging_payload_id;
  END IF;
  IF v_write.payload_state NOT IN ('staging','finalized') THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale mount staging payload abort';
  END IF;
  UPDATE public.payload_objects SET state='abandoned'
  WHERE tenant_id=p_tenant_id AND id=v_write.staging_payload_id
    AND state IN ('staging','finalized');
  UPDATE filebelt_mount.write_sessions
  SET state='aborted',finished_at=clock_timestamp(),heartbeat_at=clock_timestamp()
  WHERE tenant_id=p_tenant_id AND id=p_write_session_id
    AND fencing_token=p_fencing_token AND state='aborting';
  UPDATE public.drives SET reserved_bytes=reserved_bytes-v_write.reserved_bytes
  WHERE tenant_id=p_tenant_id AND id=v_write.drive_id
    AND reserved_bytes>=v_write.reserved_bytes;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale mount write reservation';
  END IF;
  PERFORM filebelt_mount.enqueue_nfs_staging_cleanup(
    p_tenant_id,p_write_session_id,'write_aborted',NULL
  );
  RETURN v_write.staging_payload_id;
END
$$;

-- NFS write admission is itself a replayed protocol mutation. The wrapper
-- makes quota reservation, staging identity, writer creation, and the exact
-- protobuf response one transaction; the lower-level creator remains private.
CREATE FUNCTION filebelt_mount.start_nfs_write_replayed(
  p_tenant_id uuid,
  p_mount_session_id uuid,
  p_gateway_epoch bigint,
  p_gss_binding_digest bytea,
  p_handle_id uuid,
  p_drive_id uuid,
  p_node_id uuid,
  p_membership_generation bigint,
  p_drive_acl_generation bigint,
  p_drive_namespace_generation bigint,
  p_resource_acl_generation bigint,
  p_resource_namespace_generation bigint,
  p_expected_head_version_id uuid,
  p_write_session_id uuid,
  p_staging_payload_id uuid,
  p_backend_id uuid,
  p_staging_locator uuid,
  p_reserved_bytes bigint,
  p_client_id text,
  p_nfs_session_id text,
  p_slot_id integer,
  p_sequence_id bigint,
  p_operation_index integer,
  p_request_digest bytea,
  p_response_bytes bytea,
  p_response_digest bytea
)
RETURNS TABLE (
  write_session_id uuid,
  staging_payload_id uuid,
  fencing_token bigint,
  receipt_response_bytes bytea,
  receipt_response_digest bytea,
  receipt_gateway_epoch bigint,
  receipt_expires_at timestamptz,
  replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_receipt filebelt_mount.nfs_replay_receipts%ROWTYPE;
  v_started record;
  v_replayed_write_session_id uuid;
  v_replayed_staging_payload_id uuid;
  v_replayed_fencing_token bigint;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER') THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid replayed NFS write caller';
  END IF;
  PERFORM filebelt_mount.validate_nfs_mutation_envelope(
    p_client_id,p_nfs_session_id,p_slot_id,p_sequence_id,p_operation_index,
    'start_write',p_request_digest,p_gateway_epoch,p_gss_binding_digest,
    p_response_bytes,p_response_digest
  );
  PERFORM filebelt_mount.prepare_nfs_replay_sequence(
    p_tenant_id,p_mount_session_id,p_client_id,p_nfs_session_id,p_slot_id,
    p_sequence_id,p_operation_index,p_gateway_epoch
  );
  SELECT * INTO v_receipt
  FROM filebelt_mount.nfs_replay_receipts AS receipt
  WHERE receipt.tenant_id=p_tenant_id
    AND receipt.mount_session_id=p_mount_session_id
    AND receipt.nfs_session_id=p_nfs_session_id
    AND receipt.slot_id=p_slot_id AND receipt.sequence_id=p_sequence_id
    AND receipt.operation_index=p_operation_index
  FOR UPDATE;
  IF FOUND THEN
    IF v_receipt.client_id IS DISTINCT FROM p_client_id
       OR v_receipt.operation IS DISTINCT FROM 'start_write'
       OR v_receipt.request_digest IS DISTINCT FROM p_request_digest
       OR v_receipt.gateway_epoch IS DISTINCT FROM p_gateway_epoch THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS replay identity context mismatch';
    END IF;
    BEGIN
      v_replayed_write_session_id :=
        (v_receipt.mutation_result->>'write_session_id')::uuid;
      v_replayed_staging_payload_id :=
        (v_receipt.mutation_result->>'staging_payload_id')::uuid;
      v_replayed_fencing_token :=
        (v_receipt.mutation_result->>'fencing_token')::bigint;
    EXCEPTION WHEN others THEN
      RAISE EXCEPTION USING ERRCODE='55000',
        MESSAGE='persisted NFS start-write replay result is invalid';
    END;
    IF (v_receipt.mutation_result->>'handle_id')::uuid IS DISTINCT FROM p_handle_id
       OR (v_receipt.mutation_result->>'drive_id')::uuid IS DISTINCT FROM p_drive_id
       OR (v_receipt.mutation_result->>'node_id')::uuid IS DISTINCT FROM p_node_id
       OR v_replayed_fencing_token<=0 THEN
      RAISE EXCEPTION USING ERRCODE='40001',
        MESSAGE='NFS start-write replay request authority mismatch';
    END IF;
    SELECT writer.id,writer.staging_payload_id INTO STRICT v_started
    FROM filebelt_mount.write_sessions AS writer
    WHERE writer.tenant_id=p_tenant_id AND writer.id=v_replayed_write_session_id
      AND writer.staging_payload_id=v_replayed_staging_payload_id
      AND writer.mount_session_id=p_mount_session_id AND writer.handle_id=p_handle_id
      AND writer.drive_id=p_drive_id AND writer.node_id=p_node_id;
    RETURN QUERY SELECT v_started.id,v_started.staging_payload_id,
      v_replayed_fencing_token,
      v_receipt.response_bytes,v_receipt.response_digest,v_receipt.gateway_epoch,
      v_receipt.expires_at,true;
    RETURN;
  END IF;
  SELECT * INTO STRICT v_started FROM filebelt_mount.start_nfs_write(
    p_tenant_id,p_mount_session_id,p_gateway_epoch,p_gss_binding_digest,
    p_handle_id,p_drive_id,p_node_id,p_membership_generation,
    p_drive_acl_generation,p_drive_namespace_generation,p_resource_acl_generation,
    p_resource_namespace_generation,p_expected_head_version_id,p_write_session_id,
    p_staging_payload_id,p_backend_id,p_staging_locator,p_reserved_bytes
  );
  INSERT INTO filebelt_mount.nfs_replay_receipts (
    tenant_id,mount_session_id,client_id,nfs_session_id,slot_id,sequence_id,
    operation_index,operation,request_digest,response_bytes,response_digest,
    gateway_epoch,expires_at,mutation_outcome,mutation_result
  ) VALUES (
    p_tenant_id,p_mount_session_id,p_client_id,p_nfs_session_id,p_slot_id,
    p_sequence_id,p_operation_index,'start_write',p_request_digest,p_response_bytes,
    p_response_digest,p_gateway_epoch,(SELECT session.absolute_expires_at
      FROM filebelt_mount.sessions AS session
      WHERE session.tenant_id=p_tenant_id AND session.id=p_mount_session_id),'applied',
    jsonb_build_object('write_session_id',p_write_session_id,
      'staging_payload_id',p_staging_payload_id,'fencing_token',v_started.fencing_token,
      'handle_id',p_handle_id,'drive_id',p_drive_id,'node_id',p_node_id)
  ) RETURNING * INTO v_receipt;
  RETURN QUERY SELECT v_started.write_session_id,v_started.staging_payload_id,
    v_started.fencing_token,v_receipt.response_bytes,v_receipt.response_digest,
    v_receipt.gateway_epoch,v_receipt.expires_at,false;
END
$$;

-- Grows, but never shrinks, the reservation for one already-admitted writer.
-- VFS calls this in the same transaction as the replay receipt and immutable
-- prefix chunk-plan update; the byte worker receives no quota write grant.
CREATE FUNCTION filebelt_mount.reserve_nfs_write_bytes(
  p_tenant_id uuid,
  p_write_session_id uuid,
  p_fencing_token bigint,
  p_required_bytes bigint
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_write record;
  v_delta bigint;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER')
     OR p_fencing_token<=0 OR p_required_bytes<0 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS reservation caller';
  END IF;
  SELECT writer.drive_id,writer.reserved_bytes INTO v_write
  FROM filebelt_mount.write_sessions AS writer
  JOIN public.drives AS drive
    ON drive.tenant_id=writer.tenant_id AND drive.id=writer.drive_id
  WHERE writer.tenant_id=p_tenant_id AND writer.id=p_write_session_id
    AND writer.fencing_token=p_fencing_token AND writer.state='open'
  FOR UPDATE OF writer,drive;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS write reservation';
  END IF;
  IF p_required_bytes<v_write.reserved_bytes THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='NFS write reservation cannot shrink';
  END IF;
  v_delta := p_required_bytes-v_write.reserved_bytes;
  IF v_delta>0 THEN
    UPDATE public.drives SET reserved_bytes=reserved_bytes+v_delta
    WHERE tenant_id=p_tenant_id AND id=v_write.drive_id
      AND used_physical_bytes+reserved_bytes+v_delta<=quota_bytes;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='53100',MESSAGE='NFS write reservation exceeds drive quota';
    END IF;
    UPDATE filebelt_mount.write_sessions
    SET reserved_bytes=p_required_bytes,declared_size_bytes=p_required_bytes,
        heartbeat_at=clock_timestamp()
    WHERE tenant_id=p_tenant_id AND id=p_write_session_id
      AND fencing_token=p_fencing_token AND state='open';
  END IF;
  RETURN p_required_bytes;
END
$$;

-- Apply one namespace mutation and its exact protobuf replay receipt under one
-- transaction. Caller-provided UUIDs make successful responses deterministic;
-- an existing replay identity returns the persisted response without mutation.
CREATE FUNCTION filebelt_mount.mutate_nfs_namespace(
  p_tenant_id uuid,
  p_mount_session_id uuid,
  p_client_id text,
  p_nfs_session_id text,
  p_slot_id integer,
  p_sequence_id bigint,
  p_operation_index integer,
  p_operation text,
  p_request_digest bytea,
  p_gateway_epoch bigint,
  p_gss_binding_digest bytea,
  p_mutation jsonb,
  p_response_bytes bytea,
  p_response_digest bytea
)
RETURNS TABLE (
  response_bytes bytea,
  response_digest bytea,
  receipt_gateway_epoch bigint,
  expires_at timestamptz,
  replayed boolean,
  mutation_outcome text,
  resource_id uuid,
  resource_generation bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_receipt filebelt_mount.nfs_replay_receipts%ROWTYPE;
  v_session record;
  v_target_session record;
  v_drive_id uuid;
  v_resource_id uuid;
  v_parent_id uuid;
  v_target_parent_id uuid;
  v_declared_old_parent_id uuid;
  v_node_id uuid;
  v_old_parent_id uuid;
  v_display_name text;
  v_name_key text;
  v_kind text;
  v_symlink_target text;
  v_expected_generation bigint;
  v_target_expected_generation bigint;
  v_generation bigint;
  v_mode integer;
  v_owner_principal_id uuid;
  v_group_id uuid;
  v_atime timestamptz;
  v_mtime timestamptz;
  v_xattr_name text;
  v_xattr_value bytea;
  v_create_only boolean;
  v_replace_only boolean;
  v_acl_entry jsonb;
  v_acl_count integer := 0;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER') THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='caller is not a FileBelt VFS database principal';
  END IF;
  PERFORM filebelt_mount.validate_nfs_mutation_envelope(
    p_client_id,p_nfs_session_id,p_slot_id,p_sequence_id,p_operation_index,
    p_operation,p_request_digest,p_gateway_epoch,p_gss_binding_digest,
    p_response_bytes,p_response_digest
  );
  IF p_mutation IS NULL OR jsonb_typeof(p_mutation)<>'object'
     OR p_operation NOT IN (
       'create','mkdir','symlink','rename','remove','set_attributes',
       'set_xattr','remove_xattr','set_acl'
     ) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid NFS namespace mutation';
  END IF;

  PERFORM filebelt_mount.prepare_nfs_replay_sequence(
    p_tenant_id,p_mount_session_id,p_client_id,p_nfs_session_id,p_slot_id,
    p_sequence_id,p_operation_index,p_gateway_epoch
  );
  SELECT * INTO v_receipt
  FROM filebelt_mount.nfs_replay_receipts AS receipt
  WHERE receipt.tenant_id=p_tenant_id
    AND receipt.mount_session_id=p_mount_session_id
    AND receipt.nfs_session_id=p_nfs_session_id
    AND receipt.slot_id=p_slot_id
    AND receipt.sequence_id=p_sequence_id
    AND receipt.operation_index=p_operation_index
  FOR UPDATE;
  IF FOUND THEN
    IF v_receipt.client_id IS DISTINCT FROM p_client_id
       OR v_receipt.operation IS DISTINCT FROM p_operation
       OR v_receipt.request_digest IS DISTINCT FROM p_request_digest
       OR v_receipt.gateway_epoch IS DISTINCT FROM p_gateway_epoch THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS replay identity context mismatch';
    END IF;
    RETURN QUERY SELECT v_receipt.response_bytes,v_receipt.response_digest,
      v_receipt.gateway_epoch,v_receipt.expires_at,true,
      COALESCE(v_receipt.mutation_outcome,'applied'),NULL::uuid,NULL::bigint;
    RETURN;
  END IF;

  v_drive_id := (p_mutation->>'drive_id')::uuid;
  v_resource_id := (p_mutation->>'resource_id')::uuid;
  SELECT * INTO STRICT v_session
  FROM filebelt_mount.authorize_nfs_mutation(
    p_tenant_id,p_mount_session_id,p_gateway_epoch,p_gss_binding_digest,
    v_drive_id,v_resource_id,
    (p_mutation->>'membership_generation')::bigint,
    (p_mutation->>'drive_acl_generation')::bigint,
    (p_mutation->>'drive_namespace_generation')::bigint,
    (p_mutation->>'resource_acl_generation')::bigint,
    (p_mutation->>'resource_namespace_generation')::bigint
  );

  IF p_operation IN ('create','mkdir','symlink') THEN
    v_parent_id := v_resource_id;
    v_node_id := (p_mutation->>'node_id')::uuid;
    v_display_name := p_mutation->>'display_name';
    v_name_key := p_mutation->>'name_key';
    v_expected_generation := (p_mutation->>'resource_namespace_generation')::bigint;
    v_kind := CASE p_operation WHEN 'create' THEN 'file' WHEN 'mkdir' THEN 'directory' ELSE 'symlink' END;
    v_symlink_target := CASE WHEN v_kind='symlink' THEN p_mutation->>'symlink_target' END;
    v_mode := COALESCE((p_mutation->>'mode')::integer,CASE v_kind
      WHEN 'directory' THEN 493 WHEN 'symlink' THEN 511 ELSE 420 END);
    PERFORM 1 FROM public.nodes
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id AND id=v_parent_id
      AND kind='directory' AND trash_root_id IS NULL
      AND namespace_generation=v_expected_generation
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS parent namespace';
    END IF;
    INSERT INTO public.nodes (
      tenant_id,drive_id,id,parent_id,kind,display_name,name_key,
      owner_principal_id,posix_group_id,posix_mode,symlink_target
    ) VALUES (
      p_tenant_id,v_drive_id,v_node_id,v_parent_id,v_kind,v_display_name,v_name_key,
      v_session.user_principal_id,v_session.posix_group_id,v_mode,v_symlink_target
    );
    INSERT INTO public.node_ancestry (
      tenant_id,drive_id,ancestor_id,descendant_id,depth
    )
    SELECT tenant_id,drive_id,ancestor_id,v_node_id,depth+1
    FROM public.node_ancestry
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id AND descendant_id=v_parent_id
    UNION ALL SELECT p_tenant_id,v_drive_id,v_node_id,v_node_id,0;
    UPDATE public.nodes SET namespace_generation=namespace_generation+1,
      changed_at=clock_timestamp(),updated_at=clock_timestamp()
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id AND id=v_parent_id;
    UPDATE public.drives SET namespace_generation=namespace_generation+1
    WHERE tenant_id=p_tenant_id AND id=v_drive_id;
    v_resource_id := v_node_id;
    SELECT namespace_generation INTO v_generation FROM public.nodes
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id AND id=v_node_id;
  ELSIF p_operation='rename' THEN
    v_target_parent_id := (p_mutation->>'target_parent_id')::uuid;
    v_declared_old_parent_id := (p_mutation->>'old_parent_id')::uuid;
    v_display_name := p_mutation->>'display_name';
    v_name_key := p_mutation->>'name_key';
    v_expected_generation := (p_mutation->>'resource_namespace_generation')::bigint;
    v_target_expected_generation := (p_mutation->>'target_parent_namespace_generation')::bigint;
    SELECT * INTO STRICT v_target_session
    FROM filebelt_mount.authorize_nfs_mutation(
      p_tenant_id,p_mount_session_id,p_gateway_epoch,p_gss_binding_digest,
      v_drive_id,v_target_parent_id,
      (p_mutation->>'membership_generation')::bigint,
      (p_mutation->>'drive_acl_generation')::bigint,
      (p_mutation->>'drive_namespace_generation')::bigint,
      (p_mutation->>'target_parent_acl_generation')::bigint,
      v_target_expected_generation
    );
    SELECT * INTO STRICT v_target_session
    FROM filebelt_mount.authorize_nfs_mutation(
      p_tenant_id,p_mount_session_id,p_gateway_epoch,p_gss_binding_digest,
      v_drive_id,v_declared_old_parent_id,
      (p_mutation->>'membership_generation')::bigint,
      (p_mutation->>'drive_acl_generation')::bigint,
      (p_mutation->>'drive_namespace_generation')::bigint,
      (p_mutation->>'old_parent_acl_generation')::bigint,
      (p_mutation->>'old_parent_namespace_generation')::bigint
    );
    SELECT parent_id INTO v_old_parent_id FROM public.nodes
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id AND id=v_resource_id
      AND parent_id IS NOT NULL AND trash_root_id IS NULL
      AND namespace_generation=v_expected_generation
    FOR UPDATE;
    IF NOT FOUND OR v_old_parent_id IS DISTINCT FROM v_declared_old_parent_id OR EXISTS (
      SELECT 1 FROM public.node_ancestry
      WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id
        AND ancestor_id=v_resource_id AND descendant_id=v_target_parent_id
    ) THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale or cyclic NFS rename';
    END IF;
    PERFORM 1 FROM public.nodes
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id AND id=v_target_parent_id
      AND kind='directory' AND trash_root_id IS NULL
      AND namespace_generation=v_target_expected_generation
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS rename target';
    END IF;
    IF v_old_parent_id IS DISTINCT FROM v_target_parent_id THEN
      DELETE FROM public.node_ancestry AS path
      USING public.node_ancestry AS old_ancestor,
            public.node_ancestry AS subtree
      WHERE old_ancestor.tenant_id=p_tenant_id
        AND old_ancestor.drive_id=v_drive_id
        AND old_ancestor.descendant_id=v_resource_id
        AND old_ancestor.ancestor_id<>v_resource_id
        AND subtree.tenant_id=p_tenant_id
        AND subtree.drive_id=v_drive_id
        AND subtree.ancestor_id=v_resource_id
        AND path.tenant_id=p_tenant_id
        AND path.drive_id=v_drive_id
        AND path.ancestor_id=old_ancestor.ancestor_id
        AND path.descendant_id=subtree.descendant_id;
      INSERT INTO public.node_ancestry (
        tenant_id,drive_id,ancestor_id,descendant_id,depth
      )
      SELECT p_tenant_id,v_drive_id,target_path.ancestor_id,
        subtree.descendant_id,target_path.depth+1+subtree.depth
      FROM public.node_ancestry AS target_path
      CROSS JOIN public.node_ancestry AS subtree
      WHERE target_path.tenant_id=p_tenant_id
        AND target_path.drive_id=v_drive_id
        AND target_path.descendant_id=v_target_parent_id
        AND subtree.tenant_id=p_tenant_id
        AND subtree.drive_id=v_drive_id
        AND subtree.ancestor_id=v_resource_id;
    END IF;
    UPDATE public.nodes SET parent_id=v_target_parent_id,display_name=v_display_name,
      name_key=v_name_key,namespace_generation=namespace_generation+1,
      changed_at=clock_timestamp(),updated_at=clock_timestamp()
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id AND id=v_resource_id
    RETURNING namespace_generation INTO v_generation;
    UPDATE public.nodes SET namespace_generation=namespace_generation+1,
      changed_at=clock_timestamp(),updated_at=clock_timestamp()
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id
      AND id IN (v_old_parent_id,v_target_parent_id) AND id<>v_resource_id;
    UPDATE public.drives SET namespace_generation=namespace_generation+1
    WHERE tenant_id=p_tenant_id AND id=v_drive_id;
  ELSIF p_operation='remove' THEN
    v_expected_generation := (p_mutation->>'resource_namespace_generation')::bigint;
    v_declared_old_parent_id := (p_mutation->>'parent_id')::uuid;
    SELECT * INTO STRICT v_target_session
    FROM filebelt_mount.authorize_nfs_mutation(
      p_tenant_id,p_mount_session_id,p_gateway_epoch,p_gss_binding_digest,
      v_drive_id,v_declared_old_parent_id,
      (p_mutation->>'membership_generation')::bigint,
      (p_mutation->>'drive_acl_generation')::bigint,
      (p_mutation->>'drive_namespace_generation')::bigint,
      (p_mutation->>'parent_acl_generation')::bigint,
      (p_mutation->>'parent_namespace_generation')::bigint
    );
    SELECT node.parent_id,drive.trash_retention_days
      INTO v_old_parent_id,v_mode
    FROM public.nodes AS node
    JOIN public.drives AS drive
      ON drive.tenant_id=node.tenant_id AND drive.id=node.drive_id
    WHERE node.tenant_id=p_tenant_id AND node.drive_id=v_drive_id
      AND node.id=v_resource_id AND node.parent_id IS NOT NULL
      AND node.trash_root_id IS NULL
      AND node.namespace_generation=v_expected_generation
    FOR UPDATE OF node;
    IF NOT FOUND OR v_old_parent_id IS DISTINCT FROM v_declared_old_parent_id THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS remove';
    END IF;
    UPDATE public.nodes AS node SET
      trash_root_id=v_resource_id,
      trashed_original_parent_id=CASE WHEN node.id=v_resource_id THEN node.parent_id ELSE node.trashed_original_parent_id END,
      trashed_original_name=CASE WHEN node.id=v_resource_id THEN node.display_name ELSE node.trashed_original_name END,
      trashed_original_name_key=CASE WHEN node.id=v_resource_id THEN node.name_key ELSE node.trashed_original_name_key END,
      purge_after=clock_timestamp()+make_interval(days=>v_mode),
      namespace_generation=CASE WHEN node.id=v_resource_id THEN node.namespace_generation+1 ELSE node.namespace_generation END,
      changed_at=clock_timestamp(),updated_at=clock_timestamp()
    WHERE node.tenant_id=p_tenant_id AND node.drive_id=v_drive_id
      AND EXISTS (SELECT 1 FROM public.node_ancestry AS ancestry
        WHERE ancestry.tenant_id=p_tenant_id AND ancestry.drive_id=v_drive_id
          AND ancestry.ancestor_id=v_resource_id AND ancestry.descendant_id=node.id)
      AND node.trash_root_id IS NULL;
    UPDATE public.drives SET namespace_generation=namespace_generation+1
    WHERE tenant_id=p_tenant_id AND id=v_drive_id;
    UPDATE public.nodes SET namespace_generation=namespace_generation+1,
      changed_at=clock_timestamp(),updated_at=clock_timestamp()
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id AND id=v_old_parent_id;
    SELECT namespace_generation INTO v_generation FROM public.nodes
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id AND id=v_resource_id;
  ELSIF p_operation='set_attributes' THEN
    v_mode := (p_mutation->>'mode')::integer;
    v_owner_principal_id := (p_mutation->>'owner_principal_id')::uuid;
    v_group_id := (p_mutation->>'posix_group_id')::uuid;
    v_atime := to_timestamp((p_mutation->>'accessed_at_unix_seconds')::double precision);
    v_mtime := to_timestamp((p_mutation->>'modified_at_unix_seconds')::double precision);
    IF v_mode IS NULL AND v_owner_principal_id IS NULL AND v_group_id IS NULL
       AND v_atime IS NULL AND v_mtime IS NULL THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='empty NFS setattr mutation';
    END IF;
    IF v_owner_principal_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM filebelt_mount.nfs_principal_mappings AS mapping
      WHERE mapping.tenant_id=p_tenant_id
        AND mapping.principal_id=v_owner_principal_id
        AND mapping.revoked_at IS NULL
    ) THEN
      RAISE EXCEPTION USING ERRCODE='23503',MESSAGE='NFS owner must have an active immutable mapping';
    END IF;
    IF v_group_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM filebelt_mount.nfs_posix_groups AS posix_group
      JOIN public.group_memberships AS membership
        ON membership.tenant_id=posix_group.tenant_id
       AND membership.group_id=posix_group.group_id
       AND membership.user_principal_id=v_session.user_principal_id
      WHERE posix_group.tenant_id=p_tenant_id AND posix_group.group_id=v_group_id
    ) THEN
      RAISE EXCEPTION USING ERRCODE='23503',MESSAGE='NFS primary group is not registered for the actor';
    END IF;
    UPDATE public.nodes SET
      posix_mode=COALESCE(v_mode,posix_mode),
      owner_principal_id=COALESCE(v_owner_principal_id,owner_principal_id),
      posix_group_id=COALESCE(v_group_id,posix_group_id),
      accessed_at=COALESCE(v_atime,accessed_at),
      modified_at=COALESCE(v_mtime,modified_at),
      changed_at=clock_timestamp(),
      namespace_generation=namespace_generation+1,
      updated_at=clock_timestamp()
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id AND id=v_resource_id
    RETURNING namespace_generation INTO v_generation;
    UPDATE public.drives SET namespace_generation=namespace_generation+1
    WHERE tenant_id=p_tenant_id AND id=v_drive_id;
  ELSIF p_operation='set_xattr' THEN
    v_expected_generation := (p_mutation->>'resource_namespace_generation')::bigint;
    PERFORM 1 FROM public.nodes
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id AND id=v_resource_id
      AND trash_root_id IS NULL AND namespace_generation=v_expected_generation
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS xattr resource';
    END IF;
    v_xattr_name := p_mutation->>'name';
    BEGIN
      v_xattr_value := decode(p_mutation->>'value_hex','hex');
    EXCEPTION WHEN invalid_parameter_value OR data_exception THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid NFS xattr value';
    END;
    v_create_only := COALESCE((p_mutation->>'create_only')::boolean,false);
    v_replace_only := COALESCE((p_mutation->>'replace_only')::boolean,false);
    IF v_create_only AND v_replace_only THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid NFS xattr create/replace mode';
    END IF;
    IF v_create_only AND EXISTS (
      SELECT 1 FROM public.node_xattrs WHERE tenant_id=p_tenant_id
        AND drive_id=v_drive_id AND node_id=v_resource_id AND name=v_xattr_name
    ) OR v_replace_only AND NOT EXISTS (
      SELECT 1 FROM public.node_xattrs WHERE tenant_id=p_tenant_id
        AND drive_id=v_drive_id AND node_id=v_resource_id AND name=v_xattr_name
    ) THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS xattr create/replace conflict';
    END IF;
    INSERT INTO public.node_xattrs (tenant_id,drive_id,node_id,name,value)
    VALUES (p_tenant_id,v_drive_id,v_resource_id,v_xattr_name,v_xattr_value)
    ON CONFLICT (tenant_id,drive_id,node_id,name)
    DO UPDATE SET value=EXCLUDED.value,updated_at=clock_timestamp();
    UPDATE public.nodes SET namespace_generation=namespace_generation+1,
      changed_at=clock_timestamp(),updated_at=clock_timestamp()
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id AND id=v_resource_id
    RETURNING namespace_generation INTO v_generation;
    UPDATE public.drives SET namespace_generation=namespace_generation+1
    WHERE tenant_id=p_tenant_id AND id=v_drive_id;
  ELSIF p_operation='remove_xattr' THEN
    v_expected_generation := (p_mutation->>'resource_namespace_generation')::bigint;
    PERFORM 1 FROM public.nodes
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id AND id=v_resource_id
      AND trash_root_id IS NULL AND namespace_generation=v_expected_generation
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS xattr resource';
    END IF;
    v_xattr_name := p_mutation->>'name';
    DELETE FROM public.node_xattrs
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id
      AND node_id=v_resource_id AND name=v_xattr_name;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS xattr does not exist';
    END IF;
    UPDATE public.nodes SET namespace_generation=namespace_generation+1,
      changed_at=clock_timestamp(),updated_at=clock_timestamp()
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id AND id=v_resource_id
    RETURNING namespace_generation INTO v_generation;
    UPDATE public.drives SET namespace_generation=namespace_generation+1
    WHERE tenant_id=p_tenant_id AND id=v_drive_id;
  ELSE
    IF jsonb_typeof(p_mutation->'entries')<>'array'
       OR jsonb_array_length(p_mutation->'entries')>256 THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid NFS ACL replacement';
    END IF;
    DELETE FROM public.acl_entries
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id
      AND resource_id=v_resource_id AND source='nfs';
    FOR v_acl_entry IN SELECT value FROM jsonb_array_elements(p_mutation->'entries') LOOP
      v_acl_count := v_acl_count+1;
      IF v_acl_entry->>'action' NOT IN (
        'READ_METADATA','LIST_CHILDREN','READ_CONTENT','CREATE_CHILD',
        'WRITE_CONTENT','CREATE_VERSION','RENAME','MOVE','DELETE','RESTORE',
        'SET_ATTRIBUTES','SHARE','MANAGE_ACL','MANAGE_LOCK','USE_EXTERNAL_EDITOR',
        'COMMENT','REVIEW','TRAVERSE'
      ) OR v_acl_entry->>'inheritance' NOT IN (
        'self','descendants','self_and_descendants'
      ) OR NOT EXISTS (
        SELECT 1 FROM public.principals AS principal
        WHERE principal.tenant_id=p_tenant_id
          AND principal.id=(v_acl_entry->>'principal_id')::uuid
          AND principal.disabled_at IS NULL
          AND (
            EXISTS (SELECT 1 FROM filebelt_mount.nfs_principal_mappings AS mapping
              WHERE mapping.tenant_id=principal.tenant_id
                AND mapping.principal_id=principal.id AND mapping.revoked_at IS NULL)
            OR EXISTS (SELECT 1 FROM filebelt_mount.nfs_posix_groups AS posix_group
              JOIN public.groups AS group_record
                ON group_record.tenant_id=posix_group.tenant_id
               AND group_record.id=posix_group.group_id
              WHERE group_record.tenant_id=principal.tenant_id
                AND group_record.principal_id=principal.id)
          )
      ) THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid NFS ACL entry';
      END IF;
      INSERT INTO public.acl_entries (
        tenant_id,drive_id,resource_id,id,principal_id,action,effect,
        inheritance,created_by,generation,source
      ) VALUES (
        p_tenant_id,v_drive_id,v_resource_id,
        (v_acl_entry->>'id')::uuid,(v_acl_entry->>'principal_id')::uuid,
        v_acl_entry->>'action','allow',v_acl_entry->>'inheritance',
        v_session.user_principal_id,1,'nfs'
      );
    END LOOP;
    SELECT acl_generation INTO v_generation FROM public.nodes
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id AND id=v_resource_id;
  END IF;

  INSERT INTO filebelt_mount.nfs_replay_receipts (
    tenant_id,mount_session_id,client_id,nfs_session_id,slot_id,sequence_id,
    operation_index,operation,request_digest,response_bytes,response_digest,
    gateway_epoch,expires_at,mutation_outcome
  ) VALUES (
    p_tenant_id,p_mount_session_id,p_client_id,p_nfs_session_id,p_slot_id,
    p_sequence_id,p_operation_index,p_operation,p_request_digest,p_response_bytes,
    p_response_digest,p_gateway_epoch,(SELECT session.absolute_expires_at
      FROM filebelt_mount.sessions AS session
      WHERE session.tenant_id=p_tenant_id AND session.id=p_mount_session_id),'applied'
  ) RETURNING * INTO v_receipt;
  RETURN QUERY SELECT v_receipt.response_bytes,v_receipt.response_digest,
    v_receipt.gateway_epoch,v_receipt.expires_at,false,'applied',
    v_resource_id,v_generation;
END
$$;

-- Final write publication performs the expected-head CAS, immutable version
-- publication, quota accounting, conflict retention, and exact replay receipt
-- atomically. Sparse extent/chunk finalization remains an I/O boundary and must
-- have placed the staging payload in `finalized` before this call.
CREATE FUNCTION filebelt_mount.commit_nfs_write(
  p_tenant_id uuid,
  p_mount_session_id uuid,
  p_client_id text,
  p_nfs_session_id text,
  p_slot_id integer,
  p_sequence_id bigint,
  p_operation_index integer,
  p_operation text,
  p_request_digest bytea,
  p_gateway_epoch bigint,
  p_gss_binding_digest bytea,
  p_mutation jsonb,
  p_success_response_bytes bytea,
  p_success_response_digest bytea,
  p_conflict_response_bytes bytea,
  p_conflict_response_digest bytea
)
RETURNS TABLE (
  response_bytes bytea,
  response_digest bytea,
  receipt_gateway_epoch bigint,
  expires_at timestamptz,
  replayed boolean,
  mutation_outcome text,
  resource_id uuid,
  resource_generation bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_receipt filebelt_mount.nfs_replay_receipts%ROWTYPE;
  v_session record;
  v_write record;
  v_drive_id uuid := (p_mutation->>'drive_id')::uuid;
  v_node_id uuid := (p_mutation->>'resource_id')::uuid;
  v_write_session_id uuid := (p_mutation->>'write_session_id')::uuid;
  v_version_id uuid := (p_mutation->>'version_id')::uuid;
  v_conflict_id uuid := (p_mutation->>'conflict_id')::uuid;
  v_fencing_token bigint := (p_mutation->>'fencing_token')::bigint;
  v_current_head uuid;
  v_ordinal bigint;
  v_generation bigint;
  v_creator_display_name text;
  v_outcome text;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_vfs','MEMBER') OR p_operation<>'commit'
     OR p_mutation IS NULL OR jsonb_typeof(p_mutation)<>'object' THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid NFS write commit caller or mutation';
  END IF;
  PERFORM filebelt_mount.validate_nfs_mutation_envelope(
    p_client_id,p_nfs_session_id,p_slot_id,p_sequence_id,p_operation_index,
    p_operation,p_request_digest,p_gateway_epoch,p_gss_binding_digest,
    p_success_response_bytes,p_success_response_digest
  );
  PERFORM filebelt_mount.validate_nfs_mutation_envelope(
    p_client_id,p_nfs_session_id,p_slot_id,p_sequence_id,p_operation_index,
    p_operation,p_request_digest,p_gateway_epoch,p_gss_binding_digest,
    p_conflict_response_bytes,p_conflict_response_digest
  );
  PERFORM filebelt_mount.prepare_nfs_replay_sequence(
    p_tenant_id,p_mount_session_id,p_client_id,p_nfs_session_id,p_slot_id,
    p_sequence_id,p_operation_index,p_gateway_epoch
  );
  SELECT * INTO v_receipt FROM filebelt_mount.nfs_replay_receipts AS receipt
  WHERE receipt.tenant_id=p_tenant_id
    AND receipt.mount_session_id=p_mount_session_id
    AND receipt.nfs_session_id=p_nfs_session_id
    AND receipt.slot_id=p_slot_id AND receipt.sequence_id=p_sequence_id
    AND receipt.operation_index=p_operation_index
  FOR UPDATE;
  IF FOUND THEN
    IF v_receipt.client_id IS DISTINCT FROM p_client_id
       OR v_receipt.operation IS DISTINCT FROM p_operation
       OR v_receipt.request_digest IS DISTINCT FROM p_request_digest
       OR v_receipt.gateway_epoch IS DISTINCT FROM p_gateway_epoch THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='NFS replay identity context mismatch';
    END IF;
    RETURN QUERY SELECT v_receipt.response_bytes,v_receipt.response_digest,
      v_receipt.gateway_epoch,v_receipt.expires_at,true,
      COALESCE(v_receipt.mutation_outcome,'applied'),NULL::uuid,NULL::bigint;
    RETURN;
  END IF;

  SELECT * INTO STRICT v_session FROM filebelt_mount.authorize_nfs_mutation(
    p_tenant_id,p_mount_session_id,p_gateway_epoch,p_gss_binding_digest,
    v_drive_id,v_node_id,
    (p_mutation->>'membership_generation')::bigint,
    (p_mutation->>'drive_acl_generation')::bigint,
    (p_mutation->>'drive_namespace_generation')::bigint,
    (p_mutation->>'resource_acl_generation')::bigint,
    (p_mutation->>'resource_namespace_generation')::bigint
  );
  SELECT write_session.*,payload.state AS payload_state,payload.size_bytes,
         payload.blake3,node.head_version_id
  INTO v_write
  FROM filebelt_mount.write_sessions AS write_session
  JOIN filebelt_mount.handles AS handle
    ON handle.tenant_id=write_session.tenant_id
   AND handle.id=write_session.handle_id
  JOIN filebelt_mount.sessions AS mount_session
    ON mount_session.tenant_id=write_session.tenant_id
   AND mount_session.id=write_session.mount_session_id
  JOIN public.payload_objects AS payload
    ON payload.tenant_id=write_session.tenant_id
   AND payload.id=write_session.staging_payload_id
  JOIN public.nodes AS node
    ON node.tenant_id=write_session.tenant_id
   AND node.drive_id=write_session.drive_id AND node.id=write_session.node_id
  WHERE write_session.tenant_id=p_tenant_id
    AND write_session.id=v_write_session_id
    AND write_session.mount_session_id=p_mount_session_id
    AND write_session.drive_id=v_drive_id AND write_session.node_id=v_node_id
    AND write_session.state='committing'
    AND write_session.fencing_token=v_fencing_token
    AND write_session.gateway_epoch=p_gateway_epoch
    AND write_session.authorization_generation=mount_session.authorization_generation
    AND write_session.expires_at>clock_timestamp()
    AND handle.session_id=p_mount_session_id
    AND handle.drive_id=v_drive_id AND handle.node_id=v_node_id
    AND handle.version_id IS NOT DISTINCT FROM write_session.expected_head_version_id
    AND handle.closed_at IS NULL AND handle.expires_at>clock_timestamp()
    AND 'WRITE_CONTENT'=ANY(handle.access_actions)
    AND 'CREATE_VERSION'=ANY(handle.access_actions)
    AND handle.credential_generation=mount_session.credential_generation
    AND handle.authorization_generation=mount_session.authorization_generation
    AND handle.membership_generation=(p_mutation->>'membership_generation')::bigint
    AND handle.drive_acl_generation=(p_mutation->>'drive_acl_generation')::bigint
    AND handle.namespace_generation=(p_mutation->>'resource_namespace_generation')::bigint
    AND handle.resource_acl_generation=(p_mutation->>'resource_acl_generation')::bigint
    AND handle.gateway_epoch=p_gateway_epoch
    AND payload.state='finalized' AND payload.blake3 IS NOT NULL
    AND payload.size_bytes=write_session.logical_size_bytes
    AND EXISTS (
      SELECT 1
      FROM filebelt_mount.nfs_pending_protocol_operations AS pending
      JOIN filebelt_mount.nfs_io_receipts AS finalize_receipt
        ON finalize_receipt.tenant_id=pending.tenant_id
       AND finalize_receipt.capability_id=pending.capability_id
       AND finalize_receipt.nonce_digest=pending.nonce_digest
       AND finalize_receipt.write_session_id=pending.write_session_id
       AND finalize_receipt.claims_digest=pending.claims_digest
       AND finalize_receipt.content_blake3 IS NOT DISTINCT FROM pending.content_blake3
      WHERE pending.tenant_id=write_session.tenant_id
        AND pending.mount_session_id=p_mount_session_id
        AND pending.client_id=p_client_id
        AND pending.nfs_session_id=p_nfs_session_id
        AND pending.slot_id=p_slot_id AND pending.sequence_id=p_sequence_id
        AND pending.operation_index=p_operation_index
        AND pending.protocol_operation=p_operation
        AND pending.request_digest=p_request_digest
        AND pending.gateway_epoch=p_gateway_epoch
        AND pending.write_session_id=write_session.id
        AND pending.io_operation='finalize'
        AND pending.operation_id IS NULL
        AND finalize_receipt.operation='finalize'
        AND finalize_receipt.operation_id IS NULL
        AND finalize_receipt.state='completed'
        AND finalize_receipt.outcome->>'kind'='finalize'
        AND (finalize_receipt.outcome->>'logical_size_bytes')::bigint
          =write_session.logical_size_bytes
    )
  FOR UPDATE OF write_session,payload,node FOR SHARE OF handle,mount_session;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS write publication';
  END IF;
  v_current_head := v_write.head_version_id;
  IF v_current_head IS DISTINCT FROM v_write.expected_head_version_id THEN
    INSERT INTO filebelt_mount.nfs_write_conflicts (
      tenant_id,id,write_session_id,mount_session_id,drive_id,node_id,
      base_version_id,expected_head_version_id,observed_head_version_id,
      staging_payload_id,logical_size_bytes,gateway_epoch,restore_generation
    ) VALUES (
      p_tenant_id,v_conflict_id,v_write_session_id,p_mount_session_id,
      v_drive_id,v_node_id,v_write.base_version_id,v_write.expected_head_version_id,
      v_current_head,v_write.staging_payload_id,v_write.logical_size_bytes,
      p_gateway_epoch,v_session.restore_generation
    );
    UPDATE filebelt_mount.write_sessions
    SET state='conflicted',fencing_token=fencing_token+1,finished_at=clock_timestamp()
    WHERE tenant_id=p_tenant_id AND id=v_write_session_id;
    v_outcome := 'conflict';
  ELSE
    SELECT COALESCE(max(version.ordinal),0)+1 INTO v_ordinal
    FROM public.file_versions AS version
    WHERE version.tenant_id=p_tenant_id AND version.node_id=v_node_id;
    SELECT user_account.display_name INTO v_creator_display_name
    FROM public.users AS user_account
    WHERE user_account.tenant_id=p_tenant_id
      AND user_account.principal_id=v_session.user_principal_id;
    INSERT INTO public.file_versions (
      tenant_id,node_id,id,ordinal,payload_id,size_bytes,blake3,created_by,
      origin_kind,creator_display_name
    ) VALUES (
      p_tenant_id,v_node_id,v_version_id,v_ordinal,v_write.staging_payload_id,
      v_write.size_bytes,v_write.blake3,v_session.user_principal_id,
      'nfs',v_creator_display_name
    );
    UPDATE public.nodes SET head_version_id=v_version_id,
      namespace_generation=namespace_generation+1,
      modified_at=clock_timestamp(),changed_at=clock_timestamp(),updated_at=clock_timestamp()
    WHERE tenant_id=p_tenant_id AND drive_id=v_drive_id AND id=v_node_id
    RETURNING namespace_generation INTO v_generation;
    UPDATE public.payload_objects SET state='referenced',referenced_at=clock_timestamp()
    WHERE tenant_id=p_tenant_id AND id=v_write.staging_payload_id AND state='finalized';
    UPDATE filebelt_mount.write_sessions SET state='committed',
      committed_version_id=v_version_id,finished_at=clock_timestamp()
    WHERE tenant_id=p_tenant_id AND id=v_write_session_id;
    UPDATE public.drives SET
      reserved_bytes=reserved_bytes-v_write.reserved_bytes,
      used_physical_bytes=used_physical_bytes+v_write.size_bytes,
      namespace_generation=namespace_generation+1
    WHERE tenant_id=p_tenant_id AND id=v_drive_id
      AND reserved_bytes>=v_write.reserved_bytes;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS quota reservation';
    END IF;
    v_outcome := 'applied';
  END IF;

  INSERT INTO filebelt_mount.nfs_replay_receipts (
    tenant_id,mount_session_id,client_id,nfs_session_id,slot_id,sequence_id,
    operation_index,operation,request_digest,response_bytes,response_digest,
    gateway_epoch,expires_at,mutation_outcome
  ) VALUES (
    p_tenant_id,p_mount_session_id,p_client_id,p_nfs_session_id,p_slot_id,
    p_sequence_id,p_operation_index,p_operation,p_request_digest,
    CASE v_outcome WHEN 'applied' THEN p_success_response_bytes ELSE p_conflict_response_bytes END,
    CASE v_outcome WHEN 'applied' THEN p_success_response_digest ELSE p_conflict_response_digest END,
    p_gateway_epoch,(SELECT session.absolute_expires_at
      FROM filebelt_mount.sessions AS session
      WHERE session.tenant_id=p_tenant_id AND session.id=p_mount_session_id),v_outcome
  ) RETURNING * INTO v_receipt;
  RETURN QUERY SELECT v_receipt.response_bytes,v_receipt.response_digest,
    v_receipt.gateway_epoch,v_receipt.expires_at,false,v_outcome,
    v_node_id,v_generation;
END
$$;

-- Restores fence unfinished writes in addition to session/filehandle authority.
-- Conflict inventory survives the fence so recovery can retain or copy it.
CREATE OR REPLACE FUNCTION filebelt_mount.advance_nfs_restore_generation(
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
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='caller is not a FileBelt recovery database principal';
  END IF;
  SELECT feature.state INTO v_state
  FROM filebelt_mount.nfs_feature_state AS feature
  WHERE feature.tenant_id=p_tenant_id
    AND feature.restore_generation=p_expected_generation
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale NFS restore generation';
  END IF;
  IF v_state<>'disabled' OR EXISTS (
    SELECT 1 FROM filebelt_mount.sessions AS session
    WHERE session.tenant_id=p_tenant_id AND session.protocol='nfs'
      AND session.state IN ('active','draining')
  ) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='disable and fence NFS before advancing the restore generation';
  END IF;
  UPDATE filebelt_mount.write_sessions AS write_session
  SET state='expired',fencing_token=fencing_token+1,finished_at=clock_timestamp()
  FROM filebelt_mount.sessions AS session
  WHERE write_session.tenant_id=p_tenant_id
    AND write_session.tenant_id=session.tenant_id
    AND write_session.mount_session_id=session.id
    AND session.protocol='nfs'
    AND write_session.state IN ('open','flushing','committing','aborting');
  INSERT INTO filebelt_mount.nfs_staging_cleanup_jobs (
    tenant_id,write_session_id,backend_id,payload_id,source_nonce_digest,reason
  )
  SELECT writer.tenant_id,writer.id,payload.backend_id,payload.id,
         pending.nonce_digest,'restore_fenced'
  FROM filebelt_mount.write_sessions AS writer
  JOIN filebelt_mount.sessions AS session
    ON session.tenant_id=writer.tenant_id AND session.id=writer.mount_session_id
  JOIN public.payload_objects AS payload
    ON payload.tenant_id=writer.tenant_id AND payload.id=writer.staging_payload_id
  LEFT JOIN LATERAL (
    SELECT receipt.nonce_digest FROM filebelt_mount.nfs_io_receipts AS receipt
    WHERE receipt.tenant_id=writer.tenant_id
      AND receipt.write_session_id=writer.id AND receipt.state='pending'
    ORDER BY receipt.operation_ordinal DESC LIMIT 1
  ) AS pending ON true
  WHERE writer.tenant_id=p_tenant_id AND session.protocol='nfs'
    AND writer.state='expired'
    AND payload.state IN ('staging','finalized','abandoned','deleting','deleted')
    AND NOT EXISTS (SELECT 1 FROM public.file_versions AS version
      WHERE version.tenant_id=payload.tenant_id AND version.payload_id=payload.id)
  ON CONFLICT (tenant_id,write_session_id) DO NOTHING;
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

-- Retention is enforced below the maintenance role so deleting a parent row
-- cannot cascade away live slot high-water or byte-plane replay authority.
CREATE FUNCTION filebelt_mount.protect_nfs_session_replay_retention()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,filebelt_mount
AS $$
BEGIN
  IF OLD.protocol='nfs' AND (
    OLD.absolute_expires_at>statement_timestamp()
    OR EXISTS (
      SELECT 1 FROM filebelt_mount.write_sessions AS writer
      WHERE writer.tenant_id=OLD.tenant_id AND writer.mount_session_id=OLD.id
        AND (
          writer.state NOT IN ('committed','conflicted','aborted','expired')
          OR writer.expires_at>statement_timestamp()
          OR EXISTS (SELECT 1 FROM filebelt_mount.nfs_io_receipts AS receipt
            WHERE receipt.tenant_id=writer.tenant_id
              AND receipt.write_session_id=writer.id AND receipt.state='pending')
          OR EXISTS (SELECT 1 FROM filebelt_mount.nfs_write_conflicts AS conflict
            WHERE conflict.tenant_id=writer.tenant_id
              AND conflict.write_session_id=writer.id
              AND (conflict.state='retained'
                OR conflict.expires_at>statement_timestamp()))
          OR EXISTS (SELECT 1 FROM filebelt_mount.nfs_staging_cleanup_jobs AS cleanup
            WHERE cleanup.tenant_id=writer.tenant_id
              AND cleanup.write_session_id=writer.id AND cleanup.state<>'completed')
        )
    )
  ) THEN
    RAISE EXCEPTION USING ERRCODE='55000',
      MESSAGE='NFS sessions are retained through their replay lifetime';
  END IF;
  RETURN OLD;
END
$$;
CREATE TRIGGER mount_nfs_session_replay_retention
BEFORE DELETE ON filebelt_mount.sessions
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.protect_nfs_session_replay_retention();

CREATE FUNCTION filebelt_mount.protect_nfs_replay_slot_delete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,filebelt_mount
AS $$
BEGIN
  PERFORM 1 FROM filebelt_mount.sessions AS session
  WHERE session.tenant_id=OLD.tenant_id AND session.id=OLD.mount_session_id
    AND session.absolute_expires_at>statement_timestamp();
  IF FOUND THEN
    RAISE EXCEPTION USING ERRCODE='55000',
      MESSAGE='current NFS replay slot high-water is immutable';
  END IF;
  RETURN OLD;
END
$$;
CREATE TRIGGER nfs_replay_slot_delete_retention
BEFORE DELETE ON filebelt_mount.nfs_replay_slots
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.protect_nfs_replay_slot_delete();

CREATE FUNCTION filebelt_mount.protect_nfs_write_session_delete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_mount_absolute_expires_at timestamptz;
BEGIN
  SELECT session.absolute_expires_at INTO v_mount_absolute_expires_at
  FROM filebelt_mount.sessions AS session
  WHERE session.tenant_id=OLD.tenant_id AND session.id=OLD.mount_session_id
    AND session.protocol='nfs';
  IF NOT FOUND THEN
    RETURN OLD;
  END IF;
  IF OLD.state NOT IN ('committed','conflicted','aborted','expired')
     OR OLD.expires_at>statement_timestamp()
     OR v_mount_absolute_expires_at>statement_timestamp()
     OR EXISTS (SELECT 1 FROM filebelt_mount.nfs_io_receipts AS receipt
       WHERE receipt.tenant_id=OLD.tenant_id AND receipt.write_session_id=OLD.id
         AND receipt.state='pending')
     OR EXISTS (SELECT 1 FROM filebelt_mount.nfs_write_conflicts AS conflict
       WHERE conflict.tenant_id=OLD.tenant_id AND conflict.write_session_id=OLD.id
         AND (conflict.state='retained' OR conflict.expires_at>statement_timestamp()))
     OR EXISTS (SELECT 1 FROM filebelt_mount.nfs_staging_cleanup_jobs AS cleanup
       WHERE cleanup.tenant_id=OLD.tenant_id AND cleanup.write_session_id=OLD.id
         AND cleanup.state<>'completed') THEN
    RAISE EXCEPTION USING ERRCODE='55000',
      MESSAGE='NFS write authority is retained until terminal cleanup and replay expiry';
  END IF;
  RETURN OLD;
END
$$;
CREATE TRIGGER mount_nfs_write_session_delete_retention
BEFORE DELETE ON filebelt_mount.write_sessions
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.protect_nfs_write_session_delete();

REVOKE ALL ON FUNCTION filebelt_mount.enforce_nfs_write_conflict_retention() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.enforce_nfs_write_operation() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.enforce_nfs_io_receipt() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.nfs_io_fence_live(
  uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,
  bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,text,boolean
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.preauthorize_nfs_io(
  uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,
  bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,
  text,text,integer,bigint,integer,text,bytea,
  uuid,uuid,bytea,uuid,text,bytea,bytea,bigint,bigint,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.lookup_nfs_io_preauthorization(
  uuid,uuid,text,text,integer,bigint,integer,text,bytea,bigint,uuid,uuid,uuid,
  bytea,bytea,text,uuid,bytea,bigint,bigint,bigint,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.inspect_nfs_pending_io(
  uuid,uuid,text,text,integer,bigint,integer,text,bytea,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.reissue_nfs_io(
  uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,
  bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,
  text,text,integer,bigint,integer,text,bytea,uuid,uuid,text,bytea,
  bigint,bigint,uuid,bytea,bytea,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.enforce_nfs_io_admission() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.protect_nfs_worker_authority() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.protect_nfs_cleanup_payload_reference() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.read_nfs_io_receipt(
  uuid,bytea,uuid,uuid,text,bytea,bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.read_nfs_write_operation(
  uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,
  bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,
  uuid,text,bigint,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.begin_nfs_io_receipt(
  uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,
  bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,
  uuid,bytea,text,bytea,bytea,bigint,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.complete_nfs_io_receipt(
  uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,
  bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,
  uuid,bytea,text,bytea,bytea,jsonb
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.fence_pending_nfs_io_cleanup(
  uuid,uuid,bigint,bytea,bytea,text,bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.enqueue_nfs_staging_cleanup(
  uuid,uuid,text,bytea,text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.claim_nfs_staging_cleanup(
  uuid,uuid,uuid,uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.mark_nfs_staging_cleanup_physical_deleted(
  uuid,uuid,uuid,uuid,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.complete_nfs_staging_cleanup(
  uuid,uuid,uuid,uuid,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.claim_next_nfs_staging_cleanup(
  uuid,uuid,uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.heartbeat_nfs_staging_cleanup(
  uuid,uuid,uuid,uuid,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.sweep_expired_nfs_writers(
  uuid,integer
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.complete_nfs_write_conflict_copy(
  uuid,uuid,uuid,uuid,uuid,text,text,uuid,uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.discard_nfs_write_conflict(
  uuid,uuid,uuid,uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.sweep_expired_nfs_write_conflicts(
  uuid,integer
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.enqueue_nfs_write_lock_cleanup(
  uuid,uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.claim_nfs_write_lock_cleanup(
  uuid,uuid,uuid,uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.claim_next_nfs_write_lock_cleanup(
  uuid,uuid,uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.heartbeat_nfs_write_lock_cleanup(
  uuid,uuid,uuid,uuid,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.complete_nfs_write_lock_cleanup(
  uuid,uuid,uuid,uuid,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.replace_nfs_write_extents(
  uuid,uuid,bigint,uuid,bigint[],bigint[],boolean[],bytea[]
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.apply_completed_nfs_write_operation(
  uuid,uuid,bigint,uuid,text,bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.finalize_nfs_internal_io_replay(
  uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,
  bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,
  bytea,text,text,integer,bigint,integer,text,bytea,text,bytea,bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.require_completed_nfs_internal_terminal(
  uuid,uuid,text,text,integer,bigint,integer,text,bytea,bigint,uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.sorted_unique_positive_bigints(bigint[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.project_nfs_session_manifest() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.protect_nfs_session_replay_retention() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.protect_nfs_replay_slot_delete() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.protect_nfs_write_session_delete() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.prepare_nfs_replay_sequence(
  uuid,uuid,text,text,integer,bigint,integer,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.enforce_nfs_replay_receipt() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.lock_nfs_replay_receipt(
  uuid,uuid,text,text,integer,bigint,integer,text,bytea,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.authorize_nfs_operation(
  uuid,uuid,bigint,bytea,uuid,uuid,bigint,bigint,bigint,bigint,bigint,boolean
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.authorize_nfs_mutation(
  uuid,uuid,bigint,bytea,uuid,uuid,bigint,bigint,bigint,bigint,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.authorize_nfs_handle_open(
  uuid,uuid,bigint,bytea,uuid,uuid,bigint,bigint,bigint,bigint,bigint,text[]
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.validate_nfs_mutation_envelope(
  text,text,integer,bigint,integer,text,bytea,bigint,bytea,bytea,bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.start_nfs_write(
  uuid,uuid,bigint,bytea,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,
  uuid,uuid,uuid,uuid,uuid,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.finish_nfs_write_abort(uuid,uuid,bigint)
  FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.start_nfs_write_replayed(
  uuid,uuid,bigint,bytea,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,
  uuid,uuid,uuid,uuid,uuid,bigint,text,text,integer,bigint,integer,bytea,bytea,bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.reserve_nfs_write_bytes(uuid,uuid,bigint,bigint)
  FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.mutate_nfs_namespace(
  uuid,uuid,text,text,integer,bigint,integer,text,bytea,bigint,bytea,jsonb,bytea,bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.commit_nfs_write(
  uuid,uuid,text,text,integer,bigint,integer,text,bytea,bigint,bytea,jsonb,
  bytea,bytea,bytea,bytea
) FROM PUBLIC;
