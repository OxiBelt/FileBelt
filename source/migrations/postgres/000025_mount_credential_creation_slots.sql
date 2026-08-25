-- SPDX-License-Identifier: Apache-2.0

-- Credential creation uses one durable, reusable slot per tenant/principal.
-- The slot is the ordering point for a one-time secret create and its recovery
-- cancellation without allowing arbitrary request UUIDs to append durable rows.
CREATE TABLE filebelt_mount.credential_creation_slots (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  principal_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  operation_generation bigint NOT NULL CHECK (operation_generation>0),
  state text NOT NULL CHECK (state IN ('prepared','committed','cancelled')),
  prepared_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  committed_at timestamptz,
  cancelled_at timestamptz,
  PRIMARY KEY (tenant_id,principal_id),
  UNIQUE (tenant_id,operation_id),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id),
  CHECK (expires_at>prepared_at),
  CHECK ((state='committed')=(committed_at IS NOT NULL)),
  CHECK ((state='cancelled')=(cancelled_at IS NOT NULL)),
  CHECK (state='prepared' OR expires_at>=prepared_at)
);

ALTER TABLE filebelt_mount.credentials
  ADD COLUMN creation_operation_generation bigint
  CHECK (creation_operation_generation IS NULL OR creation_operation_generation>0);

-- This singleton receipt makes the quiesced legacy cutover auditable without
-- retaining attacker-controlled orphan UUIDs.  Linked credential history is
-- preserved.  Any non-cancelled orphan indicates the required drain did not
-- complete, so the migration fails closed.
CREATE TABLE filebelt_mount.credential_creation_cutovers (
  name text PRIMARY KEY,
  removed_cancelled_fences bigint NOT NULL CHECK (removed_cancelled_fences>=0),
  completed_at timestamptz NOT NULL
);

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM filebelt_mount.credential_operation_fences AS fence
    LEFT JOIN filebelt_mount.credentials AS credential
      ON credential.tenant_id=fence.tenant_id AND credential.id=fence.credential_id
    WHERE credential.id IS NULL AND fence.state<>'cancelled'
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE='23514',
      MESSAGE='mount credential creation cutover requires quiesced legacy operations';
  END IF;
END
$$;

WITH removed AS (
  DELETE FROM filebelt_mount.credential_operation_fences AS fence
  WHERE fence.state='cancelled'
    AND NOT EXISTS (
      SELECT 1 FROM filebelt_mount.credentials AS credential
      WHERE credential.tenant_id=fence.tenant_id AND credential.id=fence.credential_id
    )
  RETURNING 1
)
INSERT INTO filebelt_mount.credential_creation_cutovers
  (name,removed_cancelled_fences,completed_at)
SELECT 'bounded_creation_slots_v1',count(*),clock_timestamp() FROM removed;

CREATE FUNCTION filebelt_mount.prepare_credential_creation_operation(
  p_tenant_id uuid,p_principal_id uuid
) RETURNS TABLE (
  created boolean,operation_id uuid,operation_generation bigint,expires_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount AS $$
DECLARE
  v_inserted bigint;
  v_operation_id uuid := gen_random_uuid();
  v_now timestamptz := clock_timestamp();
  v_slot filebelt_mount.credential_creation_slots%ROWTYPE;
BEGIN
  INSERT INTO filebelt_mount.credential_creation_slots
    (tenant_id,principal_id,operation_id,operation_generation,state,prepared_at,expires_at)
  VALUES
    (p_tenant_id,p_principal_id,v_operation_id,1,'prepared',v_now,v_now+interval '2 minutes')
  ON CONFLICT (tenant_id,principal_id) DO NOTHING;
  GET DIAGNOSTICS v_inserted=ROW_COUNT;

  SELECT slot.* INTO STRICT v_slot
  FROM filebelt_mount.credential_creation_slots AS slot
  WHERE slot.tenant_id=p_tenant_id AND slot.principal_id=p_principal_id
  FOR UPDATE;

  v_now := clock_timestamp();

  IF v_inserted=1 THEN
    RETURN QUERY SELECT true,v_slot.operation_id,v_slot.operation_generation,v_slot.expires_at;
    RETURN;
  END IF;
  IF v_slot.state='prepared' AND v_slot.expires_at>v_now THEN
    RETURN QUERY SELECT false,v_slot.operation_id,v_slot.operation_generation,v_slot.expires_at;
    RETURN;
  END IF;
  IF v_slot.operation_generation=9223372036854775807 THEN
    RAISE EXCEPTION USING
      ERRCODE='22003',
      MESSAGE='mount credential operation generation is exhausted';
  END IF;

  UPDATE filebelt_mount.credential_creation_slots AS slot
  SET operation_id=gen_random_uuid(),
      operation_generation=slot.operation_generation+1,
      state='prepared',
      prepared_at=v_now,
      expires_at=v_now+interval '2 minutes',
      committed_at=NULL,
      cancelled_at=NULL
  WHERE slot.tenant_id=p_tenant_id AND slot.principal_id=p_principal_id
  RETURNING slot.* INTO v_slot;
  RETURN QUERY SELECT true,v_slot.operation_id,v_slot.operation_generation,v_slot.expires_at;
END
$$;
REVOKE ALL ON FUNCTION filebelt_mount.prepare_credential_creation_operation(uuid,uuid)
  FROM PUBLIC;

CREATE OR REPLACE FUNCTION filebelt_mount.reserve_credential_operation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount AS $$
DECLARE
  v_slot filebelt_mount.credential_creation_slots%ROWTYPE;
BEGIN
  -- NFS authority is created through its separately fenced approval paths and
  -- remains backward compatible with its nullable creation-operation field.
  IF NEW.protocol='nfs' THEN
    RETURN NEW;
  END IF;

  SELECT slot.* INTO v_slot
  FROM filebelt_mount.credential_creation_slots AS slot
  WHERE slot.tenant_id=NEW.tenant_id AND slot.principal_id=NEW.principal_id
  FOR UPDATE;

  IF NOT FOUND
     OR NEW.creation_operation_generation IS NULL
     OR v_slot.operation_id<>NEW.id
     OR v_slot.operation_generation<>NEW.creation_operation_generation
     OR v_slot.state<>'prepared'
     OR v_slot.expires_at<=clock_timestamp() THEN
    RAISE EXCEPTION USING
      ERRCODE='FB002',
      MESSAGE='mount credential creation operation is stale';
  END IF;

  UPDATE filebelt_mount.credential_creation_slots AS slot
  SET state='committed',committed_at=clock_timestamp()
  WHERE slot.tenant_id=NEW.tenant_id AND slot.principal_id=NEW.principal_id;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION filebelt_mount.reserve_credential_operation() FROM PUBLIC;

-- Ordinary credential revocation never creates a fence or slot.  The retained
-- legacy fence is updated only when it is already linked to the credential.
CREATE OR REPLACE FUNCTION filebelt_mount.cancel_credential_operation(
  p_tenant_id uuid,p_principal_id uuid,p_credential_id uuid
) RETURNS TABLE (credential_existed boolean,protocol text,generation bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount,filebelt_mount_vault AS $$
BEGIN
  RETURN QUERY
  WITH revoked AS (
    UPDATE filebelt_mount.credentials AS credential
    SET revoked_at=clock_timestamp(),
        credential_generation=credential.credential_generation+1,
        authorization_generation=credential.authorization_generation+1
    WHERE credential.tenant_id=p_tenant_id
      AND credential.principal_id=p_principal_id
      AND credential.id=p_credential_id
      AND credential.revoked_at IS NULL
    RETURNING credential.protocol,credential.credential_generation
  ), legacy AS (
    UPDATE filebelt_mount.credential_operation_fences AS fence
    SET state='cancelled',cancelled_at=COALESCE(fence.cancelled_at,clock_timestamp())
    WHERE fence.tenant_id=p_tenant_id AND fence.credential_id=p_credential_id
      AND EXISTS (SELECT 1 FROM revoked)
    RETURNING 1
  )
  SELECT true,revoked.protocol,revoked.credential_generation FROM revoked;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false,NULL::text,NULL::bigint;
  END IF;
END
$$;
REVOKE ALL ON FUNCTION filebelt_mount.cancel_credential_operation(uuid,uuid,uuid) FROM PUBLIC;

CREATE FUNCTION filebelt_mount.cancel_credential_creation_operation(
  p_tenant_id uuid,p_principal_id uuid,p_operation_id uuid,p_expected_generation bigint
) RETURNS TABLE (
  credential_existed boolean,operation_cancelled boolean,protocol text,generation bigint
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount,filebelt_mount_vault AS $$
DECLARE
  v_slot filebelt_mount.credential_creation_slots%ROWTYPE;
  v_credential record;
  v_has_credential boolean;
BEGIN
  SELECT slot.* INTO v_slot
  FROM filebelt_mount.credential_creation_slots AS slot
  WHERE slot.tenant_id=p_tenant_id AND slot.principal_id=p_principal_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false,false,NULL::text,NULL::bigint;
    RETURN;
  END IF;

  -- Re-read only after the slot lock.  An in-flight create that held the slot
  -- must commit or roll back before this query decides the recovery outcome.
  UPDATE filebelt_mount.credentials AS credential
  SET revoked_at=clock_timestamp(),
      credential_generation=credential.credential_generation+1,
      authorization_generation=credential.authorization_generation+1
  WHERE credential.tenant_id=p_tenant_id
    AND credential.principal_id=p_principal_id
    AND credential.id=p_operation_id
    AND credential.creation_operation_generation=p_expected_generation
    AND credential.revoked_at IS NULL
  RETURNING credential.protocol,credential.credential_generation INTO v_credential;

  IF FOUND THEN
    IF v_slot.operation_id=p_operation_id
       AND v_slot.operation_generation=p_expected_generation THEN
      UPDATE filebelt_mount.credential_creation_slots AS slot
      SET state='cancelled',cancelled_at=COALESCE(slot.cancelled_at,clock_timestamp()),
          committed_at=NULL
      WHERE slot.tenant_id=p_tenant_id AND slot.principal_id=p_principal_id;
    END IF;
    UPDATE filebelt_mount.credential_operation_fences AS fence
    SET state='cancelled',cancelled_at=COALESCE(fence.cancelled_at,clock_timestamp())
    WHERE fence.tenant_id=p_tenant_id AND fence.credential_id=p_operation_id;
    RETURN QUERY SELECT true,true,v_credential.protocol,v_credential.credential_generation;
    RETURN;
  END IF;

  SELECT EXISTS (
    SELECT 1 FROM filebelt_mount.credentials AS credential
    WHERE credential.tenant_id=p_tenant_id
      AND credential.principal_id=p_principal_id
      AND credential.id=p_operation_id
      AND credential.creation_operation_generation=p_expected_generation
  ) INTO v_has_credential;

  IF v_has_credential THEN
    IF v_slot.operation_id=p_operation_id
       AND v_slot.operation_generation=p_expected_generation THEN
      UPDATE filebelt_mount.credential_creation_slots AS slot
      SET state='cancelled',cancelled_at=COALESCE(slot.cancelled_at,clock_timestamp()),
          committed_at=NULL
      WHERE slot.tenant_id=p_tenant_id AND slot.principal_id=p_principal_id;
    END IF;
    RETURN QUERY SELECT false,true,NULL::text,NULL::bigint;
    RETURN;
  END IF;
  IF v_slot.operation_id<>p_operation_id
     OR v_slot.operation_generation<>p_expected_generation THEN
    RETURN QUERY SELECT false,false,NULL::text,NULL::bigint;
    RETURN;
  END IF;
  IF v_slot.state='committed' THEN
    RAISE EXCEPTION USING
      ERRCODE='23514',
      MESSAGE='committed mount credential operation has no credential';
  END IF;
  IF v_slot.state='cancelled' THEN
    RETURN QUERY SELECT false,true,NULL::text,NULL::bigint;
    RETURN;
  END IF;
  IF v_slot.state='prepared' AND v_slot.expires_at>clock_timestamp() THEN
    UPDATE filebelt_mount.credential_creation_slots AS slot
    SET state='cancelled',cancelled_at=clock_timestamp()
    WHERE slot.tenant_id=p_tenant_id AND slot.principal_id=p_principal_id;
    RETURN QUERY SELECT false,true,NULL::text,NULL::bigint;
    RETURN;
  END IF;
  RETURN QUERY SELECT false,false,NULL::text,NULL::bigint;
END
$$;
REVOKE ALL ON FUNCTION filebelt_mount.cancel_credential_creation_operation(uuid,uuid,uuid,bigint)
  FROM PUBLIC;
