-- SPDX-License-Identifier: Apache-2.0

-- A browser chooses the mount credential UUID before asking VFS to create the
-- one-time secret.  An indeterminate create response is recovered by deleting
-- that UUID.  Absence alone is not a safe recovery result: an already in-flight
-- create can otherwise commit after DELETE observes no credential.  This row
-- is the durable, transaction-locked ordering point for both operations.
CREATE TABLE filebelt_mount.credential_operation_fences (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  credential_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('reserved','cancelled')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  cancelled_at timestamptz,
  PRIMARY KEY (tenant_id,credential_id),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id),
  CHECK ((state='cancelled')=(cancelled_at IS NOT NULL))
);

INSERT INTO filebelt_mount.credential_operation_fences
  (tenant_id,credential_id,principal_id,state,created_at,cancelled_at)
SELECT tenant_id,id,principal_id,
       CASE WHEN revoked_at IS NULL THEN 'reserved' ELSE 'cancelled' END,
       created_at,revoked_at
FROM filebelt_mount.credentials;

CREATE FUNCTION filebelt_mount.reserve_credential_operation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount AS $$
DECLARE
  v_principal_id uuid;
  v_state text;
BEGIN
  INSERT INTO filebelt_mount.credential_operation_fences
    (tenant_id,credential_id,principal_id,state)
  VALUES (NEW.tenant_id,NEW.id,NEW.principal_id,'reserved')
  ON CONFLICT (tenant_id,credential_id) DO NOTHING;

  SELECT fence.principal_id,fence.state INTO v_principal_id,v_state
  FROM filebelt_mount.credential_operation_fences AS fence
  WHERE fence.tenant_id=NEW.tenant_id AND fence.credential_id=NEW.id
  FOR UPDATE;

  IF v_principal_id IS DISTINCT FROM NEW.principal_id OR v_state<>'reserved' THEN
    RAISE EXCEPTION USING
      ERRCODE='23505',
      MESSAGE='mount credential operation is unavailable';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION filebelt_mount.reserve_credential_operation() FROM PUBLIC;

CREATE TRIGGER mount_credential_operation_reservation
BEFORE INSERT ON filebelt_mount.credentials
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.reserve_credential_operation();

CREATE FUNCTION filebelt_mount.cancel_credential_operation(
  p_tenant_id uuid,p_principal_id uuid,p_credential_id uuid
) RETURNS TABLE (credential_existed boolean,protocol text,generation bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount,filebelt_mount_vault AS $$
DECLARE
  v_principal_id uuid;
BEGIN
  INSERT INTO filebelt_mount.credential_operation_fences
    (tenant_id,credential_id,principal_id,state,cancelled_at)
  VALUES (p_tenant_id,p_credential_id,p_principal_id,'cancelled',clock_timestamp())
  ON CONFLICT (tenant_id,credential_id) DO NOTHING;

  SELECT fence.principal_id INTO v_principal_id
  FROM filebelt_mount.credential_operation_fences AS fence
  WHERE fence.tenant_id=p_tenant_id AND fence.credential_id=p_credential_id
  FOR UPDATE;

  IF v_principal_id IS DISTINCT FROM p_principal_id THEN
    RETURN QUERY SELECT false,NULL::text,NULL::bigint;
    RETURN;
  END IF;

  UPDATE filebelt_mount.credential_operation_fences AS fence
  SET state='cancelled',cancelled_at=COALESCE(fence.cancelled_at,clock_timestamp())
  WHERE fence.tenant_id=p_tenant_id AND fence.credential_id=p_credential_id;

  RETURN QUERY
  UPDATE filebelt_mount.credentials AS credential
  SET revoked_at=clock_timestamp(),
      credential_generation=credential.credential_generation+1,
      authorization_generation=credential.authorization_generation+1
  WHERE credential.tenant_id=p_tenant_id
    AND credential.principal_id=p_principal_id
    AND credential.id=p_credential_id
    AND credential.revoked_at IS NULL
  RETURNING true,credential.protocol,credential.credential_generation;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false,NULL::text,NULL::bigint;
  END IF;
END
$$;
REVOKE ALL ON FUNCTION filebelt_mount.cancel_credential_operation(uuid,uuid,uuid) FROM PUBLIC;
