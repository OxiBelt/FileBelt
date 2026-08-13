-- SPDX-License-Identifier: Apache-2.0

-- Collaboration must hold a backend row lock while it records the matching
-- drive and object reservations, but its runtime role must not receive UPDATE
-- on storage_backends merely to satisfy PostgreSQL's row-lock privilege rule.
CREATE FUNCTION filebelt_collaboration.reserve_posix_storage_backend(uuid)
RETURNS uuid
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT backend.id
  FROM public.storage_backends AS backend
  WHERE backend.tenant_id = $1
    AND backend.kind = 'posix'
    AND backend.storage_ready
    AND backend.capacity_checked_at > clock_timestamp() - interval '2 minutes'
    AND backend.capacity_free_bytes - (
      SELECT COALESCE(sum(drive.reserved_bytes), 0)
      FROM public.drives AS drive
      WHERE drive.tenant_id = $1
    ) >= 10737418240
    AND (backend.capacity_free_bytes - (
      SELECT COALESCE(sum(drive.reserved_bytes), 0)
      FROM public.drives AS drive
      WHERE drive.tenant_id = $1
    ))::numeric >= backend.capacity_total_bytes::numeric * 0.05
  ORDER BY backend.id
  LIMIT 1
  FOR SHARE OF backend
$$;

REVOKE ALL ON FUNCTION
  filebelt_collaboration.reserve_posix_storage_backend(uuid) FROM PUBLIC;

-- The same privilege rule applies to the shared authorization locks. Return
-- only the four generations the caller must compare; the owner-held row locks
-- remain active until the caller's transaction ends.
CREATE FUNCTION filebelt_collaboration.lock_authorization_fence(
  uuid, uuid, uuid, uuid, uuid
)
RETURNS TABLE (
  membership_generation bigint,
  drive_acl_generation bigint,
  namespace_generation bigint,
  resource_acl_generation bigint,
  session_expires_at text
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT principal.generation,
    drive.acl_generation,
    drive.namespace_generation,
    node.acl_generation,
    LEAST(session.idle_expires_at, session.absolute_expires_at)::text
  FROM public.api_sessions AS session
  JOIN public.users AS user_account
    ON user_account.tenant_id = session.tenant_id
   AND user_account.id = session.user_id
  JOIN public.principals AS principal
    ON principal.tenant_id = session.tenant_id
   AND principal.id = session.principal_id
  JOIN public.drives AS drive
    ON drive.tenant_id = session.tenant_id
  JOIN public.nodes AS node
    ON node.tenant_id = drive.tenant_id
   AND node.drive_id = drive.id
  WHERE session.tenant_id = $1
    AND session.id = $3
    AND session.principal_id = $2
    AND session.revoked_at IS NULL
    AND session.idle_expires_at > clock_timestamp()
    AND session.absolute_expires_at > clock_timestamp()
    AND user_account.status = 'active'
    AND principal.disabled_at IS NULL
    AND drive.id = $4
    AND node.id = $5
  FOR SHARE OF session, user_account, principal, drive, node
$$;

REVOKE ALL ON FUNCTION
  filebelt_collaboration.lock_authorization_fence(uuid,uuid,uuid,uuid,uuid)
  FROM PUBLIC;

-- The I/O worker finalizes bytes but must not gain UPDATE on collaboration
-- epochs merely to hold the epoch fence while it commits an object.
CREATE FUNCTION filebelt_collaboration.lock_epoch(uuid, uuid, bigint)
RETURNS TABLE (
  node_id uuid,
  drive_id uuid,
  state text,
  fencing_token bigint
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT epoch.node_id, epoch.drive_id, epoch.state, epoch.fencing_token
  FROM filebelt_collaboration.epochs AS epoch
  WHERE epoch.tenant_id = $1
    AND epoch.room_id = $2
    AND epoch.epoch = $3
  FOR SHARE OF epoch
$$;

REVOKE ALL ON FUNCTION filebelt_collaboration.lock_epoch(uuid,uuid,bigint)
  FROM PUBLIC;

-- Finalize exactly one collaboration object and consume its matching drive
-- reservation. The I/O role cannot mutate either accounting input directly;
-- retries fail closed after the staging/active pair is consumed.
CREATE FUNCTION filebelt_collaboration.finalize_object(uuid, uuid, bigint, bytea)
RETURNS uuid
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  WITH eligible AS MATERIALIZED (
    SELECT object.tenant_id,
      object.id AS object_id,
      object.drive_id,
      object.reserved_bytes,
      reservation.bytes AS reservation_bytes
    FROM filebelt_collaboration.objects AS object
    JOIN filebelt_collaboration.object_reservations AS reservation
      ON reservation.tenant_id = object.tenant_id
     AND reservation.object_id = object.id
    JOIN public.drives AS drive
      ON drive.tenant_id = object.tenant_id
     AND drive.id = object.drive_id
    WHERE object.tenant_id = $1
      AND object.id = $2
      AND object.state = 'staging'
      AND object.size_bytes IS NULL
      AND object.blake3 IS NULL
      AND object.reserved_bytes >= 0
      AND $3 >= 0
      AND $3 <= object.reserved_bytes
      AND octet_length($4) = 32
      AND reservation.drive_id = object.drive_id
      AND reservation.bytes = object.reserved_bytes
      AND reservation.state = 'active'
      AND drive.reserved_bytes >= object.reserved_bytes
    FOR UPDATE OF object, reservation, drive
  ), finalized AS (
    UPDATE filebelt_collaboration.objects AS object
    SET state = 'durable',
        size_bytes = $3,
        blake3 = $4,
        durable_at = clock_timestamp()
    FROM eligible
    WHERE object.tenant_id = eligible.tenant_id
      AND object.id = eligible.object_id
      AND object.state = 'staging'
    RETURNING eligible.tenant_id,
      eligible.object_id,
      eligible.drive_id,
      eligible.reserved_bytes,
      object.size_bytes
  ), committed AS (
    UPDATE filebelt_collaboration.object_reservations AS reservation
    SET state = 'committed'
    FROM finalized
    WHERE reservation.tenant_id = finalized.tenant_id
      AND reservation.object_id = finalized.object_id
      AND reservation.drive_id = finalized.drive_id
      AND reservation.bytes = finalized.reserved_bytes
      AND reservation.state = 'active'
    RETURNING finalized.tenant_id,
      finalized.drive_id,
      finalized.reserved_bytes,
      finalized.size_bytes
  )
  UPDATE public.drives AS drive
  SET reserved_bytes = drive.reserved_bytes - committed.reserved_bytes,
      used_physical_bytes = drive.used_physical_bytes + committed.size_bytes
  FROM committed
  WHERE drive.tenant_id = committed.tenant_id
    AND drive.id = committed.drive_id
  RETURNING drive.id
$$;

REVOKE ALL ON FUNCTION
  filebelt_collaboration.finalize_object(uuid,uuid,bigint,bytea)
  FROM PUBLIC;
