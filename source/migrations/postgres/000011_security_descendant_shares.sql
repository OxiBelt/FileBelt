-- SPDX-License-Identifier: Apache-2.0

-- Continuous descendant-share attenuation cutover. PostgreSQL owns the
-- admission fence and the durable repair record; Iggy only receives the
-- canonical outbox events emitted after ACL rows are actually removed.

REVOKE ALL ON SCHEMA filebelt_security FROM PUBLIC;

CREATE TABLE filebelt_security.tenant_descendant_share_admission (
  tenant_id uuid PRIMARY KEY REFERENCES public.tenants(id) ON DELETE CASCADE,
  state text NOT NULL DEFAULT 'blocked'
    CHECK (state IN ('blocked','repairing','verified','open')),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  fence_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  active_repair_run_id uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  opened_at timestamptz,
  opened_by uuid,
  FOREIGN KEY (tenant_id,opened_by) REFERENCES public.principals(tenant_id,id)
);

INSERT INTO filebelt_security.tenant_descendant_share_admission (tenant_id,state)
SELECT id,'blocked' FROM public.tenants
ON CONFLICT (tenant_id) DO NOTHING;

CREATE FUNCTION filebelt_security.seed_tenant_descendant_share_admission()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_security
AS $$
BEGIN
  INSERT INTO filebelt_security.tenant_descendant_share_admission (tenant_id,state)
  VALUES (NEW.id,'blocked')
  ON CONFLICT (tenant_id) DO NOTHING;
  RETURN NEW;
END
$$;
CREATE TRIGGER tenant_descendant_share_admission_seed
AFTER INSERT ON public.tenants
FOR EACH ROW EXECUTE FUNCTION filebelt_security.seed_tenant_descendant_share_admission();

-- This is intentionally STABLE and the only security-schema read granted to
-- the API. It is used at the API/database close-race boundary, not as policy.
CREATE FUNCTION filebelt_security.descendant_share_admission_open(p_tenant_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_security
AS $$
  SELECT COALESCE((
    SELECT state='open'
    FROM filebelt_security.tenant_descendant_share_admission
    WHERE tenant_id=p_tenant_id
  ),false);
$$;

CREATE FUNCTION filebelt_security.require_descendant_share_admission_open(p_tenant_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_security
AS $$
BEGIN
  IF NOT filebelt_security.descendant_share_admission_open(p_tenant_id) THEN
    RAISE EXCEPTION USING
      ERRCODE='FB001',
      MESSAGE='filebelt descendant-share admission is blocked';
  END IF;
END
$$;

ALTER TABLE public.direct_shares
  ADD COLUMN IF NOT EXISTS revocation_reason text,
  ADD COLUMN IF NOT EXISTS repair_run_id uuid,
  ADD COLUMN IF NOT EXISTS authorization_model_version smallint;
ALTER TABLE filebelt_mcp.data_grants
  ADD COLUMN IF NOT EXISTS drive_acl_generation bigint,
  ADD COLUMN IF NOT EXISTS revocation_reason text,
  ADD COLUMN IF NOT EXISTS repair_run_id uuid;

ALTER TABLE public.direct_shares
  ADD CONSTRAINT direct_shares_revocation_reason_check
  CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 128) NOT VALID,
  ADD CONSTRAINT direct_shares_authorization_model_version_check
  CHECK (authorization_model_version IS NULL OR authorization_model_version = 1) NOT VALID;
ALTER TABLE filebelt_mcp.data_grants
  ADD CONSTRAINT data_grants_drive_acl_generation_positive_check
  CHECK (drive_acl_generation IS NULL OR drive_acl_generation > 0) NOT VALID,
  ADD CONSTRAINT data_grants_legacy_drive_acl_generation_check
  CHECK (drive_acl_generation IS NOT NULL OR revoked_at IS NOT NULL) NOT VALID,
  ADD CONSTRAINT data_grants_revocation_reason_check
  CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 128) NOT VALID;

CREATE TABLE filebelt_security.descendant_share_repair_runs (
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
  id uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('running','verified','activated')),
  started_by uuid NOT NULL,
  source_revision text NOT NULL CHECK (length(source_revision) BETWEEN 1 AND 128),
  started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  verified_at timestamptz,
  activated_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id,started_by) REFERENCES public.principals(tenant_id,id),
  CHECK ((state IN ('verified','activated')) = (verified_at IS NOT NULL)),
  CHECK ((state='activated') = (activated_at IS NOT NULL))
);
CREATE UNIQUE INDEX descendant_share_repair_one_open_run
  ON filebelt_security.descendant_share_repair_runs (tenant_id)
  WHERE state IN ('running','verified');

ALTER TABLE filebelt_security.tenant_descendant_share_admission
  ADD CONSTRAINT tenant_descendant_share_admission_run_fk
  FOREIGN KEY (tenant_id,active_repair_run_id)
  REFERENCES filebelt_security.descendant_share_repair_runs(tenant_id,id);
ALTER TABLE public.direct_shares
  ADD CONSTRAINT direct_shares_repair_run_fk
  FOREIGN KEY (tenant_id,repair_run_id)
  REFERENCES filebelt_security.descendant_share_repair_runs(tenant_id,id);
ALTER TABLE filebelt_mcp.data_grants
  ADD CONSTRAINT data_grants_repair_run_fk
  FOREIGN KEY (tenant_id,repair_run_id)
  REFERENCES filebelt_security.descendant_share_repair_runs(tenant_id,id);

CREATE TABLE filebelt_security.descendant_share_repair_batches (
  tenant_id uuid NOT NULL,
  run_id uuid NOT NULL,
  id uuid NOT NULL,
  requested_limit integer NOT NULL CHECK (requested_limit BETWEEN 1 AND 1000),
  direct_shares_revoked integer NOT NULL DEFAULT 0 CHECK (direct_shares_revoked >= 0),
  data_grants_revoked integer NOT NULL DEFAULT 0 CHECK (data_grants_revoked >= 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id,run_id)
    REFERENCES filebelt_security.descendant_share_repair_runs(tenant_id,id)
);

CREATE TABLE filebelt_security.descendant_share_repair_receipts (
  tenant_id uuid NOT NULL,
  run_id uuid NOT NULL,
  batch_id uuid NOT NULL,
  object_kind text NOT NULL CHECK (object_kind IN ('direct_share','mcp_data_grant')),
  object_id uuid NOT NULL,
  drive_id uuid NOT NULL,
  resource_id uuid NOT NULL,
  reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 128),
  repaired_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,run_id,object_kind,object_id),
  FOREIGN KEY (tenant_id,run_id)
    REFERENCES filebelt_security.descendant_share_repair_runs(tenant_id,id),
  FOREIGN KEY (tenant_id,batch_id)
    REFERENCES filebelt_security.descendant_share_repair_batches(tenant_id,id)
);
CREATE INDEX descendant_share_repair_receipts_batch_index
  ON filebelt_security.descendant_share_repair_receipts (tenant_id,batch_id,object_kind);
CREATE INDEX direct_shares_active_recursive_creator_drive_index
  ON public.direct_shares (tenant_id,created_by,drive_id)
  WHERE revoked_at IS NULL AND inheritance='self_and_descendants';
CREATE INDEX direct_shares_active_recursive_repair_index
  ON public.direct_shares (tenant_id,created_at,id)
  WHERE revoked_at IS NULL AND inheritance='self_and_descendants';
CREATE INDEX data_grants_active_pre_fence_repair_index
  ON filebelt_mcp.data_grants (tenant_id,created_at,id)
  WHERE revoked_at IS NULL;

-- The public API must never create an untracked share while a tenant is
-- blocked, and an old writer must remain unable to create one after the gate
-- opens. NULL is retained only for legacy evidence. FB001 is the stable
-- retry/close-race and incompatible-writer contract for both backstops.
CREATE FUNCTION filebelt_security.direct_share_insert_backstop()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_security
AS $$
BEGIN
  PERFORM filebelt_security.require_descendant_share_admission_open(NEW.tenant_id);
  IF NEW.authorization_model_version IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION USING
      ERRCODE='FB001',
      MESSAGE='filebelt descendant-share authorization model is incompatible';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER direct_share_admission_backstop
BEFORE INSERT ON public.direct_shares
FOR EACH ROW EXECUTE FUNCTION filebelt_security.direct_share_insert_backstop();

-- All post-cutover grants carry the locked drive fence. NULL remains legal
-- only for a revoked legacy row so repair can be rolled out without rewriting
-- historical evidence.
CREATE FUNCTION filebelt_security.data_grant_insert_backstop()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mcp,filebelt_security
AS $$
BEGIN
  PERFORM filebelt_security.require_descendant_share_admission_open(NEW.tenant_id);
  IF NEW.drive_acl_generation IS NULL OR NEW.drive_acl_generation <= 0 THEN
    RAISE EXCEPTION USING
      ERRCODE='FB001',
      MESSAGE='filebelt descendant-share admission is blocked';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER data_grant_drive_acl_generation_backstop
BEFORE INSERT ON filebelt_mcp.data_grants
FOR EACH ROW EXECUTE FUNCTION filebelt_security.data_grant_insert_backstop();

-- Only the two primitive helpers below construct Protobuf bytes. Field tags
-- match protocol/events/v1/events.proto exactly: strings 1-4 and 6 are
-- length-delimited, generations 5 and 7 are varints, and empty field 8 is
-- omitted exactly as prost encodes EventEnvelope { payload: Vec::new() }.
CREATE FUNCTION filebelt_security.protobuf_varint(p_value bigint)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path=pg_catalog
AS $$
DECLARE
  v_value bigint := p_value;
  v_result bytea := ''::bytea;
BEGIN
  IF v_value < 0 THEN
    RAISE EXCEPTION 'protobuf varint input must be non-negative';
  END IF;
  WHILE v_value >= 128 LOOP
    v_result := v_result || decode(lpad(to_hex((v_value % 128) + 128),2,'0'),'hex');
    v_value := v_value / 128;
  END LOOP;
  RETURN v_result || decode(lpad(to_hex(v_value),2,'0'),'hex');
END
$$;

CREATE FUNCTION filebelt_security.protobuf_bytes_field(p_field integer,p_value bytea)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path=pg_catalog,filebelt_security
AS $$
  SELECT filebelt_security.protobuf_varint((p_field::bigint << 3) | 2)
    || filebelt_security.protobuf_varint(octet_length(p_value)) || p_value;
$$;

CREATE FUNCTION filebelt_security.encode_event_envelope(
  p_event_id uuid,p_tenant_id uuid,p_aggregate_type text,p_aggregate_id uuid,
  p_aggregate_generation bigint,p_event_type text,p_occurred_at_unix_seconds bigint
) RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path=pg_catalog,filebelt_security
AS $$
  SELECT filebelt_security.protobuf_bytes_field(1,convert_to(p_event_id::text,'UTF8'))
    || filebelt_security.protobuf_bytes_field(2,convert_to(p_tenant_id::text,'UTF8'))
    || filebelt_security.protobuf_bytes_field(3,convert_to(p_aggregate_type,'UTF8'))
    || filebelt_security.protobuf_bytes_field(4,convert_to(p_aggregate_id::text,'UTF8'))
    || filebelt_security.protobuf_varint((5::bigint << 3) | 0)
    || filebelt_security.protobuf_varint(p_aggregate_generation)
    || filebelt_security.protobuf_bytes_field(6,convert_to(p_event_type,'UTF8'))
    || filebelt_security.protobuf_varint((7::bigint << 3) | 0)
    || filebelt_security.protobuf_varint(p_occurred_at_unix_seconds);
$$;

-- Migration-time static checks protect the hand-written encoder's two wire
-- primitives; runtime consumers additionally decode this with prost.
DO $$
DECLARE
  v_envelope bytea;
BEGIN
  v_envelope := filebelt_security.encode_event_envelope(
    '00000000-0000-4000-8000-000000000001'::uuid,
    '00000000-0000-4000-8000-000000000002'::uuid,
    'node','00000000-0000-4000-8000-000000000003'::uuid,
    2,'filebelt.v1.acl.changed',1
  );
  IF filebelt_security.protobuf_varint(300) <> decode('ac02','hex')
     OR substring(v_envelope FROM 1 FOR 1) <> decode('0a','hex')
     OR position(decode('2802','hex') IN v_envelope)=0
     OR position(decode('3801','hex') IN v_envelope)=0 THEN
    RAISE EXCEPTION 'filebelt EventEnvelope SQL encoder self-check failed';
  END IF;
END
$$;

CREATE FUNCTION filebelt_security.assert_live_tenant_admin(
  p_tenant_id uuid,p_actor_principal_id uuid
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_security
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM public.users u
    JOIN public.external_identities ei
      ON ei.tenant_id=u.tenant_id AND ei.user_id=u.id AND ei.disabled_at IS NULL
    JOIN public.tenant_admin_bindings b
      ON b.tenant_id=ei.tenant_id AND b.issuer=ei.issuer AND b.subject=ei.subject
    JOIN public.principals p ON p.tenant_id=u.tenant_id AND p.id=u.principal_id
    WHERE u.tenant_id=p_tenant_id AND u.principal_id=p_actor_principal_id
      AND u.status='active' AND p.disabled_at IS NULL
  ) THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='live tenant administrator required';
  END IF;
END
$$;

CREATE FUNCTION filebelt_security.descendant_shares_remaining(p_tenant_id uuid)
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mcp,filebelt_security
AS $$
  SELECT (
    (SELECT count(*) FROM public.direct_shares d
      JOIN filebelt_security.tenant_descendant_share_admission s ON s.tenant_id=d.tenant_id
      WHERE d.tenant_id=p_tenant_id AND d.revoked_at IS NULL
        AND d.inheritance='self_and_descendants' AND d.created_at < s.fence_at)
    + (SELECT count(*) FROM filebelt_mcp.data_grants g
      JOIN filebelt_security.tenant_descendant_share_admission s ON s.tenant_id=g.tenant_id
      WHERE g.tenant_id=p_tenant_id AND g.revoked_at IS NULL AND g.created_at < s.fence_at)
  )::integer;
$$;

CREATE FUNCTION filebelt_security.descendant_shares_status(
  p_tenant_id uuid,p_operation_id uuid
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_security
AS $$
DECLARE
  v_state text;
  v_run uuid;
  v_generation bigint;
  v_fence_at timestamptz;
  v_opened_at timestamptz;
  v_opened_by uuid;
  v_source_revision text;
  v_remaining integer;
BEGIN
  SELECT state,active_repair_run_id,generation,fence_at,opened_at,opened_by
    INTO v_state,v_run,v_generation,v_fence_at,v_opened_at,v_opened_by
  FROM filebelt_security.tenant_descendant_share_admission WHERE tenant_id=p_tenant_id;
  v_remaining := filebelt_security.descendant_shares_remaining(p_tenant_id);
  SELECT source_revision INTO v_source_revision
  FROM filebelt_security.descendant_share_repair_runs
  WHERE tenant_id=p_tenant_id AND id=p_operation_id;
  RETURN jsonb_build_object('state',COALESCE(v_state,'blocked'),'operation_id',p_operation_id,
    'active_operation_id',v_run,'generation',COALESCE(v_generation,0),'fence_at',v_fence_at,
    'opened_at',v_opened_at,'opened_by',v_opened_by,'source_revision',v_source_revision,
    'remaining',v_remaining,'admission_open',COALESCE(v_state='open',false));
END
$$;

CREATE FUNCTION filebelt_security.repair_descendant_shares(
  p_tenant_id uuid,p_operation_id uuid,p_confirm_tenant text,p_actor_principal_id uuid,p_limit integer
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mcp,filebelt_security
AS $$
DECLARE
  v_run uuid;
  v_run_state text;
  v_admission_state text;
  v_fence_at timestamptz;
  v_tenant_slug text;
  v_source_revision text := current_setting('filebelt.source_revision',true);
  v_batch uuid := uuidv7();
  v_direct_count integer := 0;
  v_grant_count integer := 0;
  v_remaining integer;
BEGIN
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='repair limit must be between 1 and 1000';
  END IF;
  IF p_operation_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='repair operation id is required';
  END IF;
  IF v_source_revision IS NULL OR length(v_source_revision) NOT BETWEEN 1 AND 128 THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='source revision is required';
  END IF;
  SELECT slug INTO v_tenant_slug FROM public.tenants WHERE id=p_tenant_id;
  IF v_tenant_slug IS NULL OR p_confirm_tenant IS DISTINCT FROM v_tenant_slug THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='exact tenant slug confirmation is required';
  END IF;
  PERFORM filebelt_security.assert_live_tenant_admin(p_tenant_id,p_actor_principal_id);
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'filebelt_security.descendant_share_repair:' || p_tenant_id::text,0));

  SELECT state,fence_at INTO v_admission_state,v_fence_at
  FROM filebelt_security.tenant_descendant_share_admission
  WHERE tenant_id=p_tenant_id FOR UPDATE;
  IF v_fence_at IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='descendant-share admission state is missing';
  END IF;
  IF v_admission_state='open' AND NOT EXISTS (
    SELECT 1 FROM filebelt_security.descendant_share_repair_runs
    WHERE tenant_id=p_tenant_id AND id=p_operation_id AND state='activated'
      AND started_by=p_actor_principal_id AND source_revision=v_source_revision
  ) THEN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='descendant-share admission is already open';
  END IF;
  IF EXISTS (
    SELECT 1 FROM filebelt_security.descendant_share_repair_runs
    WHERE tenant_id=p_tenant_id AND state IN ('running','verified') AND id <> p_operation_id
  ) THEN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='different descendant-share repair operation is active';
  END IF;
  SELECT id,state INTO v_run,v_run_state
  FROM filebelt_security.descendant_share_repair_runs
  WHERE tenant_id=p_tenant_id AND id=p_operation_id FOR UPDATE;
  IF v_run IS NULL THEN
    v_run := p_operation_id;
    INSERT INTO filebelt_security.descendant_share_repair_runs
      (tenant_id,id,state,started_by,source_revision)
      VALUES (p_tenant_id,v_run,'running',p_actor_principal_id,v_source_revision);
  ELSIF NOT EXISTS (
    SELECT 1 FROM filebelt_security.descendant_share_repair_runs
    WHERE tenant_id=p_tenant_id AND id=v_run AND started_by=p_actor_principal_id
      AND source_revision=v_source_revision
  ) THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='repair operation actor does not match';
  END IF;
  IF v_run_state IN ('verified','activated') THEN
    v_remaining := filebelt_security.descendant_shares_remaining(p_tenant_id);
    RETURN jsonb_build_object('operation_id',v_run,'selected',0,'remaining',v_remaining,
      'state',v_run_state,'idempotent',true);
  END IF;
  UPDATE filebelt_security.tenant_descendant_share_admission
  SET state='repairing',active_repair_run_id=v_run,generation=generation+1,updated_at=clock_timestamp()
  WHERE tenant_id=p_tenant_id AND state <> 'open'
    AND (state <> 'repairing' OR active_repair_run_id IS DISTINCT FROM v_run);
  INSERT INTO filebelt_security.descendant_share_repair_batches
    (tenant_id,run_id,id,requested_limit) VALUES (p_tenant_id,v_run,v_batch,p_limit);

  WITH candidates AS MATERIALIZED (
    SELECT s.tenant_id,s.id,s.drive_id,s.resource_id
    FROM public.direct_shares s
    WHERE s.tenant_id=p_tenant_id AND s.revoked_at IS NULL
      AND s.inheritance='self_and_descendants' AND s.created_at < v_fence_at
    ORDER BY s.id FOR UPDATE SKIP LOCKED LIMIT p_limit
  ), revoked AS (
    UPDATE public.direct_shares s
    SET revoked_at=clock_timestamp(),revocation_reason='security.descendant_attenuation_v1',repair_run_id=v_run
    FROM candidates c WHERE s.tenant_id=c.tenant_id AND s.id=c.id
    RETURNING s.tenant_id,s.id,s.drive_id,s.resource_id
  )
  INSERT INTO filebelt_security.descendant_share_repair_receipts
    (tenant_id,run_id,batch_id,object_kind,object_id,drive_id,resource_id,reason)
  SELECT tenant_id,v_run,v_batch,'direct_share',id,drive_id,resource_id,
    'security.descendant_attenuation_v1' FROM revoked;
  GET DIAGNOSTICS v_direct_count = ROW_COUNT;

  -- Standalone DELETE lets the existing ACL projection trigger advance the
  -- affected generations before the EventEnvelope reads the final value.
  DELETE FROM public.acl_entries a
  USING filebelt_security.descendant_share_repair_receipts r
  WHERE r.tenant_id=p_tenant_id AND r.run_id=v_run AND r.batch_id=v_batch
    AND r.object_kind='direct_share' AND a.tenant_id=r.tenant_id
    AND a.direct_share_id=r.object_id;

  WITH affected AS (
    SELECT DISTINCT r.tenant_id,r.drive_id,r.resource_id
    FROM filebelt_security.descendant_share_repair_receipts r
    WHERE r.tenant_id=p_tenant_id AND r.run_id=v_run AND r.batch_id=v_batch
      AND r.object_kind='direct_share'
  ), events AS (
    SELECT a.tenant_id,uuidv7() AS id,a.resource_id,n.acl_generation,
      extract(epoch FROM clock_timestamp())::bigint AS occurred_at
    FROM affected a
    JOIN public.nodes n ON n.tenant_id=a.tenant_id AND n.drive_id=a.drive_id AND n.id=a.resource_id
  )
  INSERT INTO public.outbox_events
    (tenant_id,id,topic,aggregate_type,aggregate_id,aggregate_generation,partition_key,payload)
  SELECT tenant_id,id,'filebelt.v1.acl.changed','node',resource_id,acl_generation,
    tenant_id::text || ':' || resource_id::text,
    filebelt_security.encode_event_envelope(id,tenant_id,'node',resource_id,
      acl_generation,'filebelt.v1.acl.changed',occurred_at)
  FROM events;

  WITH candidates AS MATERIALIZED (
    SELECT g.tenant_id,g.id,g.drive_id,g.resource_id
    FROM filebelt_mcp.data_grants g
    WHERE g.tenant_id=p_tenant_id AND g.revoked_at IS NULL
      AND g.created_at < v_fence_at
    ORDER BY g.id FOR UPDATE SKIP LOCKED
    LIMIT GREATEST(p_limit-v_direct_count,0)
  ), revoked AS (
    UPDATE filebelt_mcp.data_grants g
    SET revoked_at=clock_timestamp(),revocation_reason='security.pre_fence_mcp_data_grant',repair_run_id=v_run
    FROM candidates c WHERE g.tenant_id=c.tenant_id AND g.id=c.id
    RETURNING g.tenant_id,g.id,g.drive_id,g.resource_id
  )
  INSERT INTO filebelt_security.descendant_share_repair_receipts
    (tenant_id,run_id,batch_id,object_kind,object_id,drive_id,resource_id,reason)
  SELECT tenant_id,v_run,v_batch,'mcp_data_grant',id,drive_id,resource_id,
    'security.pre_fence_mcp_data_grant' FROM revoked;
  GET DIAGNOSTICS v_grant_count = ROW_COUNT;

  v_remaining := filebelt_security.descendant_shares_remaining(p_tenant_id);
  UPDATE filebelt_security.descendant_share_repair_batches
  SET direct_shares_revoked=v_direct_count,data_grants_revoked=v_grant_count,
    completed_at=clock_timestamp()
  WHERE tenant_id=p_tenant_id AND id=v_batch;
  INSERT INTO public.audit_events
    (tenant_id,id,actor_principal_id,action,outcome,reason_code,privacy_visible,request_id,details)
  VALUES (p_tenant_id,uuidv7(),p_actor_principal_id,'security.descendant_share.repair',
    'allowed','security.descendant_share.repair_batch',false,NULL,jsonb_build_object('operation_id',v_run,
      'batch_id',v_batch,'direct_shares_revoked',v_direct_count,
      'data_grants_revoked',v_grant_count,'remaining',v_remaining,
      'source_revision',v_source_revision));
  RETURN jsonb_build_object('operation_id',v_run,'batch_id',v_batch,
    'selected',v_direct_count+v_grant_count,
    'direct_shares_revoked',v_direct_count,'data_grants_revoked',v_grant_count,
    'remaining',v_remaining);
END
$$;

CREATE FUNCTION filebelt_security.verify_descendant_shares(
  p_tenant_id uuid,p_operation_id uuid,p_confirm_tenant text,p_actor_principal_id uuid
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_security
AS $$
DECLARE
  v_tenant_slug text;
  v_remaining integer;
  v_orphans integer;
  v_source_revision text := current_setting('filebelt.source_revision',true);
  v_already_verified boolean;
BEGIN
  IF p_operation_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='verification operation id is required';
  END IF;
  IF v_source_revision IS NULL OR length(v_source_revision) NOT BETWEEN 1 AND 128 THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='source revision is required';
  END IF;
  SELECT slug INTO v_tenant_slug FROM public.tenants WHERE id=p_tenant_id;
  IF v_tenant_slug IS NULL OR p_confirm_tenant IS DISTINCT FROM v_tenant_slug THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='exact tenant slug confirmation is required';
  END IF;
  PERFORM filebelt_security.assert_live_tenant_admin(p_tenant_id,p_actor_principal_id);
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'filebelt_security.descendant_share_repair:' || p_tenant_id::text,0));
  IF NOT EXISTS (
    SELECT 1 FROM filebelt_security.descendant_share_repair_runs
    WHERE tenant_id=p_tenant_id AND id=p_operation_id AND state IN ('running','verified')
      AND started_by=p_actor_principal_id AND source_revision=v_source_revision
  ) THEN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='matching resumable descendant-share repair operation required';
  END IF;
  SELECT state='verified' INTO v_already_verified
  FROM filebelt_security.descendant_share_repair_runs
  WHERE tenant_id=p_tenant_id AND id=p_operation_id;
  IF NOT EXISTS (
    SELECT 1 FROM filebelt_security.tenant_descendant_share_admission
    WHERE tenant_id=p_tenant_id AND state IN ('blocked','repairing','verified')
      AND active_repair_run_id=p_operation_id
  ) THEN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='descendant-share admission state is not fenced for this operation';
  END IF;
  v_remaining := filebelt_security.descendant_shares_remaining(p_tenant_id);
  SELECT count(*) INTO v_orphans
  FROM public.acl_entries a
  JOIN filebelt_security.descendant_share_repair_receipts r
    ON r.tenant_id=a.tenant_id AND r.object_kind='direct_share' AND r.object_id=a.direct_share_id
  WHERE r.tenant_id=p_tenant_id AND r.run_id=p_operation_id;
  IF v_remaining <> 0 OR v_orphans <> 0
     OR EXISTS (
       SELECT 1
       FROM public.direct_shares s
       JOIN filebelt_security.tenant_descendant_share_admission a
         ON a.tenant_id=s.tenant_id
       WHERE s.tenant_id=p_tenant_id AND s.revoked_at IS NULL
         AND s.created_at >= a.fence_at
         AND s.authorization_model_version IS DISTINCT FROM 1
     )
     OR EXISTS (
       SELECT 1
       FROM filebelt_security.descendant_share_repair_receipts r
       LEFT JOIN filebelt_security.descendant_share_repair_batches b
         ON b.tenant_id=r.tenant_id AND b.id=r.batch_id AND b.run_id=r.run_id
       WHERE r.tenant_id=p_tenant_id AND r.run_id=p_operation_id
         AND (b.id IS NULL OR b.completed_at IS NULL)
     )
     OR EXISTS (
       SELECT 1 FROM public.direct_shares s
       WHERE s.tenant_id=p_tenant_id AND s.repair_run_id=p_operation_id
         AND NOT EXISTS (
           SELECT 1 FROM filebelt_security.descendant_share_repair_receipts r
           WHERE r.tenant_id=s.tenant_id AND r.run_id=p_operation_id
             AND r.object_kind='direct_share' AND r.object_id=s.id
         )
     )
     OR EXISTS (
       SELECT 1 FROM filebelt_mcp.data_grants g
       WHERE g.tenant_id=p_tenant_id AND g.repair_run_id=p_operation_id
         AND NOT EXISTS (
           SELECT 1 FROM filebelt_security.descendant_share_repair_receipts r
           WHERE r.tenant_id=g.tenant_id AND r.run_id=p_operation_id
             AND r.object_kind='mcp_data_grant' AND r.object_id=g.id
         )
     )
     OR EXISTS (
       SELECT 1
       FROM filebelt_security.descendant_share_repair_batches b
       WHERE b.tenant_id=p_tenant_id AND b.run_id=p_operation_id
         AND (
           b.direct_shares_revoked <> (
             SELECT count(*) FROM filebelt_security.descendant_share_repair_receipts r
             WHERE r.tenant_id=b.tenant_id AND r.batch_id=b.id
               AND r.object_kind='direct_share'
           )
           OR b.data_grants_revoked <> (
             SELECT count(*) FROM filebelt_security.descendant_share_repair_receipts r
             WHERE r.tenant_id=b.tenant_id AND r.batch_id=b.id
               AND r.object_kind='mcp_data_grant'
           )
         )
     )
     OR EXISTS (
       SELECT 1
       FROM filebelt_security.descendant_share_repair_receipts r
       LEFT JOIN public.direct_shares s
         ON s.tenant_id=r.tenant_id AND s.id=r.object_id
       WHERE r.tenant_id=p_tenant_id AND r.run_id=p_operation_id
         AND r.object_kind='direct_share'
         AND (s.id IS NULL OR s.revoked_at IS NULL OR s.repair_run_id IS DISTINCT FROM p_operation_id
           OR s.revocation_reason IS DISTINCT FROM r.reason)
     )
     OR EXISTS (
       SELECT 1
       FROM filebelt_security.descendant_share_repair_receipts r
       LEFT JOIN filebelt_mcp.data_grants g
         ON g.tenant_id=r.tenant_id AND g.id=r.object_id
       WHERE r.tenant_id=p_tenant_id AND r.run_id=p_operation_id
         AND r.object_kind='mcp_data_grant'
         AND (g.id IS NULL OR g.revoked_at IS NULL OR g.repair_run_id IS DISTINCT FROM p_operation_id
           OR g.revocation_reason IS DISTINCT FROM r.reason)
     ) THEN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='descendant-share repair verification found residual state';
  END IF;
  IF v_already_verified THEN
    RETURN jsonb_build_object('operation_id',p_operation_id,'remaining',0,
      'verified',true,'idempotent',true);
  END IF;
  UPDATE filebelt_security.descendant_share_repair_runs
  SET state='verified',verified_at=COALESCE(verified_at,clock_timestamp())
  WHERE tenant_id=p_tenant_id AND id=p_operation_id;
  UPDATE filebelt_security.tenant_descendant_share_admission
  SET state='verified',generation=generation+1,updated_at=clock_timestamp()
  WHERE tenant_id=p_tenant_id AND state <> 'verified';
  INSERT INTO public.audit_events
    (tenant_id,id,actor_principal_id,action,outcome,reason_code,privacy_visible,request_id,details)
  VALUES (p_tenant_id,uuidv7(),p_actor_principal_id,'security.descendant_share.verify',
    'allowed','security.descendant_share.verify',false,NULL,jsonb_build_object(
      'operation_id',p_operation_id,'remaining',0,'source_revision',v_source_revision));
  RETURN jsonb_build_object('operation_id',p_operation_id,'remaining',0,'verified',true);
END
$$;

CREATE FUNCTION filebelt_security.activate_descendant_shares(
  p_tenant_id uuid,p_operation_id uuid,p_confirm_tenant text,p_actor_principal_id uuid
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_security
AS $$
DECLARE
  v_tenant_slug text;
  v_remaining integer;
  v_source_revision text := current_setting('filebelt.source_revision',true);
  v_already_activated boolean;
BEGIN
  IF p_operation_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='activation operation id is required';
  END IF;
  IF v_source_revision IS NULL OR length(v_source_revision) NOT BETWEEN 1 AND 128 THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='source revision is required';
  END IF;
  SELECT slug INTO v_tenant_slug FROM public.tenants WHERE id=p_tenant_id;
  IF v_tenant_slug IS NULL OR p_confirm_tenant IS DISTINCT FROM v_tenant_slug THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='exact tenant slug confirmation is required';
  END IF;
  PERFORM filebelt_security.assert_live_tenant_admin(p_tenant_id,p_actor_principal_id);
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'filebelt_security.descendant_share_repair:' || p_tenant_id::text,0));
  IF NOT EXISTS (
    SELECT 1 FROM filebelt_security.descendant_share_repair_runs
    WHERE tenant_id=p_tenant_id AND id=p_operation_id AND state IN ('verified','activated')
      AND started_by=p_actor_principal_id AND source_revision=v_source_revision
  ) THEN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='matching verified descendant-share repair operation required';
  END IF;
  SELECT state='activated' INTO v_already_activated
  FROM filebelt_security.descendant_share_repair_runs
  WHERE tenant_id=p_tenant_id AND id=p_operation_id;
  v_remaining := filebelt_security.descendant_shares_remaining(p_tenant_id);
  IF v_remaining <> 0 THEN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='descendant-share repair still has remaining rows';
  END IF;
  IF v_already_activated THEN
    RETURN jsonb_build_object('operation_id',p_operation_id,'remaining',0,
      'admission_open',true,'idempotent',true);
  END IF;
  UPDATE filebelt_security.descendant_share_repair_runs
  SET state='activated',activated_at=COALESCE(activated_at,clock_timestamp())
  WHERE tenant_id=p_tenant_id AND id=p_operation_id;
  UPDATE filebelt_security.tenant_descendant_share_admission
  SET state='open',active_repair_run_id=p_operation_id,opened_at=COALESCE(opened_at,clock_timestamp()),
    opened_by=COALESCE(opened_by,p_actor_principal_id),generation=generation+1,
    updated_at=clock_timestamp() WHERE tenant_id=p_tenant_id AND state <> 'open';
  INSERT INTO public.audit_events
    (tenant_id,id,actor_principal_id,action,outcome,reason_code,privacy_visible,request_id,details)
  VALUES (p_tenant_id,uuidv7(),p_actor_principal_id,'security.descendant_share.activate',
    'allowed','security.descendant_share.activate',false,NULL,jsonb_build_object(
      'operation_id',p_operation_id,'remaining',0,'source_revision',v_source_revision));
  RETURN jsonb_build_object('operation_id',p_operation_id,'remaining',0,'admission_open',true);
END
$$;

-- Membership changes, user suspension, and creator disablement can attenuate a
-- descendant share after it was issued. These statement triggers preserve the
-- existing projection invalidation while advancing each affected creator drive
-- only once.
DROP TRIGGER membership_capability_projection ON public.group_memberships;
DROP TRIGGER user_capability_projection ON public.users;
DROP TRIGGER principal_capability_projection ON public.principals;

CREATE FUNCTION filebelt_security.invalidate_membership_creator_fanout()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_security
AS $$
BEGIN
  UPDATE public.principals p SET generation=p.generation+1
  FROM (SELECT DISTINCT tenant_id,user_principal_id FROM changed_memberships) changed
  WHERE p.tenant_id=changed.tenant_id AND p.id=changed.user_principal_id;
  DELETE FROM public.authorization_generations a
  USING (SELECT DISTINCT tenant_id,user_principal_id FROM changed_memberships) changed
  WHERE a.tenant_id=changed.tenant_id AND a.principal_id=changed.user_principal_id;
  UPDATE public.drives d SET acl_generation=d.acl_generation+1
  FROM (
    SELECT DISTINCT s.tenant_id,s.drive_id
    FROM public.direct_shares s
    JOIN (SELECT DISTINCT tenant_id,user_principal_id FROM changed_memberships) changed
      ON changed.tenant_id=s.tenant_id AND changed.user_principal_id=s.created_by
    WHERE s.revoked_at IS NULL AND s.inheritance='self_and_descendants'
  ) changed
  WHERE d.tenant_id=changed.tenant_id AND d.id=changed.drive_id;
  RETURN NULL;
END
$$;

CREATE FUNCTION filebelt_security.invalidate_updated_membership_creator_fanout()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_security
AS $$
BEGIN
  UPDATE public.principals p SET generation=p.generation+1
  FROM (
    SELECT tenant_id,user_principal_id FROM old_memberships
    UNION
    SELECT tenant_id,user_principal_id FROM changed_memberships
  ) changed
  WHERE p.tenant_id=changed.tenant_id AND p.id=changed.user_principal_id;
  DELETE FROM public.authorization_generations a
  USING (
    SELECT tenant_id,user_principal_id FROM old_memberships
    UNION
    SELECT tenant_id,user_principal_id FROM changed_memberships
  ) changed
  WHERE a.tenant_id=changed.tenant_id AND a.principal_id=changed.user_principal_id;
  UPDATE public.drives d SET acl_generation=d.acl_generation+1
  FROM (
    SELECT DISTINCT s.tenant_id,s.drive_id
    FROM public.direct_shares s
    JOIN (
      SELECT tenant_id,user_principal_id FROM old_memberships
      UNION
      SELECT tenant_id,user_principal_id FROM changed_memberships
    ) changed ON changed.tenant_id=s.tenant_id AND changed.user_principal_id=s.created_by
    WHERE s.revoked_at IS NULL AND s.inheritance='self_and_descendants'
  ) changed
  WHERE d.tenant_id=changed.tenant_id AND d.id=changed.drive_id;
  RETURN NULL;
END
$$;

CREATE FUNCTION filebelt_security.invalidate_principal_disable_creator_fanout()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_security
AS $$
BEGIN
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

CREATE FUNCTION filebelt_security.invalidate_user_status_creator_fanout()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_security
AS $$
BEGIN
  DELETE FROM public.authorization_generations a
  USING (
    SELECT n.tenant_id,n.principal_id
    FROM old_users o
    JOIN changed_users n ON n.tenant_id=o.tenant_id AND n.id=o.id
    WHERE o.status IS DISTINCT FROM n.status
  ) changed
  WHERE a.tenant_id=changed.tenant_id AND a.principal_id=changed.principal_id;
  UPDATE public.drives d SET acl_generation=d.acl_generation+1
  FROM (
    SELECT DISTINCT s.tenant_id,s.drive_id
    FROM public.direct_shares s
    JOIN (
      SELECT n.tenant_id,n.principal_id
      FROM old_users o
      JOIN changed_users n ON n.tenant_id=o.tenant_id AND n.id=o.id
      WHERE o.status IS DISTINCT FROM n.status
    ) changed ON changed.tenant_id=s.tenant_id AND changed.principal_id=s.created_by
    WHERE s.revoked_at IS NULL AND s.inheritance='self_and_descendants'
  ) changed
  WHERE d.tenant_id=changed.tenant_id AND d.id=changed.drive_id;
  RETURN NULL;
END
$$;

CREATE TRIGGER membership_capability_projection_insert
AFTER INSERT ON public.group_memberships
REFERENCING NEW TABLE AS changed_memberships
FOR EACH STATEMENT EXECUTE FUNCTION filebelt_security.invalidate_membership_creator_fanout();
CREATE TRIGGER membership_capability_projection_delete
AFTER DELETE ON public.group_memberships
REFERENCING OLD TABLE AS changed_memberships
FOR EACH STATEMENT EXECUTE FUNCTION filebelt_security.invalidate_membership_creator_fanout();
CREATE TRIGGER membership_capability_projection_update
AFTER UPDATE ON public.group_memberships
REFERENCING OLD TABLE AS old_memberships NEW TABLE AS changed_memberships
FOR EACH STATEMENT EXECUTE FUNCTION filebelt_security.invalidate_updated_membership_creator_fanout();
CREATE TRIGGER user_capability_projection_update
AFTER UPDATE ON public.users
REFERENCING OLD TABLE AS old_users NEW TABLE AS changed_users
FOR EACH STATEMENT EXECUTE FUNCTION filebelt_security.invalidate_user_status_creator_fanout();
CREATE TRIGGER principal_capability_projection_update
AFTER UPDATE ON public.principals
REFERENCING OLD TABLE AS old_principals NEW TABLE AS changed_principals
FOR EACH STATEMENT EXECUTE FUNCTION filebelt_security.invalidate_principal_disable_creator_fanout();

REVOKE ALL ON FUNCTION filebelt_security.seed_tenant_descendant_share_admission() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_security.descendant_share_admission_open(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_security.require_descendant_share_admission_open(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_security.direct_share_insert_backstop() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_security.data_grant_insert_backstop() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_security.protobuf_varint(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_security.protobuf_bytes_field(integer,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_security.encode_event_envelope(uuid,uuid,text,uuid,bigint,text,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_security.assert_live_tenant_admin(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_security.descendant_shares_remaining(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_security.descendant_shares_status(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_security.repair_descendant_shares(uuid,uuid,text,uuid,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_security.verify_descendant_shares(uuid,uuid,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_security.activate_descendant_shares(uuid,uuid,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_security.invalidate_membership_creator_fanout() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_security.invalidate_updated_membership_creator_fanout() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_security.invalidate_user_status_creator_fanout() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_security.invalidate_principal_disable_creator_fanout() FROM PUBLIC;
