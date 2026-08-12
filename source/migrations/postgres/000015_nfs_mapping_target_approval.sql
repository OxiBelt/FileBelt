-- SPDX-License-Identifier: Apache-2.0

-- A Kerberos principal is an external content-bearing identity. Tenant
-- administrators may propose its projection, but PostgreSQL admits the
-- mapping only after the exact target FileBelt user approves it with a fresh
-- API session. Existing mappings are quarantined instead of being silently
-- grandfathered into this stronger authority boundary.

CREATE FUNCTION filebelt_mount.sorted_unique_uuids(p_values uuid[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path=pg_catalog
AS $$
  SELECT p_values=ARRAY(
    SELECT DISTINCT value FROM unnest(p_values) AS value ORDER BY value
  )
$$;

CREATE TABLE filebelt_mount.nfs_mapping_proposals (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  proposer_principal_id uuid NOT NULL,
  proposer_api_session_id uuid NOT NULL,
  target_principal_id uuid NOT NULL,
  kerberos_principal text NOT NULL
    CHECK (length(kerberos_principal) BETWEEN 1 AND 512)
    CHECK (kerberos_principal ~ '^[^/@[:space:]]+@[^/@[:space:]]+$')
    CHECK (position(E'\\' in kerberos_principal)=0)
    CHECK (lower(split_part(kerberos_principal,'@',1))<>'root'),
  posix_name text NOT NULL
    CHECK (posix_name ~ '^[a-z_][a-z0-9_.-]{0,254}$'),
  posix_group_id uuid NOT NULL,
  projected_uid bigint NOT NULL CHECK (
    projected_uid BETWEEN 1 AND 4294967294 AND projected_uid<>65534
  ),
  projected_gid bigint NOT NULL CHECK (
    projected_gid BETWEEN 1 AND 4294967294 AND projected_gid<>65534
  ),
  allowed_drive_ids uuid[] NOT NULL,
  expected_credential_id uuid,
  expected_mapping_generation bigint CHECK (expected_mapping_generation>0),
  server_fingerprint bytea NOT NULL CHECK (octet_length(server_fingerprint)=32),
  state text NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending','approved','declined','cancelled','expired')),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation>0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  approver_principal_id uuid,
  approver_api_session_id uuid,
  approved_at timestamptz,
  terminal_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,proposer_principal_id)
    REFERENCES public.principals(tenant_id,id),
  FOREIGN KEY (tenant_id,proposer_api_session_id)
    REFERENCES public.api_sessions(tenant_id,id),
  FOREIGN KEY (tenant_id,target_principal_id)
    REFERENCES public.principals(tenant_id,id),
  FOREIGN KEY (tenant_id,posix_group_id,projected_gid)
    REFERENCES filebelt_mount.nfs_posix_groups(tenant_id,group_id,projected_gid),
  FOREIGN KEY (tenant_id,expected_credential_id)
    REFERENCES filebelt_mount.credentials(tenant_id,id),
  FOREIGN KEY (tenant_id,approver_principal_id)
    REFERENCES public.principals(tenant_id,id),
  FOREIGN KEY (tenant_id,approver_api_session_id)
    REFERENCES public.api_sessions(tenant_id,id),
  CHECK (cardinality(allowed_drive_ids) BETWEEN 1 AND 256),
  CHECK (filebelt_mount.sorted_unique_uuids(allowed_drive_ids)),
  CHECK ((expected_credential_id IS NULL)=(expected_mapping_generation IS NULL)),
  CHECK (expires_at=created_at+interval '24 hours'),
  CHECK (
    (state='pending' AND generation=1
      AND approver_principal_id IS NULL AND approver_api_session_id IS NULL
      AND approved_at IS NULL AND terminal_at IS NULL)
    OR
    (state='approved' AND generation=2
      AND approver_principal_id=target_principal_id
      AND approver_api_session_id IS NOT NULL
      AND approved_at IS NOT NULL AND terminal_at=approved_at
      AND approved_at>=created_at AND approved_at<=expires_at)
    OR
    (state='declined' AND generation=2
      AND approver_principal_id=target_principal_id
      AND approver_api_session_id IS NOT NULL
      AND approved_at IS NULL AND terminal_at IS NOT NULL
      AND terminal_at>=created_at)
    OR
    (state IN ('cancelled','expired') AND generation=2
      AND approver_principal_id IS NULL AND approver_api_session_id IS NULL
      AND approved_at IS NULL AND terminal_at IS NOT NULL
      AND terminal_at>=created_at)
  )
);
CREATE UNIQUE INDEX nfs_mapping_one_pending_principal
  ON filebelt_mount.nfs_mapping_proposals (tenant_id,kerberos_principal)
  WHERE state='pending';
CREATE INDEX nfs_mapping_proposals_target_index
  ON filebelt_mount.nfs_mapping_proposals (
    tenant_id,target_principal_id,state,expires_at,id
  );
CREATE INDEX nfs_mapping_proposals_unapproved_retention_index
  ON filebelt_mount.nfs_mapping_proposals (terminal_at,id)
  WHERE state IN ('declined','cancelled','expired');

CREATE FUNCTION filebelt_mount.enforce_nfs_mapping_proposal()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,filebelt_mount
AS $$
BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.state<>'pending' THEN
      RAISE EXCEPTION USING ERRCODE='23514',
        MESSAGE='new NFS mapping proposals must be pending';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP='DELETE' THEN
    IF OLD.state='approved'
       OR OLD.state='pending'
       OR OLD.terminal_at>clock_timestamp()-interval '30 days' THEN
      RAISE EXCEPTION USING ERRCODE='55000',
        MESSAGE='NFS mapping proposal retention has not elapsed';
    END IF;
    RETURN OLD;
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.proposer_principal_id IS DISTINCT FROM OLD.proposer_principal_id
     OR NEW.proposer_api_session_id IS DISTINCT FROM OLD.proposer_api_session_id
     OR NEW.target_principal_id IS DISTINCT FROM OLD.target_principal_id
     OR NEW.kerberos_principal IS DISTINCT FROM OLD.kerberos_principal
     OR NEW.posix_name IS DISTINCT FROM OLD.posix_name
     OR NEW.posix_group_id IS DISTINCT FROM OLD.posix_group_id
     OR NEW.projected_uid IS DISTINCT FROM OLD.projected_uid
     OR NEW.projected_gid IS DISTINCT FROM OLD.projected_gid
     OR NEW.allowed_drive_ids IS DISTINCT FROM OLD.allowed_drive_ids
     OR NEW.expected_credential_id IS DISTINCT FROM OLD.expected_credential_id
     OR NEW.expected_mapping_generation IS DISTINCT FROM OLD.expected_mapping_generation
     OR NEW.server_fingerprint IS DISTINCT FROM OLD.server_fingerprint
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR OLD.state<>'pending' OR NEW.state='pending'
     OR NEW.generation<>OLD.generation+1 THEN
    RAISE EXCEPTION USING ERRCODE='55000',
      MESSAGE='NFS mapping proposal request fields and terminal states are immutable';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER nfs_mapping_proposal_immutable
BEFORE INSERT OR UPDATE OR DELETE
ON filebelt_mount.nfs_mapping_proposals
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.enforce_nfs_mapping_proposal();

ALTER TABLE filebelt_mount.nfs_principal_mappings
  ADD COLUMN approved_proposal_id uuid,
  ADD COLUMN revocation_reason text;

-- Close the complete legacy authority set before installing the approval
-- constraint. Registry rows and the mapping identities themselves are kept.
UPDATE filebelt_mount.sessions
SET state='closed',
    closed_at=COALESCE(closed_at,clock_timestamp()),
    close_reason='nfs_mapping_approval_required',
    last_activity_at=clock_timestamp()
WHERE protocol='nfs' AND state IN ('active','draining');

UPDATE filebelt_mount.credentials AS credential
SET revoked_at=COALESCE(credential.revoked_at,clock_timestamp()),
    credential_generation=credential.credential_generation+1,
    authorization_generation=credential.authorization_generation+1
FROM filebelt_mount.nfs_principal_mappings AS mapping
WHERE credential.tenant_id=mapping.tenant_id
  AND credential.id=mapping.credential_id
  AND mapping.revoked_at IS NULL;

UPDATE filebelt_mount.nfs_principal_mappings
SET revoked_at=COALESCE(revoked_at,clock_timestamp()),
    revocation_reason=CASE
      WHEN revoked_at IS NULL THEN 'target_approval_cutover'
      ELSE 'legacy_revocation'
    END,
    generation=CASE WHEN revoked_at IS NULL THEN generation+1 ELSE generation END,
    updated_at=CASE WHEN revoked_at IS NULL THEN clock_timestamp() ELSE updated_at END;

UPDATE filebelt_mount.policies AS policy
SET enabled=false,
    allowed_drive_ids='{}'::uuid[],
    authorization_generation=policy.authorization_generation+1,
    revision=policy.revision+1,
    updated_at=clock_timestamp()
WHERE policy.protocol='nfs'
  AND EXISTS (
    SELECT 1
    FROM filebelt_mount.nfs_principal_mappings AS mapping
    WHERE mapping.tenant_id=policy.tenant_id
      AND mapping.principal_id=policy.principal_id
      AND mapping.revocation_reason='target_approval_cutover'
  );

INSERT INTO public.audit_events (
  tenant_id,id,target_principal_id,resource_id,action,outcome,reason_code,
  privacy_visible,details
)
SELECT mapping.tenant_id,gen_random_uuid(),mapping.principal_id,
       mapping.credential_id,'mount.nfs.mapping.quarantine','allowed',
       'target_approval_cutover',true,
       jsonb_build_object(
         'kerberos_principal',mapping.kerberos_principal,
         'mapping_generation',mapping.generation,
         'credential_id',mapping.credential_id
       )
FROM filebelt_mount.nfs_principal_mappings AS mapping
WHERE mapping.revocation_reason='target_approval_cutover';

WITH events AS (
  SELECT mapping.tenant_id,gen_random_uuid() AS id,mapping.credential_id,
         mapping.generation,extract(epoch FROM clock_timestamp())::bigint AS occurred_at
  FROM filebelt_mount.nfs_principal_mappings AS mapping
  WHERE mapping.revocation_reason='target_approval_cutover'
)
INSERT INTO public.outbox_events (
  tenant_id,id,topic,aggregate_type,aggregate_id,aggregate_generation,
  partition_key,payload
)
SELECT tenant_id,id,'filebelt.v1.mount.nfs.mapping.changed','nfs_mapping',
       credential_id,generation,tenant_id::text || ':' || credential_id::text,
       filebelt_security.encode_event_envelope(
         id,tenant_id,'nfs_mapping',credential_id,generation,
         'filebelt.v1.mount.nfs.mapping.changed',occurred_at
       )
FROM events;

ALTER TABLE filebelt_mount.nfs_principal_mappings
  ADD CONSTRAINT nfs_mapping_approved_proposal_fk
    FOREIGN KEY (tenant_id,approved_proposal_id)
    REFERENCES filebelt_mount.nfs_mapping_proposals(tenant_id,id),
  ADD CONSTRAINT nfs_mapping_approval_state_check CHECK (
    (revoked_at IS NULL
      AND approved_proposal_id IS NOT NULL
      AND revocation_reason IS NULL)
    OR
    (revoked_at IS NOT NULL
      AND revocation_reason IS NOT NULL
      AND length(revocation_reason) BETWEEN 1 AND 64)
  );
CREATE UNIQUE INDEX nfs_mapping_approved_proposal_unique
  ON filebelt_mount.nfs_principal_mappings (tenant_id,approved_proposal_id)
  WHERE approved_proposal_id IS NOT NULL;

-- Extend the existing immutable POSIX identity trigger with the consent
-- receipt and exact-request checks. A revoked mapping may consume a new
-- approval only while it is being reactivated.
CREATE OR REPLACE FUNCTION filebelt_mount.enforce_nfs_mapping_projection()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
DECLARE
  v_identity record;
  v_proposal filebelt_mount.nfs_mapping_proposals%ROWTYPE;
  v_credential record;
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION USING ERRCODE='55000',
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
    OR (
      NEW.approved_proposal_id IS DISTINCT FROM OLD.approved_proposal_id
      AND NOT (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL)
    )
  ) THEN
    RAISE EXCEPTION USING ERRCODE='55000',
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
      RAISE EXCEPTION USING ERRCODE='23505',
        MESSAGE='NFS Kerberos aliases must share one immutable POSIX identity';
    END IF;
  ELSIF NEW.revoked_at IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='23514',
      MESSAGE='active NFS mapping requires a complete POSIX identity';
  END IF;
  IF NEW.revoked_at IS NULL THEN
    SELECT * INTO v_proposal
    FROM filebelt_mount.nfs_mapping_proposals AS proposal
    WHERE proposal.tenant_id=NEW.tenant_id
      AND proposal.id=NEW.approved_proposal_id
      AND proposal.state='approved'
      AND proposal.target_principal_id=NEW.principal_id
      AND proposal.kerberos_principal=NEW.kerberos_principal
      AND proposal.posix_name=NEW.posix_name
      AND proposal.posix_group_id=NEW.posix_group_id
      AND proposal.projected_uid=NEW.projected_uid
      AND proposal.projected_gid=NEW.projected_gid
    FOR KEY SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='23514',
        MESSAGE='active NFS mapping requires exact target approval';
    END IF;
    IF TG_OP='INSERT' THEN
      IF v_proposal.expected_credential_id IS NOT NULL
         OR v_proposal.expected_mapping_generation IS NOT NULL
         OR NEW.generation<>1 THEN
        RAISE EXCEPTION USING ERRCODE='40001',
          MESSAGE='NFS mapping proposal creation precondition is stale';
      END IF;
    ELSIF v_proposal.expected_credential_id IS DISTINCT FROM OLD.credential_id
       OR v_proposal.expected_mapping_generation IS DISTINCT FROM OLD.generation
       OR NEW.generation<>OLD.generation+1 THEN
      RAISE EXCEPTION USING ERRCODE='40001',
        MESSAGE='NFS mapping proposal reactivation precondition is stale';
    END IF;
    SELECT credential.principal_id,credential.protocol,
           credential.verifier_kind,credential.allowed_drive_ids
    INTO v_credential
    FROM filebelt_mount.credentials AS credential
    WHERE credential.tenant_id=NEW.tenant_id AND credential.id=NEW.credential_id
    FOR KEY SHARE;
    IF NOT FOUND
       OR v_credential.principal_id IS DISTINCT FROM NEW.principal_id
       OR v_credential.protocol<>'nfs'
       OR v_credential.verifier_kind<>'kerberos_principal'
       OR cardinality(v_credential.allowed_drive_ids)=0
       OR NOT filebelt_mount.sorted_unique_uuids(v_credential.allowed_drive_ids)
       OR NOT v_credential.allowed_drive_ids<@v_proposal.allowed_drive_ids THEN
      RAISE EXCEPTION USING ERRCODE='23514',
        MESSAGE='NFS credential exceeds its approved mapping scope';
    END IF;
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
      RAISE EXCEPTION USING ERRCODE='23503',
        MESSAGE='active NFS mapping requires a registered primary-group membership';
    END IF;
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION filebelt_mount.enforce_nfs_credential_approval_ceiling()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_mapping record;
BEGIN
  IF NEW.protocol<>'nfs' AND NOT EXISTS (
    SELECT 1 FROM filebelt_mount.nfs_principal_mappings AS mapping
    WHERE mapping.tenant_id=NEW.tenant_id AND mapping.credential_id=NEW.id
  ) THEN
    RETURN NEW;
  END IF;
  SELECT mapping.principal_id,mapping.revoked_at,proposal.allowed_drive_ids
  INTO v_mapping
  FROM filebelt_mount.nfs_principal_mappings AS mapping
  LEFT JOIN filebelt_mount.nfs_mapping_proposals AS proposal
    ON proposal.tenant_id=mapping.tenant_id
   AND proposal.id=mapping.approved_proposal_id
   AND proposal.state='approved'
  WHERE mapping.tenant_id=NEW.tenant_id AND mapping.credential_id=NEW.id
  FOR KEY SHARE OF mapping;
  IF FOUND THEN
    IF NEW.protocol<>'nfs' OR NEW.verifier_kind<>'kerberos_principal'
       OR NEW.principal_id IS DISTINCT FROM v_mapping.principal_id
       OR (NEW.revoked_at IS NULL AND (
         v_mapping.revoked_at IS NOT NULL
         OR cardinality(NEW.allowed_drive_ids)=0
         OR NOT filebelt_mount.sorted_unique_uuids(NEW.allowed_drive_ids)
         OR v_mapping.allowed_drive_ids IS NULL
         OR NOT NEW.allowed_drive_ids<@v_mapping.allowed_drive_ids
       )) THEN
      RAISE EXCEPTION USING ERRCODE='23514',
        MESSAGE='active NFS credential requires an approved mapping scope';
    END IF;
  ELSIF NEW.protocol='nfs' AND NEW.revoked_at IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='23514',
      MESSAGE='new NFS credential must remain revoked until its mapping is approved';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER nfs_credential_approval_ceiling
BEFORE INSERT OR UPDATE ON filebelt_mount.credentials
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.enforce_nfs_credential_approval_ceiling();

CREATE VIEW filebelt_mount.nfs_approved_active_mappings
WITH (security_barrier=true)
AS
SELECT mapping.tenant_id,mapping.kerberos_principal,mapping.principal_id,
       mapping.credential_id,mapping.posix_name,mapping.posix_group_id,
       mapping.projected_uid,mapping.projected_gid,mapping.generation,
       mapping.approved_proposal_id,proposal.server_fingerprint,
       proposal.allowed_drive_ids AS approved_drive_ids,
       credential.allowed_drive_ids,credential.credential_generation,
       credential.authorization_generation
FROM filebelt_mount.nfs_principal_mappings AS mapping
JOIN filebelt_mount.nfs_mapping_proposals AS proposal
  ON proposal.tenant_id=mapping.tenant_id
 AND proposal.id=mapping.approved_proposal_id
 AND proposal.state='approved'
JOIN filebelt_mount.credentials AS credential
  ON credential.tenant_id=mapping.tenant_id
 AND credential.id=mapping.credential_id
 AND credential.principal_id=mapping.principal_id
 AND credential.protocol='nfs'
 AND credential.verifier_kind='kerberos_principal'
 AND credential.revoked_at IS NULL
WHERE mapping.revoked_at IS NULL
  AND credential.allowed_drive_ids<@proposal.allowed_drive_ids;

-- Session rows can also be written by the privileged VFS role. Keep that raw
-- path fail closed even if a caller bypasses create_nfs_session: every live
-- NFS session must bind the exact generation of an approved active mapping.
CREATE FUNCTION filebelt_mount.enforce_nfs_session_mapping_approval()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
BEGIN
  IF NEW.protocol='nfs' AND NEW.state IN ('active','draining') AND NOT EXISTS (
    SELECT 1
    FROM filebelt_mount.nfs_approved_active_mappings AS mapping
    WHERE mapping.tenant_id=NEW.tenant_id
      AND mapping.credential_id=NEW.credential_id
      AND mapping.principal_id=NEW.user_principal_id
      AND mapping.generation=NEW.nfs_mapping_generation
  ) THEN
    RAISE EXCEPTION USING ERRCODE='23514',
      MESSAGE='live NFS session requires an approved active mapping';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER nfs_session_mapping_approval
BEFORE INSERT OR UPDATE ON filebelt_mount.sessions
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.enforce_nfs_session_mapping_approval();

-- The ACL predicate intentionally mirrors the existing NFS administrator
-- drive snapshot. PostgreSQL rechecks both proposer and target at approval.
CREATE FUNCTION filebelt_mount.nfs_principal_has_read_metadata(
  p_tenant_id uuid,p_principal_id uuid,p_drive_ids uuid[]
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount
AS $$
  SELECT cardinality(p_drive_ids) BETWEEN 1 AND 256
    AND filebelt_mount.sorted_unique_uuids(p_drive_ids)
    AND EXISTS (
      SELECT 1 FROM public.principals
      WHERE tenant_id=p_tenant_id AND id=p_principal_id
        AND kind='user' AND disabled_at IS NULL
    )
    AND (
      SELECT count(*)=cardinality(p_drive_ids)
      FROM public.drives AS drive
      WHERE drive.tenant_id=p_tenant_id AND drive.id=ANY(p_drive_ids)
        AND (
          drive.owner_principal_id=p_principal_id
          OR drive.owner_principal_id IN (
            SELECT groups.principal_id
            FROM public.group_memberships AS membership
            JOIN public.groups AS groups
              ON groups.tenant_id=membership.tenant_id
             AND groups.id=membership.group_id
            WHERE membership.tenant_id=p_tenant_id
              AND membership.user_principal_id=p_principal_id
          )
          OR EXISTS (
            SELECT 1 FROM public.acl_entries AS acl
            WHERE acl.tenant_id=drive.tenant_id AND acl.drive_id=drive.id
              AND acl.effect='allow' AND acl.action='READ_METADATA'
              AND (
                acl.principal_id=p_principal_id
                OR acl.principal_id IN (
                  SELECT groups.principal_id
                  FROM public.group_memberships AS membership
                  JOIN public.groups AS groups
                    ON groups.tenant_id=membership.tenant_id
                   AND groups.id=membership.group_id
                  WHERE membership.tenant_id=p_tenant_id
                    AND membership.user_principal_id=p_principal_id
                )
              )
          )
        )
    )
$$;

CREATE FUNCTION filebelt_mount.create_nfs_mapping_proposal(
  p_tenant_id uuid,p_proposal_id uuid,p_proposer_principal_id uuid,
  p_proposer_api_session_id uuid,p_target_principal_id uuid,
  p_kerberos_principal text,p_posix_name text,p_posix_group_id uuid,
  p_projected_uid bigint,p_projected_gid bigint,p_allowed_drive_ids uuid[],
  p_expected_credential_id uuid,p_expected_mapping_generation bigint,
  p_server_fingerprint bytea
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount,filebelt_security
AS $$
DECLARE
  v_now timestamptz := clock_timestamp();
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_api','MEMBER') THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='caller is not the FileBelt API database principal';
  END IF;
  PERFORM filebelt_security.assert_live_tenant_admin(
    p_tenant_id,p_proposer_principal_id
  );
  PERFORM 1 FROM public.api_sessions AS session
  WHERE session.tenant_id=p_tenant_id
    AND session.id=p_proposer_api_session_id
    AND session.principal_id=p_proposer_principal_id
    AND session.revoked_at IS NULL
    AND session.idle_expires_at>v_now AND session.absolute_expires_at>v_now
    AND session.reauthenticated_at>v_now-interval '10 minutes'
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='fresh proposer API session required';
  END IF;
  IF NOT filebelt_mount.nfs_principal_has_read_metadata(
       p_tenant_id,p_proposer_principal_id,p_allowed_drive_ids
     )
     OR NOT filebelt_mount.nfs_principal_has_read_metadata(
       p_tenant_id,p_target_principal_id,p_allowed_drive_ids
     ) THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='NFS proposal principals require READ_METADATA on every drive';
  END IF;
  PERFORM 1
  FROM public.users AS target
  JOIN public.principals AS principal
    ON principal.tenant_id=target.tenant_id AND principal.id=target.principal_id
  JOIN public.group_memberships AS membership
    ON membership.tenant_id=target.tenant_id
   AND membership.user_principal_id=target.principal_id
  JOIN filebelt_mount.nfs_posix_groups AS posix_group
    ON posix_group.tenant_id=membership.tenant_id
   AND posix_group.group_id=membership.group_id
  WHERE target.tenant_id=p_tenant_id
    AND target.principal_id=p_target_principal_id
    AND target.status='active' AND principal.disabled_at IS NULL
    AND posix_group.group_id=p_posix_group_id
    AND posix_group.projected_gid=p_projected_gid
  FOR SHARE OF target,principal,membership,posix_group;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='23503',
      MESSAGE='NFS proposal target requires an active registered POSIX identity';
  END IF;
  IF EXISTS (
    SELECT 1 FROM filebelt_mount.nfs_posix_users AS identity
    WHERE identity.tenant_id=p_tenant_id
      AND identity.principal_id=p_target_principal_id
      AND (
        identity.posix_name IS DISTINCT FROM p_posix_name
        OR identity.posix_group_id IS DISTINCT FROM p_posix_group_id
        OR identity.projected_uid IS DISTINCT FROM p_projected_uid
        OR identity.projected_gid IS DISTINCT FROM p_projected_gid
      )
  ) THEN
    RAISE EXCEPTION USING ERRCODE='23505',
      MESSAGE='NFS proposal conflicts with the immutable POSIX user registry';
  END IF;
  IF (p_expected_credential_id IS NULL)
       IS DISTINCT FROM (p_expected_mapping_generation IS NULL) THEN
    RAISE EXCEPTION USING ERRCODE='23514',
      MESSAGE='NFS proposal mapping preconditions must be paired';
  END IF;
  IF p_expected_credential_id IS NULL THEN
    IF EXISTS (
      SELECT 1 FROM filebelt_mount.nfs_principal_mappings AS mapping
      WHERE mapping.tenant_id=p_tenant_id
        AND mapping.kerberos_principal=p_kerberos_principal
    ) THEN
      RAISE EXCEPTION USING ERRCODE='40001',
        MESSAGE='NFS mapping proposal creation precondition is stale';
    END IF;
  ELSE
    PERFORM 1 FROM filebelt_mount.nfs_principal_mappings AS mapping
    WHERE mapping.tenant_id=p_tenant_id
      AND mapping.kerberos_principal=p_kerberos_principal
      AND mapping.principal_id=p_target_principal_id
      AND mapping.credential_id=p_expected_credential_id
      AND mapping.generation=p_expected_mapping_generation
      AND mapping.posix_name=p_posix_name
      AND mapping.posix_group_id=p_posix_group_id
      AND mapping.projected_uid=p_projected_uid
      AND mapping.projected_gid=p_projected_gid
    FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='40001',
        MESSAGE='NFS mapping proposal update precondition is stale';
    END IF;
  END IF;
  UPDATE filebelt_mount.nfs_mapping_proposals
  SET state='expired',generation=2,terminal_at=v_now
  WHERE tenant_id=p_tenant_id AND kerberos_principal=p_kerberos_principal
    AND state='pending' AND expires_at<=v_now;
  INSERT INTO filebelt_mount.nfs_mapping_proposals (
    tenant_id,id,proposer_principal_id,proposer_api_session_id,
    target_principal_id,kerberos_principal,posix_name,posix_group_id,
    projected_uid,projected_gid,allowed_drive_ids,expected_credential_id,
    expected_mapping_generation,server_fingerprint,created_at,expires_at
  ) VALUES (
    p_tenant_id,p_proposal_id,p_proposer_principal_id,p_proposer_api_session_id,
    p_target_principal_id,p_kerberos_principal,p_posix_name,p_posix_group_id,
    p_projected_uid,p_projected_gid,p_allowed_drive_ids,p_expected_credential_id,
    p_expected_mapping_generation,p_server_fingerprint,v_now,v_now+interval '24 hours'
  );
  RETURN 1;
END
$$;

CREATE FUNCTION filebelt_mount.approve_nfs_mapping_proposal(
  p_tenant_id uuid,p_proposal_id uuid,p_approver_principal_id uuid,
  p_approver_api_session_id uuid,p_expected_generation bigint
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount,filebelt_security
AS $$
DECLARE
  v_now timestamptz := clock_timestamp();
  v_proposal filebelt_mount.nfs_mapping_proposals%ROWTYPE;
  v_generation bigint;
  v_locked_count integer;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_api','MEMBER') THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='caller is not the FileBelt API database principal';
  END IF;
  SELECT * INTO v_proposal
  FROM filebelt_mount.nfs_mapping_proposals AS proposal
  WHERE proposal.tenant_id=p_tenant_id AND proposal.id=p_proposal_id
    AND proposal.state='pending' AND proposal.generation=p_expected_generation
  FOR UPDATE;
  IF NOT FOUND OR v_proposal.expires_at<=v_now
     OR v_proposal.target_principal_id<>p_approver_principal_id THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='NFS mapping proposal is stale or belongs to another target';
  END IF;
  -- Serialize every mutable predicate before evaluating it. Membership and
  -- ACL triggers fence their principal/drive generation rows; NOWAIT turns an
  -- in-flight revocation into a retryable stale approval instead of allowing
  -- authority observed before that revocation to be activated afterward.
  PERFORM 1
  FROM public.group_memberships AS membership
  JOIN filebelt_mount.nfs_posix_groups AS posix_group
    ON posix_group.tenant_id=membership.tenant_id
   AND posix_group.group_id=membership.group_id
  WHERE membership.tenant_id=p_tenant_id
    AND membership.user_principal_id=p_approver_principal_id
    AND posix_group.group_id=v_proposal.posix_group_id
    AND posix_group.projected_gid=v_proposal.projected_gid
  FOR SHARE OF membership,posix_group NOWAIT;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='23503',
      MESSAGE='NFS approval target lost its registered primary group';
  END IF;
  PERFORM 1 FROM public.principals
  WHERE tenant_id=p_tenant_id
    AND id IN (v_proposal.proposer_principal_id,p_approver_principal_id)
    AND disabled_at IS NULL
  ORDER BY id FOR SHARE NOWAIT;
  GET DIAGNOSTICS v_locked_count = ROW_COUNT;
  IF v_locked_count<>(
    SELECT count(DISTINCT principal_id)::integer
    FROM unnest(ARRAY[
      v_proposal.proposer_principal_id,p_approver_principal_id
    ]) AS principal_id
  ) THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='NFS approval principal is no longer active';
  END IF;
  PERFORM 1 FROM public.drives
  WHERE tenant_id=p_tenant_id AND id=ANY(v_proposal.allowed_drive_ids)
  ORDER BY id FOR SHARE NOWAIT;
  GET DIAGNOSTICS v_locked_count = ROW_COUNT;
  IF v_locked_count<>cardinality(v_proposal.allowed_drive_ids) THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='NFS approval drive no longer exists';
  END IF;
  PERFORM 1
  FROM public.users AS admin_user
  JOIN public.external_identities AS identity
    ON identity.tenant_id=admin_user.tenant_id
   AND identity.user_id=admin_user.id AND identity.disabled_at IS NULL
  JOIN public.tenant_admin_bindings AS binding
    ON binding.tenant_id=identity.tenant_id
   AND binding.issuer=identity.issuer AND binding.subject=identity.subject
  WHERE admin_user.tenant_id=p_tenant_id
    AND admin_user.principal_id=v_proposal.proposer_principal_id
    AND admin_user.status='active'
  FOR SHARE OF admin_user,identity,binding NOWAIT;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='live tenant administrator required';
  END IF;
  PERFORM 1 FROM public.api_sessions AS session
  JOIN public.users AS target
    ON target.tenant_id=session.tenant_id AND target.id=session.user_id
  JOIN public.principals AS principal
    ON principal.tenant_id=session.tenant_id AND principal.id=session.principal_id
  WHERE session.tenant_id=p_tenant_id
    AND session.id=p_approver_api_session_id
    AND session.principal_id=p_approver_principal_id
    AND session.revoked_at IS NULL
    AND session.idle_expires_at>v_now AND session.absolute_expires_at>v_now
    AND session.reauthenticated_at>v_now-interval '10 minutes'
    AND target.status='active' AND principal.disabled_at IS NULL
  FOR SHARE OF session,target NOWAIT;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='fresh target API session required';
  END IF;
  IF NOT filebelt_mount.nfs_principal_has_read_metadata(
       p_tenant_id,v_proposal.proposer_principal_id,v_proposal.allowed_drive_ids
     )
     OR NOT filebelt_mount.nfs_principal_has_read_metadata(
       p_tenant_id,p_approver_principal_id,v_proposal.allowed_drive_ids
     ) THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='NFS approval principals require READ_METADATA on every drive';
  END IF;
  IF v_proposal.expected_credential_id IS NULL THEN
    IF EXISTS (
      SELECT 1 FROM filebelt_mount.nfs_principal_mappings AS mapping
      WHERE mapping.tenant_id=p_tenant_id
        AND mapping.kerberos_principal=v_proposal.kerberos_principal
    ) THEN
      RAISE EXCEPTION USING ERRCODE='40001',
        MESSAGE='NFS mapping proposal creation precondition is stale';
    END IF;
  ELSE
    PERFORM 1 FROM filebelt_mount.nfs_principal_mappings AS mapping
    WHERE mapping.tenant_id=p_tenant_id
      AND mapping.kerberos_principal=v_proposal.kerberos_principal
      AND mapping.principal_id=v_proposal.target_principal_id
      AND mapping.credential_id=v_proposal.expected_credential_id
      AND mapping.generation=v_proposal.expected_mapping_generation
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='40001',
        MESSAGE='NFS mapping proposal update precondition is stale';
    END IF;
  END IF;
  UPDATE filebelt_mount.nfs_mapping_proposals
  SET state='approved',generation=generation+1,
      approver_principal_id=p_approver_principal_id,
      approver_api_session_id=p_approver_api_session_id,
      approved_at=v_now,terminal_at=v_now
  WHERE tenant_id=p_tenant_id AND id=p_proposal_id
  RETURNING generation INTO v_generation;
  INSERT INTO public.audit_events (
    tenant_id,id,actor_principal_id,target_principal_id,resource_id,
    action,outcome,reason_code,privacy_visible,details
  ) VALUES (
    p_tenant_id,gen_random_uuid(),p_approver_principal_id,
    p_approver_principal_id,p_proposal_id,'mount.nfs.mapping_proposal.approve',
    'allowed','target_user_approval',true,
    jsonb_build_object(
      'kerberos_principal',v_proposal.kerberos_principal,
      'proposal_generation',v_generation
    )
  );
  RETURN v_generation;
END
$$;

CREATE FUNCTION filebelt_mount.transition_nfs_mapping_proposal(
  p_tenant_id uuid,p_proposal_id uuid,p_actor_principal_id uuid,
  p_actor_api_session_id uuid,p_expected_generation bigint,p_new_state text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_mount,filebelt_security
AS $$
DECLARE
  v_now timestamptz := clock_timestamp();
  v_proposal filebelt_mount.nfs_mapping_proposals%ROWTYPE;
  v_generation bigint;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_api','MEMBER')
     OR p_new_state NOT IN ('declined','cancelled') THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='invalid NFS proposal transition caller';
  END IF;
  SELECT * INTO v_proposal
  FROM filebelt_mount.nfs_mapping_proposals AS proposal
  WHERE proposal.tenant_id=p_tenant_id AND proposal.id=p_proposal_id
    AND proposal.state='pending' AND proposal.generation=p_expected_generation
  FOR UPDATE;
  IF NOT FOUND OR (
       p_new_state='declined'
       AND v_proposal.target_principal_id<>p_actor_principal_id
     ) THEN
    RAISE EXCEPTION USING ERRCODE='40001',
      MESSAGE='NFS mapping proposal transition is stale or unauthorized';
  END IF;
  PERFORM 1 FROM public.api_sessions AS session
  WHERE session.tenant_id=p_tenant_id AND session.id=p_actor_api_session_id
    AND session.principal_id=p_actor_principal_id AND session.revoked_at IS NULL
    AND session.idle_expires_at>v_now AND session.absolute_expires_at>v_now
    AND session.reauthenticated_at>v_now-interval '10 minutes'
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='fresh API session required for NFS proposal transition';
  END IF;
  IF p_new_state='cancelled' THEN
    PERFORM filebelt_security.assert_live_tenant_admin(
      p_tenant_id,p_actor_principal_id
    );
    UPDATE filebelt_mount.nfs_mapping_proposals
    SET state='cancelled',generation=generation+1,terminal_at=v_now
    WHERE tenant_id=p_tenant_id AND id=p_proposal_id
    RETURNING generation INTO v_generation;
  ELSE
    UPDATE filebelt_mount.nfs_mapping_proposals
    SET state='declined',generation=generation+1,
        approver_principal_id=p_actor_principal_id,
        approver_api_session_id=p_actor_api_session_id,terminal_at=v_now
    WHERE tenant_id=p_tenant_id AND id=p_proposal_id
    RETURNING generation INTO v_generation;
  END IF;
  INSERT INTO public.audit_events (
    tenant_id,id,actor_principal_id,target_principal_id,resource_id,
    action,outcome,reason_code,privacy_visible,details
  ) VALUES (
    p_tenant_id,gen_random_uuid(),p_actor_principal_id,
    v_proposal.target_principal_id,p_proposal_id,
    'mount.nfs.mapping_proposal.' || p_new_state,'allowed',
    'mapping_proposal_' || p_new_state,true,
    jsonb_build_object('proposal_generation',v_generation)
  );
  RETURN v_generation;
END
$$;

CREATE FUNCTION filebelt_mount.expire_nfs_mapping_proposals(
  p_tenant_id uuid,p_limit integer
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_changed bigint;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_maintenance','MEMBER')
     OR p_limit NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='invalid NFS mapping proposal expiry caller';
  END IF;
  WITH candidates AS MATERIALIZED (
    SELECT tenant_id,id
    FROM filebelt_mount.nfs_mapping_proposals
    WHERE tenant_id=p_tenant_id AND state='pending'
      AND expires_at<=clock_timestamp()
    ORDER BY expires_at,id FOR UPDATE SKIP LOCKED LIMIT p_limit
  )
  UPDATE filebelt_mount.nfs_mapping_proposals AS proposal
  SET state='expired',generation=proposal.generation+1,
      terminal_at=clock_timestamp()
  FROM candidates
  WHERE proposal.tenant_id=candidates.tenant_id AND proposal.id=candidates.id;
  GET DIAGNOSTICS v_changed=ROW_COUNT;
  RETURN v_changed;
END
$$;

CREATE FUNCTION filebelt_mount.purge_nfs_mapping_proposals(
  p_tenant_id uuid,p_limit integer
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_mount
AS $$
DECLARE
  v_changed bigint;
BEGIN
  IF NOT pg_has_role(session_user,'filebelt_maintenance','MEMBER')
     OR p_limit NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION USING ERRCODE='42501',
      MESSAGE='invalid NFS mapping proposal purge caller';
  END IF;
  WITH candidates AS MATERIALIZED (
    SELECT tenant_id,id
    FROM filebelt_mount.nfs_mapping_proposals
    WHERE tenant_id=p_tenant_id
      AND state IN ('declined','cancelled','expired')
      AND terminal_at<=clock_timestamp()-interval '30 days'
    ORDER BY terminal_at,id FOR UPDATE SKIP LOCKED LIMIT p_limit
  )
  DELETE FROM filebelt_mount.nfs_mapping_proposals AS proposal
  USING candidates
  WHERE proposal.tenant_id=candidates.tenant_id AND proposal.id=candidates.id;
  GET DIAGNOSTICS v_changed=ROW_COUNT;
  RETURN v_changed;
END
$$;

REVOKE ALL ON FUNCTION filebelt_mount.sorted_unique_uuids(uuid[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.enforce_nfs_mapping_proposal() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.enforce_nfs_mapping_projection() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.enforce_nfs_credential_approval_ceiling()
  FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.enforce_nfs_session_mapping_approval()
  FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.nfs_principal_has_read_metadata(uuid,uuid,uuid[])
  FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.create_nfs_mapping_proposal(
  uuid,uuid,uuid,uuid,uuid,text,text,uuid,bigint,bigint,uuid[],uuid,bigint,bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.approve_nfs_mapping_proposal(
  uuid,uuid,uuid,uuid,bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.transition_nfs_mapping_proposal(
  uuid,uuid,uuid,uuid,bigint,text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.expire_nfs_mapping_proposals(uuid,integer)
  FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.purge_nfs_mapping_proposals(uuid,integer)
  FROM PUBLIC;
