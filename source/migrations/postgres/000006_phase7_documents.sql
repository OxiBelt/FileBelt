-- SPDX-License-Identifier: Apache-2.0

-- Provider-neutral document-session state. External-editor adapters retain
-- their own protocol ledger and receive no direct authority over these rows.

ALTER TABLE principals DROP CONSTRAINT principals_kind_check;
ALTER TABLE principals ADD CONSTRAINT principals_kind_check
  CHECK (kind IN ('user','group','service','share_link','mount_session','document_session'));

ALTER TABLE file_versions DROP CONSTRAINT file_versions_origin_kind_check;
ALTER TABLE file_versions ADD CONSTRAINT file_versions_origin_kind_check
  CHECK (origin_kind IN (
    'upload','markdown_save','collaboration_checkpoint','import','restore','external_document'
  ));

REVOKE ALL ON SCHEMA filebelt_document FROM PUBLIC;

CREATE FUNCTION filebelt_document.create_session_principal(p_tenant_id uuid,p_id uuid)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_document
AS $$
  INSERT INTO public.principals (tenant_id,id,kind)
  VALUES (p_tenant_id,p_id,'document_session');
$$;
REVOKE ALL ON FUNCTION filebelt_document.create_session_principal(uuid,uuid) FROM PUBLIC;

CREATE TABLE filebelt_document.sessions (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  session_principal_id uuid NOT NULL,
  drive_id uuid NOT NULL,
  node_id uuid NOT NULL,
  provider_id text NOT NULL CHECK (length(provider_id) BETWEEN 1 AND 64),
  base_version_id uuid NOT NULL,
  expected_head_version_id uuid NOT NULL,
  state text NOT NULL DEFAULT 'active'
    CHECK (state IN ('active','draining','committed','conflict','revoked','expired','failed')),
  fencing_token bigint NOT NULL DEFAULT 1 CHECK (fencing_token > 0),
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_revalidated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  absolute_expires_at timestamptz NOT NULL DEFAULT (clock_timestamp()+interval '24 hours'),
  reconnect_until timestamptz NOT NULL DEFAULT (clock_timestamp()+interval '100 seconds'),
  closed_at timestamptz,
  close_reason text,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,session_principal_id),
  FOREIGN KEY (tenant_id,session_principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,created_by) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,drive_id,node_id) REFERENCES nodes(tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,node_id,base_version_id) REFERENCES file_versions(tenant_id,node_id,id),
  FOREIGN KEY (tenant_id,node_id,expected_head_version_id) REFERENCES file_versions(tenant_id,node_id,id),
  CHECK (absolute_expires_at <= created_at+interval '24 hours'),
  CHECK (reconnect_until <= absolute_expires_at),
  CHECK ((state IN ('active','draining')) = (closed_at IS NULL))
);
CREATE UNIQUE INDEX document_active_lineage_index
  ON filebelt_document.sessions (tenant_id,provider_id,node_id,base_version_id)
  WHERE state IN ('active','draining');
CREATE INDEX document_sessions_owner_index
  ON filebelt_document.sessions (tenant_id,created_by,created_at DESC);
CREATE INDEX document_sessions_expiry_index
  ON filebelt_document.sessions (absolute_expires_at)
  WHERE state IN ('active','draining');

CREATE TABLE filebelt_document.operation_receipts (
  tenant_id uuid NOT NULL,
  operation_digest bytea NOT NULL CHECK (octet_length(operation_digest)=32),
  request_fingerprint bytea NOT NULL CHECK (octet_length(request_fingerprint)=32),
  command_kind text NOT NULL CHECK (command_kind IN ('create_session','conflict_copy')),
  response jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  expires_at timestamptz NOT NULL DEFAULT (statement_timestamp()+interval '24 hours'),
  PRIMARY KEY (tenant_id,operation_digest),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  CHECK (expires_at > created_at AND expires_at <= created_at+interval '24 hours')
);
CREATE INDEX document_operation_receipts_expiry_index
  ON filebelt_document.operation_receipts (expires_at);

CREATE TABLE filebelt_document.participants (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  document_session_id uuid NOT NULL,
  user_principal_id uuid NOT NULL,
  api_session_id uuid NOT NULL,
  mode text NOT NULL CHECK (mode IN ('view','edit','comment','review')),
  state text NOT NULL DEFAULT 'active'
    CHECK (state IN ('active','disconnected','revoked','closed')),
  membership_generation bigint NOT NULL CHECK (membership_generation > 0),
  drive_acl_generation bigint NOT NULL CHECK (drive_acl_generation > 0),
  namespace_generation bigint NOT NULL CHECK (namespace_generation > 0),
  resource_acl_generation bigint NOT NULL CHECK (resource_acl_generation > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_activity_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_revalidated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  disconnected_until timestamptz,
  closed_at timestamptz,
  close_reason text,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,document_session_id,api_session_id,id),
  FOREIGN KEY (tenant_id,document_session_id) REFERENCES filebelt_document.sessions(tenant_id,id),
  FOREIGN KEY (tenant_id,user_principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,api_session_id) REFERENCES api_sessions(tenant_id,id),
  CHECK ((state IN ('active','disconnected')) = (closed_at IS NULL)),
  CHECK (disconnected_until IS NULL OR disconnected_until <= created_at+interval '24 hours')
);
CREATE INDEX document_participants_active_provider_index
  ON filebelt_document.participants (tenant_id,document_session_id,last_activity_at)
  WHERE state IN ('active','disconnected');
CREATE INDEX document_participants_principal_index
  ON filebelt_document.participants (tenant_id,user_principal_id,created_at DESC);

CREATE TABLE filebelt_document.launch_grants (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  participant_id uuid NOT NULL,
  token_digest bytea NOT NULL CHECK (octet_length(token_digest)=32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,token_digest),
  FOREIGN KEY (tenant_id,participant_id) REFERENCES filebelt_document.participants(tenant_id,id),
  CHECK (expires_at > created_at AND expires_at <= created_at+interval '60 seconds')
);
CREATE INDEX document_launch_grants_expiry_index
  ON filebelt_document.launch_grants (tenant_id,expires_at)
  WHERE consumed_at IS NULL;

CREATE TABLE filebelt_document.revisions (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  document_session_id uuid NOT NULL,
  actor_participant_id uuid NOT NULL,
  provider_event_digest bytea NOT NULL CHECK (octet_length(provider_event_digest)=32),
  kind text NOT NULL CHECK (kind IN ('checkpoint','user_save','final_save')),
  state text NOT NULL DEFAULT 'received'
    CHECK (state IN (
      'received','staging','staged','committing','checkpoint','committed',
      'no_op','conflict','rejected','failed'
    )),
  expected_head_version_id uuid NOT NULL,
  payload_id uuid,
  reserved_bytes bigint NOT NULL DEFAULT 0 CHECK (reserved_bytes BETWEEN 0 AND 104857600),
  size_bytes bigint CHECK (size_bytes IS NULL OR size_bytes BETWEEN 0 AND 104857600),
  blake3 bytea CHECK (blake3 IS NULL OR octet_length(blake3)=32),
  media_type text,
  committed_version_id uuid,
  conflict_reason text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  staged_at timestamptz,
  finished_at timestamptz,
  retained_until timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,document_session_id,provider_event_digest),
  FOREIGN KEY (tenant_id,document_session_id) REFERENCES filebelt_document.sessions(tenant_id,id),
  FOREIGN KEY (tenant_id,actor_participant_id) REFERENCES filebelt_document.participants(tenant_id,id),
  FOREIGN KEY (tenant_id,payload_id) REFERENCES payload_objects(tenant_id,id),
  FOREIGN KEY (tenant_id,committed_version_id) REFERENCES file_versions(tenant_id,id),
  CHECK (state NOT IN ('staged','committing','checkpoint','committed','no_op','conflict') OR
    (payload_id IS NOT NULL AND size_bytes IS NOT NULL AND blake3 IS NOT NULL)),
  CHECK (payload_id IS NOT NULL OR (reserved_bytes=0 AND size_bytes IS NULL AND blake3 IS NULL)),
  CHECK ((state='committed') = (committed_version_id IS NOT NULL)),
  CHECK (
    retained_until IS NULL OR
    retained_until <= COALESCE(finished_at,staged_at,created_at)+interval '7 days'
  )
);
CREATE INDEX document_revision_reconcile_index
  ON filebelt_document.revisions (tenant_id,state,created_at)
  WHERE state IN ('staged','committing');
CREATE INDEX document_revision_retention_index
  ON filebelt_document.revisions (retained_until)
  WHERE retained_until IS NOT NULL AND state IN ('checkpoint','conflict','rejected','failed');

CREATE TABLE filebelt_document.revision_contributors (
  tenant_id uuid NOT NULL,
  revision_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  PRIMARY KEY (tenant_id,revision_id,principal_id),
  FOREIGN KEY (tenant_id,revision_id) REFERENCES filebelt_document.revisions(tenant_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id)
);

CREATE TABLE filebelt_document.reconciliation_jobs (
  tenant_id uuid NOT NULL,
  revision_id uuid NOT NULL,
  state text NOT NULL DEFAULT 'queued'
    CHECK (state IN ('queued','running','retry_wait','complete','terminal')),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 8),
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  lease_owner uuid,
  lease_expires_at timestamptz,
  fencing_token bigint NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
  last_error_code text,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,revision_id),
  FOREIGN KEY (tenant_id,revision_id) REFERENCES filebelt_document.revisions(tenant_id,id) ON DELETE CASCADE
);
CREATE INDEX document_reconciliation_claim_index
  ON filebelt_document.reconciliation_jobs (available_at,revision_id)
  WHERE state IN ('queued','retry_wait');

CREATE TABLE filebelt_document.session_events (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  document_session_id uuid NOT NULL,
  participant_id uuid,
  provider_event_digest bytea NOT NULL CHECK (octet_length(provider_event_digest)=32),
  event_kind text NOT NULL CHECK (length(event_kind) BETWEEN 1 AND 64),
  outcome text NOT NULL CHECK (outcome IN ('allowed','denied','conflict','failed')),
  reason_code text NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 96),
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  purge_after timestamptz NOT NULL DEFAULT (clock_timestamp()+interval '30 days'),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,document_session_id,provider_event_digest),
  FOREIGN KEY (tenant_id,document_session_id) REFERENCES filebelt_document.sessions(tenant_id,id),
  FOREIGN KEY (tenant_id,participant_id) REFERENCES filebelt_document.participants(tenant_id,id),
  CHECK (purge_after <= occurred_at+interval '30 days')
);
CREATE INDEX document_session_events_retention_index
  ON filebelt_document.session_events (purge_after);

CREATE TABLE filebelt_document.data_migrations (
  name text PRIMARY KEY CHECK (length(name) BETWEEN 1 AND 96),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  affected_resources bigint NOT NULL CHECK (affected_resources >= 0)
);

-- Generation invalidation is statement-scoped so a preset expansion advances
-- each affected resource once, independent of the number of explicit actions
-- materialized in that statement.
DROP TRIGGER acl_capability_projection ON acl_entries;

CREATE FUNCTION invalidate_inserted_acl_capability_projection() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE drives d SET acl_generation=d.acl_generation+1
    FROM (SELECT DISTINCT tenant_id,drive_id FROM new_acl_rows) changed
    WHERE d.tenant_id=changed.tenant_id AND d.id=changed.drive_id;
  UPDATE nodes n SET acl_generation=n.acl_generation+1
    FROM (SELECT DISTINCT tenant_id,drive_id,resource_id FROM new_acl_rows) changed
    WHERE n.tenant_id=changed.tenant_id AND n.drive_id=changed.drive_id
      AND n.id=changed.resource_id;
  DELETE FROM authorization_generations a USING
    (SELECT DISTINCT tenant_id,drive_id FROM new_acl_rows) changed
    WHERE a.tenant_id=changed.tenant_id AND a.drive_id=changed.drive_id;
  RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION invalidate_inserted_acl_capability_projection() FROM PUBLIC;

CREATE FUNCTION invalidate_deleted_acl_capability_projection() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE drives d SET acl_generation=d.acl_generation+1
    FROM (SELECT DISTINCT tenant_id,drive_id FROM old_acl_rows) changed
    WHERE d.tenant_id=changed.tenant_id AND d.id=changed.drive_id;
  UPDATE nodes n SET acl_generation=n.acl_generation+1
    FROM (SELECT DISTINCT tenant_id,drive_id,resource_id FROM old_acl_rows) changed
    WHERE n.tenant_id=changed.tenant_id AND n.drive_id=changed.drive_id
      AND n.id=changed.resource_id;
  DELETE FROM authorization_generations a USING
    (SELECT DISTINCT tenant_id,drive_id FROM old_acl_rows) changed
    WHERE a.tenant_id=changed.tenant_id AND a.drive_id=changed.drive_id;
  RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION invalidate_deleted_acl_capability_projection() FROM PUBLIC;

CREATE FUNCTION invalidate_updated_acl_capability_projection() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE drives d SET acl_generation=d.acl_generation+1
    FROM (
      SELECT tenant_id,drive_id FROM old_acl_rows
      UNION SELECT tenant_id,drive_id FROM new_acl_rows
    ) changed
    WHERE d.tenant_id=changed.tenant_id AND d.id=changed.drive_id;
  UPDATE nodes n SET acl_generation=n.acl_generation+1
    FROM (
      SELECT tenant_id,drive_id,resource_id FROM old_acl_rows
      UNION SELECT tenant_id,drive_id,resource_id FROM new_acl_rows
    ) changed
    WHERE n.tenant_id=changed.tenant_id AND n.drive_id=changed.drive_id
      AND n.id=changed.resource_id;
  DELETE FROM authorization_generations a USING (
    SELECT tenant_id,drive_id FROM old_acl_rows
    UNION SELECT tenant_id,drive_id FROM new_acl_rows
  ) changed
    WHERE a.tenant_id=changed.tenant_id AND a.drive_id=changed.drive_id;
  RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION invalidate_updated_acl_capability_projection() FROM PUBLIC;

CREATE TRIGGER acl_capability_projection_insert
AFTER INSERT ON acl_entries
REFERENCING NEW TABLE AS new_acl_rows
FOR EACH STATEMENT EXECUTE FUNCTION invalidate_inserted_acl_capability_projection();
CREATE TRIGGER acl_capability_projection_delete
AFTER DELETE ON acl_entries
REFERENCING OLD TABLE AS old_acl_rows
FOR EACH STATEMENT EXECUTE FUNCTION invalidate_deleted_acl_capability_projection();
CREATE TRIGGER acl_capability_projection_update
AFTER UPDATE ON acl_entries
REFERENCING OLD TABLE AS old_acl_rows NEW TABLE AS new_acl_rows
FOR EACH STATEMENT EXECUTE FUNCTION invalidate_updated_acl_capability_projection();

-- Existing direct shares predate the external-editor/comment/review preset
-- vocabulary. Expand them once under the statement trigger above so each
-- affected drive/resource generation advances once, then record the forward
-- data migration for recovery evidence.
WITH expanded AS (
  SELECT s.tenant_id,s.drive_id,s.resource_id,s.id AS direct_share_id,
    s.target_principal_id,s.inheritance,s.created_by,action
  FROM direct_shares s CROSS JOIN LATERAL unnest(
    CASE s.preset
      WHEN 'viewer' THEN ARRAY['USE_EXTERNAL_EDITOR']::text[]
      ELSE ARRAY['USE_EXTERNAL_EDITOR','COMMENT','REVIEW']::text[]
    END
  ) action
  WHERE s.revoked_at IS NULL
)
INSERT INTO acl_entries (
  tenant_id,drive_id,resource_id,id,principal_id,action,effect,inheritance,
  created_by,generation,direct_share_id
)
SELECT tenant_id,drive_id,resource_id,uuidv7(),target_principal_id,action,
  'allow',inheritance,created_by,1,direct_share_id
FROM expanded
ON CONFLICT (tenant_id,resource_id,principal_id,action,inheritance) DO NOTHING;

INSERT INTO filebelt_document.data_migrations (name,affected_resources)
SELECT 'phase7_share_presets_v1',count(DISTINCT (tenant_id,resource_id))
FROM direct_shares WHERE revoked_at IS NULL;
