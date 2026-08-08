-- SPDX-License-Identifier: Apache-2.0

-- Durable Markdown collaboration manifests. PostgreSQL holds authority and
-- fencing metadata; CRDT updates and snapshots remain UUID payload objects.
-- The database owner creates this schema through roles.sql before the
-- restricted migrator runs this forward-only migration.

ALTER TABLE public.payload_objects
  ADD COLUMN authority_kind text NOT NULL DEFAULT 'file'
    CHECK (authority_kind IN ('file','collaboration')),
  ADD CONSTRAINT payload_objects_authority_key
    UNIQUE (tenant_id,id,authority_kind);

CREATE FUNCTION filebelt_collaboration.prevent_payload_authority_change()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.authority_kind IS DISTINCT FROM OLD.authority_kind THEN
    RAISE EXCEPTION 'payload authority class is immutable';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION filebelt_collaboration.prevent_payload_authority_change() FROM PUBLIC;
CREATE TRIGGER payload_objects_authority_immutable
BEFORE UPDATE OF authority_kind ON public.payload_objects
FOR EACH ROW EXECUTE FUNCTION filebelt_collaboration.prevent_payload_authority_change();

CREATE VIEW filebelt_collaboration.payload_objects
  WITH (security_barrier = true) AS
SELECT tenant_id,id,drive_id,backend_id,locator,layout,state,size_bytes,blake3,
  finalized_at,referenced_at,deletion_intent_at,quarantine_reason,created_at,
  authority_kind
FROM public.payload_objects
WHERE authority_kind = 'collaboration'
WITH LOCAL CHECK OPTION;

ALTER TABLE public.file_versions
  ADD COLUMN origin_kind text NOT NULL DEFAULT 'upload'
    CHECK (origin_kind IN ('upload','markdown_save','collaboration_checkpoint','import','restore')),
  ADD COLUMN source_version_id uuid,
  ADD COLUMN creator_display_name text,
  ADD COLUMN mcp_assisted boolean NOT NULL DEFAULT false,
  ADD CONSTRAINT file_versions_source_version_fk
    FOREIGN KEY (tenant_id,source_version_id)
    REFERENCES public.file_versions(tenant_id,id),
  ADD CONSTRAINT file_versions_creator_display_name_bound
    CHECK (creator_display_name IS NULL OR length(creator_display_name) BETWEEN 1 AND 120),
  ADD CONSTRAINT file_versions_media_type_bound
    CHECK (media_type IS NULL OR (
      length(media_type) BETWEEN 3 AND 127 AND
      media_type ~ '^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$'
    ));

-- Semantic Markdown provenance contains only immutable target context and
-- domain-separated source digests. The normalized source itself never enters
-- the MCP invocation record.
ALTER TABLE filebelt_mcp.invocations
  ADD COLUMN semantic_node_id uuid,
  ADD COLUMN semantic_base_version_id uuid,
  ADD COLUMN semantic_input_digest bytea,
  ADD COLUMN semantic_output_digest bytea,
  ADD CONSTRAINT mcp_semantic_context_complete CHECK (
    num_nonnulls(semantic_node_id,semantic_base_version_id,semantic_input_digest) IN (0,3)
  ),
  ADD CONSTRAINT mcp_semantic_output_requires_context CHECK (
    semantic_output_digest IS NULL OR
    num_nonnulls(semantic_node_id,semantic_base_version_id,semantic_input_digest) = 3
  ),
  ADD CONSTRAINT mcp_semantic_input_digest_bound CHECK (
    semantic_input_digest IS NULL OR octet_length(semantic_input_digest) = 32
  ),
  ADD CONSTRAINT mcp_semantic_output_digest_bound CHECK (
    semantic_output_digest IS NULL OR octet_length(semantic_output_digest) = 32
  ),
  ADD CONSTRAINT mcp_semantic_base_version_fk
    FOREIGN KEY (tenant_id,semantic_node_id,semantic_base_version_id)
    REFERENCES public.file_versions(tenant_id,node_id,id);

CREATE TABLE filebelt_collaboration.rooms (
  tenant_id uuid NOT NULL REFERENCES public.tenants(id),
  id uuid NOT NULL,
  drive_id uuid NOT NULL,
  node_id uuid NOT NULL,
  current_epoch bigint NOT NULL DEFAULT 1 CHECK (current_epoch > 0),
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,id,drive_id,node_id),
  UNIQUE (tenant_id,drive_id,node_id),
  FOREIGN KEY (tenant_id,drive_id,node_id)
    REFERENCES public.nodes(tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,created_by) REFERENCES public.principals(tenant_id,id)
);

CREATE TABLE filebelt_collaboration.epochs (
  tenant_id uuid NOT NULL,
  room_id uuid NOT NULL,
  epoch bigint NOT NULL CHECK (epoch > 0),
  drive_id uuid NOT NULL,
  node_id uuid NOT NULL,
  base_version_id uuid NOT NULL,
  state text NOT NULL DEFAULT 'active'
    CHECK (state IN ('active','frozen','closed','tombstoned')),
  freeze_reason text CHECK (freeze_reason IS NULL OR freeze_reason IN (
    'external_head','authorization_uncertain','quota','state_limit',
    'retained_payload_limit','corrupt_state','expired','discarded'
  )),
  dirty boolean NOT NULL DEFAULT false,
  durable_sequence bigint NOT NULL DEFAULT 0 CHECK (durable_sequence >= 0),
  fencing_token bigint NOT NULL DEFAULT 1 CHECK (fencing_token > 0),
  source_bom boolean NOT NULL DEFAULT false,
  source_line_ending text NOT NULL DEFAULT 'lf'
    CHECK (source_line_ending IN ('lf','crlf')),
  last_content_activity_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '30 days',
  warning_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '23 days',
  warning_emitted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  closed_at timestamptz,
  PRIMARY KEY (tenant_id,room_id,epoch),
  FOREIGN KEY (tenant_id,room_id,drive_id,node_id)
    REFERENCES filebelt_collaboration.rooms(tenant_id,id,drive_id,node_id),
  FOREIGN KEY (tenant_id,node_id,base_version_id)
    REFERENCES public.file_versions(tenant_id,node_id,id),
  CHECK (warning_at < expires_at),
  CHECK ((state IN ('active','frozen')) = (closed_at IS NULL)),
  CHECK ((state = 'frozen') = (freeze_reason IS NOT NULL))
);
CREATE UNIQUE INDEX collaboration_active_epoch
  ON filebelt_collaboration.epochs (tenant_id,room_id)
  WHERE state = 'active';
CREATE INDEX collaboration_epoch_expiry
  ON filebelt_collaboration.epochs (tenant_id,expires_at)
  WHERE dirty AND state IN ('active','frozen');

ALTER TABLE filebelt_collaboration.rooms
  ADD CONSTRAINT rooms_current_epoch_fk
  FOREIGN KEY (tenant_id,id,current_epoch)
  REFERENCES filebelt_collaboration.epochs(tenant_id,room_id,epoch)
  DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE filebelt_collaboration.objects (
  tenant_id uuid NOT NULL,
  room_id uuid NOT NULL,
  epoch bigint NOT NULL,
  id uuid NOT NULL,
  drive_id uuid NOT NULL,
  payload_id uuid NOT NULL,
  payload_authority_kind text NOT NULL DEFAULT 'collaboration'
    CHECK (payload_authority_kind = 'collaboration'),
  purpose text NOT NULL CHECK (purpose IN ('update_group','snapshot')),
  state text NOT NULL DEFAULT 'staging'
    CHECK (state IN ('staging','durable','superseded','delete_intent','tombstoned','quarantined','abandoned')),
  reserved_bytes bigint NOT NULL CHECK (reserved_bytes >= 0),
  size_bytes bigint CHECK (size_bytes IS NULL OR size_bytes >= 0),
  blake3 bytea CHECK (blake3 IS NULL OR octet_length(blake3) = 32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  durable_at timestamptz,
  delete_after timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,room_id,epoch,id),
  UNIQUE (tenant_id,payload_id),
  FOREIGN KEY (tenant_id,room_id,epoch)
    REFERENCES filebelt_collaboration.epochs(tenant_id,room_id,epoch),
  FOREIGN KEY (tenant_id,payload_id,payload_authority_kind)
    REFERENCES public.payload_objects(tenant_id,id,authority_kind),
  FOREIGN KEY (tenant_id,drive_id)
    REFERENCES public.drives(tenant_id,id),
  CHECK ((state IN ('durable','superseded','delete_intent','tombstoned')) =
    (size_bytes IS NOT NULL AND blake3 IS NOT NULL AND durable_at IS NOT NULL))
);
CREATE INDEX collaboration_object_cleanup
  ON filebelt_collaboration.objects (tenant_id,delete_after)
  WHERE state IN ('superseded','delete_intent');

CREATE TABLE filebelt_collaboration.object_reservations (
  tenant_id uuid NOT NULL,
  object_id uuid NOT NULL,
  drive_id uuid NOT NULL,
  bytes bigint NOT NULL CHECK (bytes >= 0),
  state text NOT NULL DEFAULT 'active'
    CHECK (state IN ('active','committed','released')),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,object_id),
  FOREIGN KEY (tenant_id,object_id)
    REFERENCES filebelt_collaboration.objects(tenant_id,id),
  FOREIGN KEY (tenant_id,drive_id)
    REFERENCES public.drives(tenant_id,id)
);

CREATE TABLE filebelt_collaboration.update_groups (
  tenant_id uuid NOT NULL,
  room_id uuid NOT NULL,
  epoch bigint NOT NULL,
  id uuid NOT NULL,
  client_id uuid NOT NULL,
  client_update_id uuid NOT NULL,
  actor_principal_id uuid NOT NULL,
  origin_kind text NOT NULL DEFAULT 'user'
    CHECK (origin_kind IN ('user','mcp')),
  mcp_invocation_id uuid,
  source_before_digest bytea NOT NULL CHECK (octet_length(source_before_digest) = 32),
  source_after_digest bytea NOT NULL CHECK (octet_length(source_after_digest) = 32),
  object_id uuid NOT NULL,
  chunk_count integer NOT NULL CHECK (chunk_count BETWEEN 1 AND 16),
  total_bytes bigint NOT NULL CHECK (total_bytes BETWEEN 1 AND 2097152),
  first_sequence bigint NOT NULL CHECK (first_sequence > 0),
  last_sequence bigint NOT NULL CHECK (last_sequence >= first_sequence),
  state_vector bytea NOT NULL,
  state_digest bytea NOT NULL CHECK (octet_length(state_digest) = 32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,room_id,epoch,client_id,client_update_id),
  UNIQUE (tenant_id,room_id,epoch,first_sequence),
  FOREIGN KEY (tenant_id,room_id,epoch,object_id)
    REFERENCES filebelt_collaboration.objects(tenant_id,room_id,epoch,id),
  FOREIGN KEY (tenant_id,actor_principal_id)
    REFERENCES public.principals(tenant_id,id),
  FOREIGN KEY (tenant_id,mcp_invocation_id)
    REFERENCES filebelt_mcp.invocations(tenant_id,id),
  CHECK ((origin_kind = 'mcp') = (mcp_invocation_id IS NOT NULL)),
  CHECK (last_sequence = first_sequence),
  CHECK (octet_length(state_vector) <= 1048576)
);
CREATE INDEX collaboration_update_replay
  ON filebelt_collaboration.update_groups
    (tenant_id,room_id,epoch,first_sequence,last_sequence);

CREATE TABLE filebelt_collaboration.update_chunks (
  tenant_id uuid NOT NULL,
  group_id uuid NOT NULL,
  chunk_index integer NOT NULL CHECK (chunk_index BETWEEN 0 AND 15),
  object_offset bigint NOT NULL CHECK (object_offset >= 0),
  size_bytes integer NOT NULL CHECK (size_bytes BETWEEN 1 AND 262144),
  blake3 bytea NOT NULL CHECK (octet_length(blake3) = 32),
  PRIMARY KEY (tenant_id,group_id,chunk_index),
  FOREIGN KEY (tenant_id,group_id)
    REFERENCES filebelt_collaboration.update_groups(tenant_id,id) ON DELETE CASCADE
);

CREATE TABLE filebelt_collaboration.snapshots (
  tenant_id uuid NOT NULL,
  room_id uuid NOT NULL,
  epoch bigint NOT NULL,
  id uuid NOT NULL,
  object_id uuid NOT NULL,
  covered_sequence bigint NOT NULL CHECK (covered_sequence >= 0),
  state_vector bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  superseded_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,room_id,epoch,covered_sequence),
  FOREIGN KEY (tenant_id,room_id,epoch,object_id)
    REFERENCES filebelt_collaboration.objects(tenant_id,room_id,epoch,id),
  CHECK (octet_length(state_vector) <= 1048576)
);
CREATE UNIQUE INDEX collaboration_current_snapshot
  ON filebelt_collaboration.snapshots (tenant_id,room_id,epoch)
  WHERE superseded_at IS NULL;

CREATE TABLE filebelt_collaboration.join_grants (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  token_digest bytea NOT NULL CHECK (octet_length(token_digest) = 32),
  room_id uuid NOT NULL,
  epoch bigint NOT NULL,
  principal_id uuid NOT NULL,
  session_id uuid NOT NULL,
  client_id uuid NOT NULL,
  presence_mode text NOT NULL CHECK (presence_mode IN ('pseudonym','display_name')),
  presence_label text NOT NULL CHECK (length(presence_label) BETWEEN 1 AND 120),
  resource_acl_generation bigint NOT NULL CHECK (resource_acl_generation > 0),
  drive_acl_generation bigint NOT NULL CHECK (drive_acl_generation > 0),
  membership_generation bigint NOT NULL CHECK (membership_generation > 0),
  namespace_generation bigint NOT NULL CHECK (namespace_generation > 0),
  can_checkpoint boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,token_digest),
  FOREIGN KEY (tenant_id,room_id,epoch)
    REFERENCES filebelt_collaboration.epochs(tenant_id,room_id,epoch),
  FOREIGN KEY (tenant_id,principal_id)
    REFERENCES public.principals(tenant_id,id),
  FOREIGN KEY (tenant_id,session_id)
    REFERENCES public.api_sessions(tenant_id,id),
  CHECK (expires_at <= created_at + interval '60 seconds')
);
CREATE INDEX collaboration_join_grant_expiry
  ON filebelt_collaboration.join_grants (tenant_id,expires_at,consumed_at);

CREATE TABLE filebelt_collaboration.checkpoints (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  room_id uuid NOT NULL,
  epoch bigint NOT NULL,
  node_id uuid NOT NULL,
  base_version_id uuid NOT NULL,
  durable_sequence bigint NOT NULL CHECK (durable_sequence >= 0),
  state_vector bytea NOT NULL,
  source_size_bytes bigint NOT NULL CHECK (source_size_bytes BETWEEN 0 AND 2097152),
  source_blake3 bytea NOT NULL CHECK (octet_length(source_blake3) = 32),
  created_by uuid NOT NULL,
  mcp_assisted boolean NOT NULL DEFAULT false,
  state text NOT NULL DEFAULT 'prepared'
    CHECK (state IN ('prepared','committed','expired','rejected')),
  committed_version_id uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,id,node_id),
  FOREIGN KEY (tenant_id,room_id,epoch)
    REFERENCES filebelt_collaboration.epochs(tenant_id,room_id,epoch),
  FOREIGN KEY (tenant_id,node_id,base_version_id)
    REFERENCES public.file_versions(tenant_id,node_id,id),
  FOREIGN KEY (tenant_id,node_id,committed_version_id)
    REFERENCES public.file_versions(tenant_id,node_id,id),
  FOREIGN KEY (tenant_id,created_by)
    REFERENCES public.principals(tenant_id,id),
  CHECK (octet_length(state_vector) <= 1048576),
  CHECK (expires_at <= created_at + interval '5 minutes'),
  CHECK ((state = 'committed') = (committed_version_id IS NOT NULL AND consumed_at IS NOT NULL))
);

CREATE TABLE filebelt_collaboration.import_intents (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  drive_id uuid NOT NULL,
  source_node_id uuid NOT NULL,
  source_version_id uuid NOT NULL,
  target_parent_id uuid NOT NULL,
  target_display_name text NOT NULL CHECK (length(target_display_name) BETWEEN 1 AND 255),
  target_name_key text NOT NULL,
  principal_id uuid NOT NULL,
  session_id uuid NOT NULL,
  source_membership_generation bigint NOT NULL CHECK (source_membership_generation > 0),
  source_drive_acl_generation bigint NOT NULL CHECK (source_drive_acl_generation > 0),
  source_namespace_generation bigint NOT NULL CHECK (source_namespace_generation > 0),
  source_resource_acl_generation bigint NOT NULL CHECK (source_resource_acl_generation > 0),
  target_membership_generation bigint NOT NULL CHECK (target_membership_generation > 0),
  target_drive_acl_generation bigint NOT NULL CHECK (target_drive_acl_generation > 0),
  target_namespace_generation bigint NOT NULL CHECK (target_namespace_generation > 0),
  target_resource_acl_generation bigint NOT NULL CHECK (target_resource_acl_generation > 0),
  state text NOT NULL DEFAULT 'active'
    CHECK (state IN ('active','consumed','expired','revoked')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,id,drive_id),
  FOREIGN KEY (tenant_id,drive_id,source_node_id)
    REFERENCES public.nodes(tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,source_node_id,source_version_id)
    REFERENCES public.file_versions(tenant_id,node_id,id),
  FOREIGN KEY (tenant_id,drive_id,target_parent_id)
    REFERENCES public.nodes(tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,principal_id)
    REFERENCES public.principals(tenant_id,id),
  FOREIGN KEY (tenant_id,session_id)
    REFERENCES public.api_sessions(tenant_id,id),
  CHECK (expires_at <= created_at + interval '15 minutes'),
  CHECK ((state = 'consumed') = (consumed_at IS NOT NULL))
);

CREATE TABLE filebelt_collaboration.leases (
  tenant_id uuid NOT NULL,
  room_id uuid NOT NULL,
  epoch bigint NOT NULL,
  kind text NOT NULL CHECK (kind IN ('snapshot','checkpoint','cleanup')),
  owner_id uuid NOT NULL,
  fencing_token bigint NOT NULL CHECK (fencing_token > 0),
  expires_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,room_id,epoch,kind),
  FOREIGN KEY (tenant_id,room_id,epoch)
    REFERENCES filebelt_collaboration.epochs(tenant_id,room_id,epoch)
);

CREATE TABLE filebelt_collaboration.participants (
  tenant_id uuid NOT NULL,
  room_id uuid NOT NULL,
  epoch bigint NOT NULL,
  client_id uuid NOT NULL,
  connection_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  session_id uuid NOT NULL,
  joined_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,room_id,epoch,client_id),
  UNIQUE (tenant_id,connection_id),
  FOREIGN KEY (tenant_id,room_id,epoch)
    REFERENCES filebelt_collaboration.epochs(tenant_id,room_id,epoch),
  FOREIGN KEY (tenant_id,principal_id)
    REFERENCES public.principals(tenant_id,id),
  FOREIGN KEY (tenant_id,session_id)
    REFERENCES public.api_sessions(tenant_id,id),
  CHECK (expires_at <= last_seen_at + interval '90 seconds')
);
CREATE INDEX collaboration_participant_expiry
  ON filebelt_collaboration.participants (tenant_id,expires_at);

ALTER TABLE public.upload_sessions
  ADD COLUMN declared_media_type text,
  ADD COLUMN collaboration_checkpoint_id uuid,
  ADD COLUMN import_intent_id uuid,
  ADD CONSTRAINT upload_declared_media_type_bound CHECK (
    declared_media_type IS NULL OR (
      length(declared_media_type) BETWEEN 3 AND 127 AND
      declared_media_type ~ '^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$'
    )
  ),
  ADD CONSTRAINT upload_collaboration_checkpoint_fk
    FOREIGN KEY (tenant_id,collaboration_checkpoint_id,node_id)
    REFERENCES filebelt_collaboration.checkpoints(tenant_id,id,node_id),
  ADD CONSTRAINT upload_import_intent_fk
    FOREIGN KEY (tenant_id,import_intent_id,drive_id)
    REFERENCES filebelt_collaboration.import_intents(tenant_id,id,drive_id),
  ADD CONSTRAINT upload_single_provenance_intent CHECK (
    num_nonnulls(collaboration_checkpoint_id,import_intent_id) <= 1
  );
