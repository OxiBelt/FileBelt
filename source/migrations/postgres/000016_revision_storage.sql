-- SPDX-License-Identifier: Apache-2.0

-- Canonical revision-storage expansion.  PostgreSQL remains authoritative for
-- FileBelt versions and policy; Git repositories and shared chunk objects are
-- replaceable byte planes addressed only through these records.

CREATE SCHEMA IF NOT EXISTS filebelt_revision;
REVOKE ALL ON SCHEMA filebelt_revision FROM PUBLIC;

ALTER TABLE public.user_preferences
  ADD COLUMN text_edit_limit_bytes bigint NOT NULL DEFAULT 2097152
    CHECK (text_edit_limit_bytes IN (1048576,2097152,4194304,8388608,16777216)),
  ADD COLUMN text_inline_limit_bytes bigint NOT NULL DEFAULT 8388608
    CHECK (text_inline_limit_bytes IN (8388608,16777216,33554432,67108864,104857600)),
  ADD COLUMN text_preference_generation bigint NOT NULL DEFAULT 1
    CHECK (text_preference_generation>0),
  ADD CONSTRAINT user_preferences_text_limit_order
    CHECK (text_inline_limit_bytes>=text_edit_limit_bytes);

ALTER TABLE public.nodes
  ADD COLUMN content_class_policy text NOT NULL DEFAULT 'auto'
    CHECK (content_class_policy IN ('auto','binary')),
  ADD COLUMN attribute_generation bigint NOT NULL DEFAULT 1
    CHECK (attribute_generation>0);

ALTER TABLE public.file_versions DROP CONSTRAINT file_versions_origin_kind_check;
ALTER TABLE public.file_versions ADD CONSTRAINT file_versions_origin_kind_check
  CHECK (origin_kind IN (
    'upload','text_save','markdown_save','collaboration_checkpoint','import',
    'restore','external_document','mount','nfs'
  ));

CREATE TABLE filebelt_revision.contents (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  drive_id uuid NOT NULL,
  node_id uuid NOT NULL,
  backend text NOT NULL
    CHECK (backend IN ('legacy_payload','git_sha256','shared_chunks')),
  observed_class text NOT NULL
    CHECK (observed_class IN ('unclassified','text','office','binary')),
  state text NOT NULL
    CHECK (state IN ('legacy','staging','referenced','held','quarantined')),
  legacy_payload_id uuid,
  size_bytes bigint NOT NULL CHECK (size_bytes>=0),
  blake3 bytea NOT NULL CHECK (octet_length(blake3)=32),
  media_type text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,id,node_id),
  UNIQUE (tenant_id,id,drive_id),
  UNIQUE (tenant_id,id,drive_id,node_id),
  FOREIGN KEY (tenant_id,drive_id,node_id)
    REFERENCES public.nodes(tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,legacy_payload_id)
    REFERENCES public.payload_objects(tenant_id,id),
  CHECK ((backend='legacy_payload')=(legacy_payload_id IS NOT NULL)),
  CHECK ((state='legacy')=(backend='legacy_payload'))
);

INSERT INTO filebelt_revision.contents (
  tenant_id,id,drive_id,node_id,backend,observed_class,state,
  legacy_payload_id,size_bytes,blake3,media_type,created_at
)
SELECT version.tenant_id,version.id,node.drive_id,version.node_id,
       'legacy_payload','unclassified','legacy',version.payload_id,
       version.size_bytes,version.blake3,version.media_type,version.created_at
FROM public.file_versions AS version
JOIN public.nodes AS node
  ON node.tenant_id=version.tenant_id AND node.id=version.node_id;

ALTER TABLE public.file_versions ADD COLUMN content_id uuid;
UPDATE public.file_versions SET content_id=id;

-- Release-A compatibility: existing writers continue to publish legacy
-- payloads while the coordinator backfills and activation remains gated. The
-- trigger creates the authoritative content record in the same transaction;
-- it is removed only in the later writer-activation migration.
CREATE FUNCTION filebelt_revision.attach_legacy_content()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_revision
AS $$
DECLARE
  revision_drive_id uuid;
BEGIN
  IF NEW.content_id IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE='55000',
      MESSAGE='compatibility writers cannot supply revision content identifiers';
  END IF;
  SELECT drive_id INTO STRICT revision_drive_id
  FROM public.nodes
  WHERE tenant_id=NEW.tenant_id AND id=NEW.node_id;
  NEW.content_id := NEW.id;
  INSERT INTO filebelt_revision.contents (
    tenant_id,id,drive_id,node_id,backend,observed_class,state,
    legacy_payload_id,size_bytes,blake3,media_type,created_at
  ) VALUES (
    NEW.tenant_id,NEW.content_id,revision_drive_id,NEW.node_id,
    'legacy_payload','unclassified','legacy',NEW.payload_id,
    NEW.size_bytes,NEW.blake3,NEW.media_type,NEW.created_at
  );
  INSERT INTO filebelt_revision.backfill_jobs(tenant_id,content_id)
  VALUES (NEW.tenant_id,NEW.content_id);
  RETURN NEW;
END
$$;
CREATE TRIGGER file_versions_attach_legacy_content
BEFORE INSERT ON public.file_versions
FOR EACH ROW EXECUTE FUNCTION filebelt_revision.attach_legacy_content();

ALTER TABLE public.file_versions ALTER COLUMN content_id SET NOT NULL;
ALTER TABLE public.file_versions ADD CONSTRAINT file_versions_content_fk
  FOREIGN KEY (tenant_id,content_id,node_id)
  REFERENCES filebelt_revision.contents(tenant_id,id,node_id);

CREATE TABLE filebelt_revision.git_repositories (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  drive_id uuid NOT NULL,
  node_id uuid NOT NULL,
  object_format text NOT NULL DEFAULT 'sha256' CHECK (object_format='sha256'),
  projected_head_oid bytea CHECK (
    projected_head_oid IS NULL OR octet_length(projected_head_oid)=32
  ),
  state text NOT NULL DEFAULT 'active'
    CHECK (state IN ('active','quarantined','delete_intent','deleted')),
  allocated_bytes bigint NOT NULL DEFAULT 0 CHECK (allocated_bytes>=0),
  fencing_token bigint NOT NULL DEFAULT 1 CHECK (fencing_token>0),
  quarantine_reason text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,id,drive_id,node_id),
  UNIQUE (tenant_id,drive_id,node_id),
  FOREIGN KEY (tenant_id,drive_id,node_id)
    REFERENCES public.nodes(tenant_id,drive_id,id)
);

CREATE TABLE filebelt_revision.git_revisions (
  tenant_id uuid NOT NULL,
  content_id uuid NOT NULL,
  repository_id uuid NOT NULL,
  drive_id uuid NOT NULL,
  node_id uuid NOT NULL,
  commit_oid bytea NOT NULL CHECK (octet_length(commit_oid)=32),
  tree_oid bytea NOT NULL CHECK (octet_length(tree_oid)=32),
  blob_oid bytea NOT NULL CHECK (octet_length(blob_oid)=32),
  final_newline boolean NOT NULL,
  parent_commit_oid bytea CHECK (
    parent_commit_oid IS NULL OR octet_length(parent_commit_oid)=32
  ),
  ordinal bigint NOT NULL CHECK (ordinal>0),
  committed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,content_id),
  UNIQUE (tenant_id,repository_id,commit_oid),
  UNIQUE (tenant_id,repository_id,ordinal),
  FOREIGN KEY (tenant_id,content_id,drive_id,node_id)
    REFERENCES filebelt_revision.contents(tenant_id,id,drive_id,node_id),
  FOREIGN KEY (tenant_id,repository_id,drive_id,node_id)
    REFERENCES filebelt_revision.git_repositories(tenant_id,id,drive_id,node_id)
);

CREATE TABLE filebelt_revision.chunk_objects (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  drive_id uuid NOT NULL,
  locator uuid NOT NULL,
  size_bytes integer NOT NULL CHECK (size_bytes BETWEEN 1 AND 16777216),
  blake3 bytea NOT NULL CHECK (octet_length(blake3)=32),
  state text NOT NULL
    CHECK (state IN ('staging','referenced','delete_intent','deleting','deleted',
                     'quarantining','quarantined')),
  reference_count bigint NOT NULL DEFAULT 0 CHECK (reference_count>=0),
  fencing_token bigint NOT NULL DEFAULT 1 CHECK (fencing_token>0),
  quarantine_reason text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  referenced_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,id,drive_id),
  UNIQUE (tenant_id,drive_id,blake3,size_bytes),
  UNIQUE (tenant_id,locator),
  FOREIGN KEY (tenant_id,drive_id) REFERENCES public.drives(tenant_id,id),
  CHECK (state='staging' OR referenced_at IS NOT NULL),
  CHECK (state NOT IN ('delete_intent','deleting','deleted') OR reference_count=0)
);

CREATE TABLE filebelt_revision.chunk_manifests (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  content_id uuid NOT NULL,
  drive_id uuid NOT NULL,
  chunk_size_bytes integer NOT NULL DEFAULT 16777216
    CHECK (chunk_size_bytes=16777216),
  chunk_count integer NOT NULL CHECK (chunk_count>=0),
  size_bytes bigint NOT NULL CHECK (size_bytes>=0),
  blake3 bytea NOT NULL CHECK (octet_length(blake3)=32),
  state text NOT NULL CHECK (state IN ('staging','referenced','quarantined')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,content_id),
  UNIQUE (tenant_id,id,drive_id),
  FOREIGN KEY (tenant_id,content_id,drive_id)
    REFERENCES filebelt_revision.contents(tenant_id,id,drive_id),
  FOREIGN KEY (tenant_id,drive_id) REFERENCES public.drives(tenant_id,id),
  CHECK ((size_bytes=0)=(chunk_count=0))
);

CREATE TABLE filebelt_revision.chunk_members (
  tenant_id uuid NOT NULL,
  manifest_id uuid NOT NULL,
  drive_id uuid NOT NULL,
  chunk_index integer NOT NULL CHECK (chunk_index>=0),
  chunk_id uuid NOT NULL,
  logical_offset bigint NOT NULL CHECK (logical_offset>=0),
  size_bytes integer NOT NULL CHECK (size_bytes BETWEEN 1 AND 16777216),
  PRIMARY KEY (tenant_id,manifest_id,chunk_index),
  FOREIGN KEY (tenant_id,manifest_id,drive_id)
    REFERENCES filebelt_revision.chunk_manifests(tenant_id,id,drive_id)
    ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,chunk_id,drive_id)
    REFERENCES filebelt_revision.chunk_objects(tenant_id,id,drive_id),
  UNIQUE (tenant_id,manifest_id,logical_offset)
);

CREATE TABLE filebelt_revision.operations (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  drive_id uuid NOT NULL,
  node_id uuid NOT NULL,
  actor_principal_id uuid NOT NULL,
  api_session_id uuid,
  expected_head_version_id uuid,
  target_version_id uuid,
  kind text NOT NULL
    CHECK (kind IN ('publish','restore','backfill','reconcile_ref','delete')),
  backend text NOT NULL
    CHECK (backend IN ('git_sha256','shared_chunks')),
  state text NOT NULL
    CHECK (state IN ('allocated','staging','prepared','committing','committed',
                     'conflict','held','failed')),
  request_fingerprint bytea NOT NULL CHECK (octet_length(request_fingerprint)=32),
  fencing_token bigint NOT NULL DEFAULT 1 CHECK (fencing_token>0),
  lease_owner uuid,
  lease_expires_at timestamptz,
  failure_code text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,actor_principal_id,request_fingerprint),
  FOREIGN KEY (tenant_id,drive_id,node_id)
    REFERENCES public.nodes(tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,actor_principal_id)
    REFERENCES public.principals(tenant_id,id),
  FOREIGN KEY (tenant_id,api_session_id)
    REFERENCES public.api_sessions(tenant_id,id),
  FOREIGN KEY (tenant_id,node_id,expected_head_version_id)
    REFERENCES public.file_versions(tenant_id,node_id,id),
  FOREIGN KEY (tenant_id,node_id,target_version_id)
    REFERENCES public.file_versions(tenant_id,node_id,id),
  CHECK ((lease_owner IS NULL)=(lease_expires_at IS NULL))
);
CREATE INDEX revision_operations_reconcile_index
  ON filebelt_revision.operations(tenant_id,state,updated_at,id)
  WHERE state IN ('prepared','committing','held');

CREATE TABLE filebelt_revision.backfill_jobs (
  tenant_id uuid NOT NULL,
  content_id uuid NOT NULL,
  target_backend text NOT NULL
    DEFAULT 'classify'
    CHECK (target_backend IN ('classify','git_sha256','shared_chunks')),
  state text NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending','leased','verified','held')),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count>=0),
  fencing_token bigint NOT NULL DEFAULT 1 CHECK (fencing_token>0),
  lease_owner uuid,
  lease_expires_at timestamptz,
  next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_error_code text,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,content_id),
  FOREIGN KEY (tenant_id,content_id)
    REFERENCES filebelt_revision.contents(tenant_id,id),
  CHECK ((state='leased')=(lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL))
);
CREATE INDEX revision_backfill_ready_index
  ON filebelt_revision.backfill_jobs(tenant_id,next_attempt_at,content_id)
  WHERE state='pending';

INSERT INTO filebelt_revision.backfill_jobs(tenant_id,content_id)
SELECT tenant_id,id FROM filebelt_revision.contents;

CREATE TABLE filebelt_revision.holds (
  tenant_id uuid NOT NULL,
  content_id uuid NOT NULL,
  reason_code text NOT NULL,
  detail text NOT NULL CHECK (length(detail) BETWEEN 1 AND 1024),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  resolved_at timestamptz,
  resolution text CHECK (resolution IN ('retry','binary','recovered')),
  PRIMARY KEY (tenant_id,content_id),
  FOREIGN KEY (tenant_id,content_id)
    REFERENCES filebelt_revision.contents(tenant_id,id),
  CHECK ((resolved_at IS NULL)=(resolution IS NULL))
);

CREATE TABLE filebelt_revision.activation_state (
  tenant_id uuid PRIMARY KEY REFERENCES public.tenants(id),
  state text NOT NULL DEFAULT 'compatibility'
    CHECK (state IN ('compatibility','backfilling','ready','active')),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation>0),
  activated_at timestamptz,
  source_revision text,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((state='active')=(activated_at IS NOT NULL))
);
INSERT INTO filebelt_revision.activation_state(tenant_id)
SELECT id FROM public.tenants;

CREATE FUNCTION filebelt_revision.create_tenant_activation_state()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,filebelt_revision
AS $$
BEGIN
  INSERT INTO filebelt_revision.activation_state(tenant_id) VALUES (NEW.id);
  RETURN NEW;
END
$$;
CREATE TRIGGER revision_tenant_activation_state
AFTER INSERT ON public.tenants
FOR EACH ROW EXECUTE FUNCTION filebelt_revision.create_tenant_activation_state();

CREATE FUNCTION filebelt_revision.prevent_referenced_content_rewrite()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog
AS $$
BEGIN
  IF (OLD.state='referenced' AND NEW.state NOT IN ('referenced','quarantined')) OR
     (OLD.state='quarantined' AND NEW.state IS DISTINCT FROM 'quarantined') OR
     (OLD.state IN ('referenced','quarantined') AND (
    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
    NEW.id IS DISTINCT FROM OLD.id OR
    NEW.drive_id IS DISTINCT FROM OLD.drive_id OR
    NEW.node_id IS DISTINCT FROM OLD.node_id OR
    NEW.backend IS DISTINCT FROM OLD.backend OR
    NEW.observed_class IS DISTINCT FROM OLD.observed_class OR
    NEW.legacy_payload_id IS DISTINCT FROM OLD.legacy_payload_id OR
    NEW.size_bytes IS DISTINCT FROM OLD.size_bytes OR
    NEW.blake3 IS DISTINCT FROM OLD.blake3 OR
    NEW.media_type IS DISTINCT FROM OLD.media_type OR
    NEW.created_at IS DISTINCT FROM OLD.created_at
  )) THEN
    RAISE EXCEPTION USING ERRCODE='55000',
      MESSAGE='referenced revision content is immutable';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER revision_content_immutable
BEFORE UPDATE ON filebelt_revision.contents
FOR EACH ROW EXECUTE FUNCTION filebelt_revision.prevent_referenced_content_rewrite();

REVOKE ALL ON FUNCTION filebelt_revision.create_tenant_activation_state() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_revision.prevent_referenced_content_rewrite() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_revision.attach_legacy_content() FROM PUBLIC;
