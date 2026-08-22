-- SPDX-License-Identifier: Apache-2.0

-- Additive, dormant PostgreSQL authority for directory-level Git repositories.
-- The existing one-file revision projection remains unchanged.  No runtime
-- role receives access to these rows in this compatibility release.

CREATE TABLE filebelt_revision.managed_repositories (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  drive_id uuid NOT NULL,
  root_node_id uuid NOT NULL,
  object_format text NOT NULL DEFAULT 'sha256'
    CHECK (object_format IN ('sha1','sha256')),
  state text NOT NULL DEFAULT 'compatibility'
    CHECK (state IN ('compatibility','ready','active','quarantined',
                     'delete_intent','deleted')),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation>0),
  source_revision text,
  verified_at timestamptz,
  activated_at timestamptz,
  pack_limit_bytes bigint NOT NULL DEFAULT 1073741824
    CHECK (pack_limit_bytes=1073741824),
  push_commit_limit integer NOT NULL DEFAULT 32
    CHECK (push_commit_limit=32),
  changed_path_limit_per_commit integer NOT NULL DEFAULT 10000
    CHECK (changed_path_limit_per_commit=10000),
  tree_entry_limit integer NOT NULL DEFAULT 100000
    CHECK (tree_entry_limit=100000),
  blob_limit_bytes bigint NOT NULL DEFAULT 104857600
    CHECK (blob_limit_bytes=104857600),
  unreachable_retention interval NOT NULL DEFAULT interval '30 days'
    CHECK (unreachable_retention=interval '30 days'),
  quarantine_retention interval NOT NULL DEFAULT interval '24 hours'
    CHECK (quarantine_retention=interval '24 hours'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,id,object_format),
  UNIQUE (tenant_id,drive_id,root_node_id),
  FOREIGN KEY (tenant_id,drive_id,root_node_id)
    REFERENCES public.nodes(tenant_id,drive_id,id),
  CHECK (state NOT IN ('ready','active') OR verified_at IS NOT NULL),
  CHECK (state<>'active' OR activated_at IS NOT NULL),
  CHECK (state NOT IN ('ready','active') OR source_revision IS NOT NULL)
);

CREATE TABLE filebelt_revision.managed_repository_refs (
  tenant_id uuid NOT NULL,
  repository_id uuid NOT NULL,
  object_format text NOT NULL,
  ref_name text NOT NULL CHECK (
    octet_length(ref_name) BETWEEN 6 AND 255
    AND ref_name ~ '^refs/(heads|tags|pull)/[A-Za-z0-9._/-]+$'
    AND ref_name NOT LIKE '%..%'
    AND ref_name NOT LIKE '%//%'
    AND right(ref_name,1)<>'/'
    AND right(ref_name,1)<>'.'
    AND ref_name NOT LIKE '%.lock'
  ),
  state text NOT NULL DEFAULT 'approved'
    CHECK (state IN ('approved','blocked')),
  oid bytea,
  generation bigint NOT NULL DEFAULT 0 CHECK (generation>=0),
  namespace_projection boolean NOT NULL DEFAULT false,
  projected_snapshot_id uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,repository_id,ref_name),
  UNIQUE (tenant_id,repository_id,ref_name,object_format),
  FOREIGN KEY (tenant_id,repository_id,object_format)
    REFERENCES filebelt_revision.managed_repositories(tenant_id,id,object_format),
  CHECK (
    (object_format='sha1' AND (oid IS NULL OR octet_length(oid)=20))
    OR (object_format='sha256' AND (oid IS NULL OR octet_length(oid)=32))
  ),
  CHECK (namespace_projection=(ref_name='refs/heads/main')),
  CHECK (
    ref_name<>'refs/heads/main'
    OR ((oid IS NULL)=(projected_snapshot_id IS NULL))
  ),
  CHECK (ref_name='refs/heads/main' OR projected_snapshot_id IS NULL)
);
CREATE UNIQUE INDEX managed_repository_one_namespace_projection
  ON filebelt_revision.managed_repository_refs(tenant_id,repository_id)
  WHERE namespace_projection;

CREATE TABLE filebelt_revision.managed_repository_ref_operations (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  repository_id uuid NOT NULL,
  object_format text NOT NULL,
  actor_principal_id uuid NOT NULL,
  request_fingerprint bytea NOT NULL CHECK (octet_length(request_fingerprint)=32),
  object_set_digest bytea NOT NULL CHECK (octet_length(object_set_digest)=32),
  state text NOT NULL DEFAULT 'prepared'
    CHECK (state IN ('prepared','committed','aborted','held')),
  expected_repository_generation bigint NOT NULL CHECK (expected_repository_generation>0),
  expected_actor_generation bigint NOT NULL CHECK (expected_actor_generation>0),
  expected_drive_acl_generation bigint NOT NULL CHECK (expected_drive_acl_generation>0),
  expected_namespace_generation bigint NOT NULL CHECK (expected_namespace_generation>0),
  expected_root_acl_generation bigint NOT NULL CHECK (expected_root_acl_generation>0),
  pack_bytes bigint NOT NULL CHECK (pack_bytes BETWEEN 0 AND 1073741824),
  commit_count integer NOT NULL CHECK (commit_count BETWEEN 0 AND 32),
  max_changed_paths_per_commit integer NOT NULL
    CHECK (max_changed_paths_per_commit BETWEEN 0 AND 10000),
  max_tree_entries integer NOT NULL CHECK (max_tree_entries BETWEEN 0 AND 100000),
  max_blob_bytes bigint NOT NULL CHECK (max_blob_bytes BETWEEN 0 AND 104857600),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  expires_at timestamptz NOT NULL DEFAULT statement_timestamp()+interval '24 hours',
  terminal_at timestamptz,
  failure_code text,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,id,repository_id),
  UNIQUE (tenant_id,repository_id,actor_principal_id,request_fingerprint),
  FOREIGN KEY (tenant_id,repository_id,object_format)
    REFERENCES filebelt_revision.managed_repositories(tenant_id,id,object_format),
  FOREIGN KEY (tenant_id,actor_principal_id)
    REFERENCES public.principals(tenant_id,id),
  CHECK (expires_at>created_at AND expires_at<=created_at+interval '24 hours'),
  CHECK ((state='prepared')=(terminal_at IS NULL)),
  CHECK ((state='held')=(failure_code IS NOT NULL))
);
CREATE INDEX managed_repository_operations_reconcile
  ON filebelt_revision.managed_repository_ref_operations(
    tenant_id,state,expires_at,repository_id,id
  ) WHERE state='prepared';

CREATE TABLE filebelt_revision.managed_repository_snapshots (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  repository_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  object_format text NOT NULL,
  ref_name text NOT NULL DEFAULT 'refs/heads/main'
    CHECK (ref_name='refs/heads/main'),
  commit_oid bytea NOT NULL,
  tree_oid bytea NOT NULL,
  parent_snapshot_id uuid,
  tree_entry_count integer NOT NULL CHECK (tree_entry_count BETWEEN 0 AND 100000),
  entry_set_digest bytea NOT NULL CHECK (octet_length(entry_set_digest)=32),
  state text NOT NULL DEFAULT 'prepared'
    CHECK (state IN ('prepared','projected','quarantined')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  projected_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,id,repository_id),
  UNIQUE (tenant_id,id,repository_id,object_format),
  UNIQUE (tenant_id,repository_id,operation_id),
  UNIQUE (tenant_id,repository_id,commit_oid),
  FOREIGN KEY (tenant_id,repository_id,object_format)
    REFERENCES filebelt_revision.managed_repositories(tenant_id,id,object_format),
  FOREIGN KEY (tenant_id,operation_id,repository_id)
    REFERENCES filebelt_revision.managed_repository_ref_operations(tenant_id,id,repository_id),
  FOREIGN KEY (tenant_id,parent_snapshot_id,repository_id)
    REFERENCES filebelt_revision.managed_repository_snapshots(tenant_id,id,repository_id),
  CHECK (
    (object_format='sha1'
      AND octet_length(commit_oid)=20 AND octet_length(tree_oid)=20)
    OR (object_format='sha256'
      AND octet_length(commit_oid)=32 AND octet_length(tree_oid)=32)
  ),
  CHECK (state<>'projected' OR projected_at IS NOT NULL)
);

ALTER TABLE filebelt_revision.managed_repository_refs
  ADD CONSTRAINT managed_repository_refs_snapshot_fk
  FOREIGN KEY (tenant_id,projected_snapshot_id,repository_id,object_format)
  REFERENCES filebelt_revision.managed_repository_snapshots(
    tenant_id,id,repository_id,object_format
  );

CREATE TABLE filebelt_revision.managed_repository_contents (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  repository_id uuid NOT NULL,
  object_format text NOT NULL,
  blob_oid bytea NOT NULL,
  size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 0 AND 104857600),
  blake3 bytea NOT NULL CHECK (octet_length(blake3)=32),
  state text NOT NULL DEFAULT 'staged'
    CHECK (state IN ('staged','referenced','quarantined')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  referenced_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,id,repository_id),
  UNIQUE (tenant_id,id,repository_id,object_format),
  UNIQUE (tenant_id,repository_id,blob_oid),
  FOREIGN KEY (tenant_id,repository_id,object_format)
    REFERENCES filebelt_revision.managed_repositories(tenant_id,id,object_format),
  CHECK (
    (object_format='sha1' AND octet_length(blob_oid)=20)
    OR (object_format='sha256' AND octet_length(blob_oid)=32)
  ),
  CHECK (state<>'referenced' OR referenced_at IS NOT NULL)
);

CREATE TABLE filebelt_revision.managed_repository_file_versions (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  repository_id uuid NOT NULL,
  snapshot_id uuid NOT NULL,
  content_id uuid NOT NULL,
  object_format text NOT NULL,
  source_commit_oid bytea NOT NULL,
  source_path_key text NOT NULL CHECK (
    octet_length(source_path_key) BETWEEN 1 AND 4096
  ),
  state text NOT NULL DEFAULT 'prepared'
    CHECK (state IN ('prepared','projected','quarantined')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  projected_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,id,repository_id,snapshot_id),
  UNIQUE (tenant_id,repository_id,snapshot_id,source_path_key),
  FOREIGN KEY (tenant_id,snapshot_id,repository_id,object_format)
    REFERENCES filebelt_revision.managed_repository_snapshots(
      tenant_id,id,repository_id,object_format
    ),
  FOREIGN KEY (tenant_id,content_id,repository_id,object_format)
    REFERENCES filebelt_revision.managed_repository_contents(
      tenant_id,id,repository_id,object_format
    ),
  CHECK (
    (object_format='sha1' AND octet_length(source_commit_oid)=20)
    OR (object_format='sha256' AND octet_length(source_commit_oid)=32)
  ),
  CHECK (state<>'projected' OR projected_at IS NOT NULL)
);

CREATE TABLE filebelt_revision.managed_repository_snapshot_entries (
  tenant_id uuid NOT NULL,
  repository_id uuid NOT NULL,
  snapshot_id uuid NOT NULL,
  object_format text NOT NULL,
  path text NOT NULL CHECK (
    octet_length(path) BETWEEN 1 AND 4096
    AND left(path,1)<>'/' AND right(path,1)<>'/'
    AND path NOT LIKE '%//%'
    AND path !~ '(^|/)(\\.|\\.\\.)($|/)'
  ),
  path_key text NOT NULL CHECK (
    octet_length(path_key) BETWEEN 1 AND 4096
  ),
  parent_path text,
  parent_path_key text,
  entry_kind text NOT NULL CHECK (entry_kind IN ('directory','file')),
  git_mode integer NOT NULL,
  object_oid bytea NOT NULL,
  size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 0 AND 104857600),
  version_id uuid,
  PRIMARY KEY (tenant_id,snapshot_id,path_key),
  UNIQUE (tenant_id,snapshot_id,path),
  FOREIGN KEY (tenant_id,snapshot_id,repository_id,object_format)
    REFERENCES filebelt_revision.managed_repository_snapshots(
      tenant_id,id,repository_id,object_format
    ) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,version_id,repository_id,snapshot_id)
    REFERENCES filebelt_revision.managed_repository_file_versions(
      tenant_id,id,repository_id,snapshot_id
    ),
  CHECK (
    (object_format='sha1' AND octet_length(object_oid)=20)
    OR (object_format='sha256' AND octet_length(object_oid)=32)
  ),
  CHECK ((parent_path IS NULL)=(parent_path_key IS NULL)),
  CHECK (parent_path IS NULL OR (
    octet_length(parent_path) BETWEEN 1 AND 4096
    AND octet_length(parent_path_key) BETWEEN 1 AND 4096
  )),
  CHECK (parent_path IS NOT DISTINCT FROM CASE
    WHEN position('/' in path)>0 THEN regexp_replace(path,'/[^/]+$','')
    ELSE NULL
  END),
  CHECK (
    (entry_kind='directory' AND git_mode=16384
      AND size_bytes=0 AND version_id IS NULL)
    OR (entry_kind='file' AND git_mode=33188 AND version_id IS NOT NULL)
  )
);

CREATE TABLE filebelt_revision.managed_repository_ref_operation_updates (
  tenant_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  repository_id uuid NOT NULL,
  object_format text NOT NULL,
  ref_name text NOT NULL,
  expected_generation bigint NOT NULL CHECK (expected_generation>=0),
  expected_oid bytea,
  new_oid bytea NOT NULL,
  change_kind text NOT NULL CHECK (change_kind IN ('create','fast_forward','force')),
  snapshot_id uuid,
  PRIMARY KEY (tenant_id,operation_id,ref_name),
  FOREIGN KEY (tenant_id,operation_id,repository_id)
    REFERENCES filebelt_revision.managed_repository_ref_operations(tenant_id,id,repository_id)
    ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,repository_id,ref_name,object_format)
    REFERENCES filebelt_revision.managed_repository_refs(
      tenant_id,repository_id,ref_name,object_format
    ),
  FOREIGN KEY (tenant_id,snapshot_id,repository_id,object_format)
    REFERENCES filebelt_revision.managed_repository_snapshots(
      tenant_id,id,repository_id,object_format
    ),
  CHECK (
    (object_format='sha1'
      AND (expected_oid IS NULL OR octet_length(expected_oid)=20)
      AND octet_length(new_oid)=20)
    OR (object_format='sha256'
      AND (expected_oid IS NULL OR octet_length(expected_oid)=32)
      AND octet_length(new_oid)=32)
  ),
  CHECK ((change_kind='create')=(expected_oid IS NULL)),
  CHECK ((ref_name='refs/heads/main')=(snapshot_id IS NOT NULL))
);

CREATE TABLE filebelt_revision.managed_repository_rulesets (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  repository_id uuid NOT NULL,
  target_ref_name text NOT NULL,
  name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 128),
  priority integer NOT NULL DEFAULT 100 CHECK (priority BETWEEN 0 AND 10000),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','disabled')),
  require_pull_request boolean NOT NULL DEFAULT false,
  required_approvals integer NOT NULL DEFAULT 0 CHECK (required_approvals=0),
  require_status_checks boolean NOT NULL DEFAULT false,
  require_deployments boolean NOT NULL DEFAULT false,
  dismiss_stale_reviews boolean NOT NULL DEFAULT true,
  block_force_push boolean NOT NULL DEFAULT true,
  block_deletion boolean NOT NULL DEFAULT true,
  require_linear_history boolean NOT NULL DEFAULT true,
  generation bigint NOT NULL DEFAULT 1 CHECK (generation>0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,repository_id,name),
  UNIQUE (tenant_id,id,repository_id),
  FOREIGN KEY (tenant_id,repository_id,target_ref_name)
    REFERENCES filebelt_revision.managed_repository_refs(
      tenant_id,repository_id,ref_name
    ),
  CHECK (NOT require_pull_request),
  CHECK (NOT require_deployments)
);

CREATE TABLE filebelt_revision.managed_repository_required_checks (
  tenant_id uuid NOT NULL,
  ruleset_id uuid NOT NULL,
  repository_id uuid NOT NULL,
  check_name text NOT NULL CHECK (
    octet_length(check_name) BETWEEN 1 AND 128
  ),
  PRIMARY KEY (tenant_id,ruleset_id,check_name),
  FOREIGN KEY (tenant_id,ruleset_id,repository_id)
    REFERENCES filebelt_revision.managed_repository_rulesets(
      tenant_id,id,repository_id
    ) ON DELETE CASCADE
);

CREATE TABLE filebelt_revision.managed_repository_check_runs (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  repository_id uuid NOT NULL,
  object_format text NOT NULL,
  commit_oid bytea NOT NULL,
  check_name text NOT NULL CHECK (
    octet_length(check_name) BETWEEN 1 AND 128
  ),
  attempt integer NOT NULL CHECK (attempt>0),
  state text NOT NULL CHECK (
    state IN ('queued','in_progress','success','failure','cancelled','timed_out')
  ),
  details_digest bytea CHECK (details_digest IS NULL OR octet_length(details_digest)=32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,repository_id,commit_oid,check_name,attempt),
  FOREIGN KEY (tenant_id,repository_id,object_format)
    REFERENCES filebelt_revision.managed_repositories(tenant_id,id,object_format),
  CHECK (
    (object_format='sha1' AND octet_length(commit_oid)=20)
    OR (object_format='sha256' AND octet_length(commit_oid)=32)
  ),
  CHECK (
    (state IN ('success','failure','cancelled','timed_out'))=(completed_at IS NOT NULL)
  )
);

CREATE TABLE filebelt_revision.managed_repository_reconciliations (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  repository_id uuid NOT NULL,
  operation_id uuid,
  kind text NOT NULL CHECK (kind IN ('object_integrity','ref_projection','quota','retention')),
  state text NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending','leased','verified','held')),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count>=0),
  fencing_token bigint NOT NULL DEFAULT 1 CHECK (fencing_token>0),
  lease_owner uuid,
  lease_expires_at timestamptz,
  next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,repository_id,operation_id,kind),
  FOREIGN KEY (tenant_id,repository_id)
    REFERENCES filebelt_revision.managed_repositories(tenant_id,id),
  FOREIGN KEY (tenant_id,operation_id,repository_id)
    REFERENCES filebelt_revision.managed_repository_ref_operations(tenant_id,id,repository_id),
  CHECK ((state='leased')=(lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL))
);
CREATE INDEX managed_repository_reconciliation_ready
  ON filebelt_revision.managed_repository_reconciliations(
    tenant_id,next_attempt_at,repository_id,id
  ) WHERE state='pending';

CREATE FUNCTION filebelt_revision.enforce_managed_repository_root()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,public,filebelt_revision
AS $$
DECLARE
  v_kind text;
  v_trash_root_id uuid;
BEGIN
  IF TG_OP='UPDATE' AND NEW.object_format IS DISTINCT FROM OLD.object_format THEN
    RAISE EXCEPTION USING ERRCODE='55000',
      MESSAGE='managed repository object format is immutable';
  END IF;

  PERFORM 1 FROM public.drives
  WHERE tenant_id=NEW.tenant_id AND id=NEW.drive_id
  FOR UPDATE;

  SELECT kind,trash_root_id INTO v_kind,v_trash_root_id
  FROM public.nodes
  WHERE tenant_id=NEW.tenant_id AND drive_id=NEW.drive_id AND id=NEW.root_node_id
  FOR KEY SHARE;
  IF NOT FOUND OR v_kind<>'directory' OR v_trash_root_id IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE='23514',
      MESSAGE='managed repository root must be a live directory on its drive';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM filebelt_revision.managed_repositories AS existing
    JOIN public.node_ancestry AS ancestry
      ON ancestry.tenant_id=existing.tenant_id
     AND ancestry.drive_id=existing.drive_id
     AND ancestry.depth>0
     AND (
       (ancestry.ancestor_id=existing.root_node_id
         AND ancestry.descendant_id=NEW.root_node_id)
       OR (ancestry.ancestor_id=NEW.root_node_id
         AND ancestry.descendant_id=existing.root_node_id)
     )
    WHERE existing.tenant_id=NEW.tenant_id
      AND existing.drive_id=NEW.drive_id
      AND existing.id<>NEW.id
      AND existing.state<>'deleted'
  ) THEN
    RAISE EXCEPTION USING ERRCODE='23514',
      MESSAGE='managed repository roots cannot be nested';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER managed_repository_root_guard
BEFORE INSERT OR UPDATE OF tenant_id,drive_id,root_node_id,object_format
ON filebelt_revision.managed_repositories
FOR EACH ROW EXECUTE FUNCTION filebelt_revision.enforce_managed_repository_root();

CREATE FUNCTION filebelt_revision.seed_managed_repository_defaults()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,filebelt_revision
AS $$
BEGIN
  INSERT INTO filebelt_revision.managed_repository_refs(
    tenant_id,repository_id,object_format,ref_name,namespace_projection
  ) VALUES (
    NEW.tenant_id,NEW.id,NEW.object_format,'refs/heads/main',true
  );
  INSERT INTO filebelt_revision.managed_repository_rulesets(
    tenant_id,id,repository_id,target_ref_name,name,
    require_pull_request,required_approvals,require_status_checks,
    require_deployments,dismiss_stale_reviews,block_force_push,
    block_deletion,require_linear_history
  ) VALUES (
    NEW.tenant_id,NEW.id,NEW.id,'refs/heads/main','default-main',
    false,0,false,false,true,true,true,true
  );
  RETURN NEW;
END
$$;
CREATE TRIGGER managed_repository_defaults
AFTER INSERT ON filebelt_revision.managed_repositories
FOR EACH ROW EXECUTE FUNCTION filebelt_revision.seed_managed_repository_defaults();

CREATE FUNCTION filebelt_revision.enforce_managed_repository_operation_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog
AS $$
BEGIN
  IF OLD.state<>'prepared' OR NEW.state NOT IN ('committed','aborted','held') THEN
    RAISE EXCEPTION USING ERRCODE='55000',
      MESSAGE='invalid managed repository operation transition';
  END IF;
  IF NEW.terminal_at IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='23514',
      MESSAGE='terminal managed repository operation requires terminal_at';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER managed_repository_operation_transition
BEFORE UPDATE OF state
ON filebelt_revision.managed_repository_ref_operations
FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state)
EXECUTE FUNCTION filebelt_revision.enforce_managed_repository_operation_transition();

CREATE FUNCTION filebelt_revision.finalize_managed_repository_operation(
  p_tenant_id uuid,
  p_repository_id uuid,
  p_operation_id uuid
)
RETURNS bigint
LANGUAGE plpgsql
SET search_path=pg_catalog,public,filebelt_revision
AS $$
DECLARE
  v_operation filebelt_revision.managed_repository_ref_operations%ROWTYPE;
  v_repository filebelt_revision.managed_repositories%ROWTYPE;
  v_actor_generation bigint;
  v_drive_acl_generation bigint;
  v_namespace_generation bigint;
  v_root_acl_generation bigint;
  v_update_count bigint;
BEGIN
  SELECT operation.* INTO v_operation
  FROM filebelt_revision.managed_repository_ref_operations AS operation
  WHERE operation.tenant_id=p_tenant_id
    AND operation.repository_id=p_repository_id
    AND operation.id=p_operation_id
  FOR UPDATE;
  IF NOT FOUND OR v_operation.state<>'prepared' THEN
    RAISE EXCEPTION USING ERRCODE='FBR02',
      MESSAGE='managed repository operation is not prepared';
  END IF;

  SELECT repository.* INTO v_repository
  FROM filebelt_revision.managed_repositories AS repository
  WHERE repository.tenant_id=p_tenant_id AND repository.id=p_repository_id
  FOR UPDATE;
  IF NOT FOUND OR v_repository.state<>'active'
     OR v_operation.expires_at<=clock_timestamp() THEN
    RAISE EXCEPTION USING ERRCODE='FBR02',
      MESSAGE='managed repository writer admission is closed';
  END IF;

  SELECT principal.generation,drive.acl_generation,drive.namespace_generation,
         root.acl_generation
  INTO v_actor_generation,v_drive_acl_generation,v_namespace_generation,
       v_root_acl_generation
  FROM public.principals AS principal
  JOIN public.drives AS drive
    ON drive.tenant_id=principal.tenant_id
   AND drive.id=v_repository.drive_id
  JOIN public.nodes AS root
    ON root.tenant_id=drive.tenant_id
   AND root.drive_id=drive.id
   AND root.id=v_repository.root_node_id
  WHERE principal.tenant_id=p_tenant_id
    AND principal.id=v_operation.actor_principal_id
    AND principal.disabled_at IS NULL
    AND root.kind='directory'
    AND root.trash_root_id IS NULL
  FOR UPDATE OF principal,drive,root;
  IF NOT FOUND
     OR v_operation.expected_repository_generation<>v_repository.generation
     OR v_operation.expected_actor_generation<>v_actor_generation
     OR v_operation.expected_drive_acl_generation<>v_drive_acl_generation
     OR v_operation.expected_namespace_generation<>v_namespace_generation
     OR v_operation.expected_root_acl_generation<>v_root_acl_generation THEN
    RAISE EXCEPTION USING ERRCODE='FBR01',
      MESSAGE='managed repository authorization or namespace generation is stale';
  END IF;

  -- Existing namespace writers remain unchanged in this compatibility
  -- release.  Recheck the root relationship at the activation boundary so a
  -- concurrent or out-of-band move can never make a nested root writable.
  IF EXISTS (
    SELECT 1
    FROM filebelt_revision.managed_repositories AS existing
    JOIN public.node_ancestry AS ancestry
      ON ancestry.tenant_id=existing.tenant_id
     AND ancestry.drive_id=existing.drive_id
     AND ancestry.depth>0
     AND (
       (ancestry.ancestor_id=existing.root_node_id
         AND ancestry.descendant_id=v_repository.root_node_id)
       OR (ancestry.ancestor_id=v_repository.root_node_id
         AND ancestry.descendant_id=existing.root_node_id)
     )
    WHERE existing.tenant_id=p_tenant_id
      AND existing.drive_id=v_repository.drive_id
      AND existing.id<>p_repository_id
      AND existing.state<>'deleted'
  ) THEN
    RAISE EXCEPTION USING ERRCODE='FBR02',
      MESSAGE='managed repository roots cannot be nested';
  END IF;

  SELECT count(*) INTO v_update_count
  FROM filebelt_revision.managed_repository_ref_operation_updates
  WHERE tenant_id=p_tenant_id AND repository_id=p_repository_id
    AND operation_id=p_operation_id;
  IF v_update_count=0 THEN
    RAISE EXCEPTION USING ERRCODE='FBR02',
      MESSAGE='managed repository operation has no ref updates';
  END IF;

  PERFORM reference.ref_name
  FROM filebelt_revision.managed_repository_refs AS reference
  JOIN filebelt_revision.managed_repository_ref_operation_updates AS update_row
    ON update_row.tenant_id=reference.tenant_id
   AND update_row.repository_id=reference.repository_id
   AND update_row.ref_name=reference.ref_name
  WHERE update_row.tenant_id=p_tenant_id
    AND update_row.repository_id=p_repository_id
    AND update_row.operation_id=p_operation_id
  ORDER BY reference.ref_name
  FOR UPDATE OF reference;

  IF (SELECT count(*)
      FROM filebelt_revision.managed_repository_refs AS reference
      JOIN filebelt_revision.managed_repository_ref_operation_updates AS update_row
        ON update_row.tenant_id=reference.tenant_id
       AND update_row.repository_id=reference.repository_id
       AND update_row.ref_name=reference.ref_name
      WHERE update_row.tenant_id=p_tenant_id
        AND update_row.repository_id=p_repository_id
        AND update_row.operation_id=p_operation_id
        AND reference.state='approved'
        AND reference.generation=update_row.expected_generation
        AND reference.oid IS NOT DISTINCT FROM update_row.expected_oid
     )<>v_update_count THEN
    RAISE EXCEPTION USING ERRCODE='FBR01',
      MESSAGE='managed repository ref compare-and-swap failed';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM filebelt_revision.managed_repository_ref_operation_updates AS update_row
    LEFT JOIN filebelt_revision.managed_repository_snapshots AS snapshot
      ON snapshot.tenant_id=update_row.tenant_id
     AND snapshot.repository_id=update_row.repository_id
     AND snapshot.id=update_row.snapshot_id
    WHERE update_row.tenant_id=p_tenant_id
      AND update_row.repository_id=p_repository_id
      AND update_row.operation_id=p_operation_id
      AND update_row.ref_name='refs/heads/main'
      AND (snapshot.id IS NULL OR snapshot.operation_id<>p_operation_id
        OR snapshot.state<>'prepared'
        OR snapshot.commit_oid<>update_row.new_oid
        OR snapshot.tree_entry_count<>(
          SELECT count(*)
          FROM filebelt_revision.managed_repository_snapshot_entries AS entry
          WHERE entry.tenant_id=snapshot.tenant_id
            AND entry.snapshot_id=snapshot.id
        ))
  ) THEN
    RAISE EXCEPTION USING ERRCODE='FBR02',
      MESSAGE='managed repository main snapshot is incomplete';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM filebelt_revision.managed_repository_snapshot_entries AS entry
    JOIN filebelt_revision.managed_repository_snapshots AS snapshot
      ON snapshot.tenant_id=entry.tenant_id AND snapshot.id=entry.snapshot_id
    LEFT JOIN filebelt_revision.managed_repository_snapshot_entries AS parent
      ON parent.tenant_id=entry.tenant_id
     AND parent.snapshot_id=entry.snapshot_id
     AND parent.path=entry.parent_path
     AND parent.path_key=entry.parent_path_key
     AND parent.entry_kind='directory'
    LEFT JOIN filebelt_revision.managed_repository_file_versions AS version
      ON version.tenant_id=entry.tenant_id AND version.id=entry.version_id
    LEFT JOIN filebelt_revision.managed_repository_contents AS content
      ON content.tenant_id=version.tenant_id AND content.id=version.content_id
    WHERE snapshot.tenant_id=p_tenant_id
      AND snapshot.repository_id=p_repository_id
      AND snapshot.operation_id=p_operation_id
      AND (
        (entry.parent_path IS NOT NULL AND parent.path_key IS NULL)
        OR (entry.entry_kind='file' AND (
          version.id IS NULL OR version.state<>'prepared'
          OR version.snapshot_id<>snapshot.id
          OR version.source_commit_oid<>snapshot.commit_oid
          OR version.source_path_key<>entry.path_key
          OR content.id IS NULL OR content.state NOT IN ('staged','referenced')
          OR content.blob_oid<>entry.object_oid
          OR content.size_bytes<>entry.size_bytes
        ))
      )
  ) THEN
    RAISE EXCEPTION USING ERRCODE='FBR02',
      MESSAGE='managed repository snapshot entries are inconsistent';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM filebelt_revision.managed_repository_ref_operation_updates AS update_row
    JOIN filebelt_revision.managed_repository_rulesets AS ruleset
      ON ruleset.tenant_id=update_row.tenant_id
     AND ruleset.repository_id=update_row.repository_id
     AND ruleset.target_ref_name=update_row.ref_name
     AND ruleset.state='active'
    WHERE update_row.tenant_id=p_tenant_id
      AND update_row.repository_id=p_repository_id
      AND update_row.operation_id=p_operation_id
      AND (
        (ruleset.block_force_push AND update_row.change_kind='force')
        OR (ruleset.require_linear_history
          AND update_row.change_kind NOT IN ('create','fast_forward'))
        OR (ruleset.require_status_checks AND EXISTS (
          SELECT 1
          FROM filebelt_revision.managed_repository_required_checks AS required
          WHERE required.tenant_id=ruleset.tenant_id
            AND required.ruleset_id=ruleset.id
            AND NOT EXISTS (
              SELECT 1
              FROM filebelt_revision.managed_repository_check_runs AS check_run
              WHERE check_run.tenant_id=update_row.tenant_id
                AND check_run.repository_id=update_row.repository_id
                AND check_run.commit_oid=update_row.new_oid
                AND check_run.check_name=required.check_name
                AND check_run.state='success'
                AND check_run.attempt=(
                  SELECT max(latest.attempt)
                  FROM filebelt_revision.managed_repository_check_runs AS latest
                  WHERE latest.tenant_id=check_run.tenant_id
                    AND latest.repository_id=check_run.repository_id
                    AND latest.commit_oid=check_run.commit_oid
                    AND latest.check_name=check_run.check_name
                )
            )
        ))
      )
  ) THEN
    RAISE EXCEPTION USING ERRCODE='FBR03',
      MESSAGE='managed repository rules are not satisfied';
  END IF;

  UPDATE filebelt_revision.managed_repository_refs AS reference
  SET oid=update_row.new_oid,
      generation=reference.generation+1,
      projected_snapshot_id=update_row.snapshot_id,
      updated_at=clock_timestamp()
  FROM filebelt_revision.managed_repository_ref_operation_updates AS update_row
  WHERE update_row.tenant_id=p_tenant_id
    AND update_row.repository_id=p_repository_id
    AND update_row.operation_id=p_operation_id
    AND reference.tenant_id=update_row.tenant_id
    AND reference.repository_id=update_row.repository_id
    AND reference.ref_name=update_row.ref_name;

  UPDATE filebelt_revision.managed_repository_snapshots
  SET state='projected',projected_at=clock_timestamp()
  WHERE tenant_id=p_tenant_id AND repository_id=p_repository_id
    AND operation_id=p_operation_id AND state='prepared';
  UPDATE filebelt_revision.managed_repository_file_versions AS version
  SET state='projected',projected_at=clock_timestamp()
  FROM filebelt_revision.managed_repository_snapshots AS snapshot
  WHERE snapshot.tenant_id=p_tenant_id
    AND snapshot.repository_id=p_repository_id
    AND snapshot.operation_id=p_operation_id
    AND version.tenant_id=snapshot.tenant_id
    AND version.snapshot_id=snapshot.id
    AND version.state='prepared';
  UPDATE filebelt_revision.managed_repository_contents AS content
  SET state='referenced',referenced_at=COALESCE(referenced_at,clock_timestamp())
  WHERE content.tenant_id=p_tenant_id
    AND content.repository_id=p_repository_id
    AND content.state='staged'
    AND EXISTS (
      SELECT 1
      FROM filebelt_revision.managed_repository_file_versions AS version
      JOIN filebelt_revision.managed_repository_snapshots AS snapshot
        ON snapshot.tenant_id=version.tenant_id
       AND snapshot.id=version.snapshot_id
      WHERE version.tenant_id=content.tenant_id
        AND version.content_id=content.id
        AND snapshot.operation_id=p_operation_id
    );

  UPDATE filebelt_revision.managed_repository_ref_operations
  SET state='committed',terminal_at=clock_timestamp(),failure_code=NULL
  WHERE tenant_id=p_tenant_id AND repository_id=p_repository_id
    AND id=p_operation_id AND state='prepared';
  UPDATE filebelt_revision.managed_repositories
  SET generation=generation+1,updated_at=clock_timestamp()
  WHERE tenant_id=p_tenant_id AND id=p_repository_id;

  INSERT INTO filebelt_revision.managed_repository_reconciliations(
    tenant_id,id,repository_id,operation_id,kind
  ) VALUES
    (p_tenant_id,gen_random_uuid(),p_repository_id,p_operation_id,'object_integrity'),
    (p_tenant_id,gen_random_uuid(),p_repository_id,p_operation_id,'ref_projection'),
    (p_tenant_id,gen_random_uuid(),p_repository_id,p_operation_id,'quota'),
    (p_tenant_id,gen_random_uuid(),p_repository_id,p_operation_id,'retention');

  RETURN v_repository.generation+1;
END
$$;

REVOKE ALL ON FUNCTION filebelt_revision.enforce_managed_repository_root()
  FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_revision.seed_managed_repository_defaults()
  FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_revision.enforce_managed_repository_operation_transition()
  FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_revision.finalize_managed_repository_operation(uuid,uuid,uuid)
  FROM PUBLIC;
