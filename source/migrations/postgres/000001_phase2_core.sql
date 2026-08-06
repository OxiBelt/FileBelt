-- SPDX-License-Identifier: Apache-2.0

CREATE TABLE tenants (
  id uuid PRIMARY KEY,
  slug text NOT NULL UNIQUE CHECK (slug = lower(slug) AND slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE principals (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('user','group','service','share_link')),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  disabled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id)
);

CREATE TABLE users (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  principal_id uuid NOT NULL,
  display_name text NOT NULL,
  verified_email text,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,principal_id),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id)
);
CREATE UNIQUE INDEX users_verified_email_unique ON users (tenant_id,lower(verified_email)) WHERE verified_email IS NOT NULL;

CREATE TABLE external_identities (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  user_id uuid NOT NULL,
  issuer text NOT NULL,
  subject text NOT NULL,
  claims_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  disabled_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,issuer,subject),
  UNIQUE (tenant_id,user_id),
  FOREIGN KEY (tenant_id,user_id) REFERENCES users(tenant_id,id)
);

CREATE TABLE tenant_admin_bindings (
  tenant_id uuid NOT NULL REFERENCES tenants(id), issuer text NOT NULL, subject text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,issuer,subject)
);

CREATE TABLE groups (
  tenant_id uuid NOT NULL, id uuid NOT NULL, principal_id uuid NOT NULL,
  display_name text NOT NULL, name_key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,principal_id), UNIQUE (tenant_id,name_key),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id)
);

CREATE TABLE group_memberships (
  tenant_id uuid NOT NULL, group_id uuid NOT NULL, user_principal_id uuid NOT NULL,
  role text NOT NULL CHECK (role IN ('member','manager')),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,group_id,user_principal_id),
  FOREIGN KEY (tenant_id,group_id) REFERENCES groups(tenant_id,id),
  FOREIGN KEY (tenant_id,user_principal_id) REFERENCES principals(tenant_id,id)
);

CREATE TABLE drives (
  tenant_id uuid NOT NULL, id uuid NOT NULL, owner_principal_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('private','shared')), display_name text NOT NULL,
  namespace_generation bigint NOT NULL DEFAULT 1 CHECK (namespace_generation > 0),
  acl_generation bigint NOT NULL DEFAULT 1 CHECK (acl_generation > 0),
  quota_bytes bigint NOT NULL CHECK (quota_bytes >= 1073741824),
  used_physical_bytes bigint NOT NULL DEFAULT 0 CHECK (used_physical_bytes >= 0),
  reserved_bytes bigint NOT NULL DEFAULT 0 CHECK (reserved_bytes >= 0),
  trash_retention_days integer NOT NULL DEFAULT 30 CHECK (trash_retention_days BETWEEN 1 AND 90),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id,owner_principal_id) REFERENCES principals(tenant_id,id),
  CHECK (used_physical_bytes + reserved_bytes <= quota_bytes)
);

CREATE TABLE nodes (
  tenant_id uuid NOT NULL, drive_id uuid NOT NULL, id uuid NOT NULL, parent_id uuid,
  kind text NOT NULL CHECK (kind IN ('file','directory')),
  display_name text NOT NULL, name_key text NOT NULL, head_version_id uuid,
  namespace_generation bigint NOT NULL DEFAULT 1 CHECK (namespace_generation > 0),
  acl_generation bigint NOT NULL DEFAULT 1 CHECK (acl_generation > 0),
  trash_root_id uuid, trashed_original_parent_id uuid, trashed_original_name text,
  trashed_original_name_key text, purge_after timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,drive_id) REFERENCES drives(tenant_id,id),
  FOREIGN KEY (tenant_id,drive_id,parent_id) REFERENCES nodes(tenant_id,drive_id,id),
  CHECK ((parent_id IS NULL) = (display_name = '')),
  CHECK (kind = 'file' OR head_version_id IS NULL)
);
ALTER TABLE nodes ADD CONSTRAINT nodes_trash_root_fk FOREIGN KEY (tenant_id,drive_id,trash_root_id) REFERENCES nodes(tenant_id,drive_id,id);
CREATE UNIQUE INDEX drives_one_root ON nodes (tenant_id,drive_id) WHERE parent_id IS NULL;
CREATE UNIQUE INDEX nodes_live_name_unique ON nodes (tenant_id,drive_id,parent_id,name_key) WHERE trash_root_id IS NULL;

CREATE TABLE node_ancestry (
  tenant_id uuid NOT NULL, drive_id uuid NOT NULL, ancestor_id uuid NOT NULL, descendant_id uuid NOT NULL,
  depth integer NOT NULL CHECK (depth BETWEEN 0 AND 128),
  PRIMARY KEY (tenant_id,drive_id,ancestor_id,descendant_id),
  UNIQUE (tenant_id,drive_id,descendant_id,depth),
  FOREIGN KEY (tenant_id,drive_id,ancestor_id) REFERENCES nodes(tenant_id,drive_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,drive_id,descendant_id) REFERENCES nodes(tenant_id,drive_id,id) ON DELETE CASCADE,
  CHECK ((depth = 0) = (ancestor_id = descendant_id))
);

CREATE TABLE acl_entries (
  tenant_id uuid NOT NULL, drive_id uuid NOT NULL, resource_id uuid NOT NULL, id uuid NOT NULL,
  principal_id uuid NOT NULL, action text NOT NULL,
  effect text NOT NULL CHECK (effect IN ('allow','deny')),
  inheritance text NOT NULL CHECK (inheritance IN ('self','descendants','self_and_descendants')),
  created_by uuid NOT NULL, generation bigint NOT NULL CHECK (generation > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,resource_id,principal_id,action,inheritance),
  FOREIGN KEY (tenant_id,drive_id,resource_id) REFERENCES nodes(tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,created_by) REFERENCES principals(tenant_id,id)
);

CREATE TABLE api_sessions (
  tenant_id uuid NOT NULL, id uuid NOT NULL, user_id uuid NOT NULL, principal_id uuid NOT NULL,
  token_key_generation integer NOT NULL CHECK (token_key_generation > 0), token_digest bytea NOT NULL,
  csrf_digest bytea NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(), idle_expires_at timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL, reauthenticated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at timestamptz, user_agent text,
  PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,token_key_generation,token_digest),
  FOREIGN KEY (tenant_id,user_id) REFERENCES users(tenant_id,id),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id),
  CHECK (idle_expires_at <= absolute_expires_at)
);

CREATE TABLE oidc_login_attempts (
  tenant_id uuid NOT NULL REFERENCES tenants(id), id uuid NOT NULL,
  state_digest bytea NOT NULL, nonce_digest bytea NOT NULL, pkce_verifier_digest bytea NOT NULL,
  nonce_secret text NOT NULL, pkce_verifier_secret text NOT NULL,
  return_path text NOT NULL, session_id uuid, expires_at timestamptz NOT NULL, consumed_at timestamptz,
  PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,state_digest)
);
CREATE INDEX oidc_login_attempts_retention_index
  ON oidc_login_attempts (tenant_id,expires_at,consumed_at);

CREATE TABLE user_preferences (
  tenant_id uuid NOT NULL, user_id uuid NOT NULL,
  theme text NOT NULL DEFAULT 'system' CHECK (theme IN ('system','light','dark')),
  private_trash_retention_days integer NOT NULL DEFAULT 30 CHECK (private_trash_retention_days BETWEEN 1 AND 90),
  notify_privacy_actions boolean NOT NULL DEFAULT true,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,user_id), FOREIGN KEY (tenant_id,user_id) REFERENCES users(tenant_id,id)
);

CREATE TABLE storage_backends (
  tenant_id uuid NOT NULL REFERENCES tenants(id), id uuid NOT NULL,
  kind text NOT NULL DEFAULT 'posix' CHECK (kind = 'posix'),
  capacity_total_bytes bigint, capacity_free_bytes bigint,
  capacity_checked_at timestamptz, storage_ready boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,kind),
  CHECK (capacity_total_bytes IS NULL OR capacity_total_bytes > 0),
  CHECK (capacity_free_bytes IS NULL OR capacity_free_bytes >= 0),
  CHECK (capacity_total_bytes IS NULL OR capacity_free_bytes IS NULL OR capacity_free_bytes <= capacity_total_bytes),
  CHECK (NOT storage_ready OR (capacity_total_bytes IS NOT NULL AND capacity_free_bytes IS NOT NULL AND capacity_checked_at IS NOT NULL))
);

CREATE TABLE payload_objects (
  tenant_id uuid NOT NULL, id uuid NOT NULL, drive_id uuid NOT NULL, backend_id uuid NOT NULL,
  locator uuid NOT NULL, layout text NOT NULL CHECK (layout IN ('whole','chunked')),
  state text NOT NULL CHECK (state IN ('staging','finalizing','finalized','referenced','abandoned','delete_intent','deleting','deleted','quarantining','quarantined')),
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0), blake3 bytea,
  finalized_at timestamptz, referenced_at timestamptz, deletion_intent_at timestamptz,
  quarantine_reason text, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,backend_id,locator),
  FOREIGN KEY (tenant_id,drive_id) REFERENCES drives(tenant_id,id),
  FOREIGN KEY (tenant_id,backend_id) REFERENCES storage_backends(tenant_id,id),
  CHECK (state NOT IN ('finalized','referenced','delete_intent','deleting','deleted','quarantining','quarantined') OR blake3 IS NOT NULL)
);

CREATE TABLE upload_sessions (
  tenant_id uuid NOT NULL, id uuid NOT NULL, drive_id uuid NOT NULL, node_id uuid, parent_id uuid NOT NULL,
  owner_principal_id uuid NOT NULL, payload_id uuid NOT NULL, expected_head_version_id uuid,
  target_display_name text NOT NULL, target_name_key text NOT NULL,
  declared_size_bytes bigint NOT NULL CHECK (declared_size_bytes >= 0),
  chunk_size_bytes integer NOT NULL CHECK (chunk_size_bytes > 0), part_count integer NOT NULL CHECK (part_count > 0),
  state text NOT NULL CHECK (state IN ('open','finalizing','finalized','committed','aborted','expired')),
  fencing_token bigint NOT NULL DEFAULT 1 CHECK (fencing_token > 0), expires_at timestamptz NOT NULL,
  finalization_owner uuid, finalization_lease_expires_at timestamptz,
  staging_cleaned_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id,drive_id) REFERENCES drives(tenant_id,id),
  FOREIGN KEY (tenant_id,drive_id,node_id) REFERENCES nodes(tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,drive_id,parent_id) REFERENCES nodes(tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,owner_principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,payload_id) REFERENCES payload_objects(tenant_id,id),
  CHECK (staging_cleaned_at IS NULL OR state IN ('finalized','committed')),
  CHECK ((state = 'finalizing') =
    (finalization_owner IS NOT NULL AND finalization_lease_expires_at IS NOT NULL))
);
CREATE INDEX uploads_staging_cleanup_index ON upload_sessions (tenant_id,created_at)
  WHERE state IN ('finalized','committed') AND staging_cleaned_at IS NULL;
CREATE INDEX uploads_finalization_lease_index
  ON upload_sessions (tenant_id,finalization_lease_expires_at)
  WHERE state = 'finalizing';

CREATE TABLE upload_parts (
  tenant_id uuid NOT NULL, upload_id uuid NOT NULL, part_number integer NOT NULL CHECK (part_number >= 0),
  state text NOT NULL CHECK (state IN ('allocated','writing','durable')),
  size_bytes integer NOT NULL CHECK (size_bytes >= 0), blake3 bytea, locator uuid NOT NULL, durable_at timestamptz,
  PRIMARY KEY (tenant_id,upload_id,part_number), UNIQUE (tenant_id,locator),
  FOREIGN KEY (tenant_id,upload_id) REFERENCES upload_sessions(tenant_id,id) ON DELETE CASCADE
);

CREATE TABLE file_versions (
  tenant_id uuid NOT NULL, node_id uuid NOT NULL, id uuid NOT NULL,
  ordinal bigint NOT NULL CHECK (ordinal > 0), payload_id uuid NOT NULL,
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0), blake3 bytea NOT NULL, media_type text,
  created_by uuid NOT NULL, restored_from_version_id uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,node_id,id), UNIQUE (tenant_id,node_id,ordinal),
  FOREIGN KEY (tenant_id,payload_id) REFERENCES payload_objects(tenant_id,id),
  FOREIGN KEY (tenant_id,created_by) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,restored_from_version_id) REFERENCES file_versions(tenant_id,id)
);
ALTER TABLE nodes ADD CONSTRAINT nodes_head_version_fk FOREIGN KEY (tenant_id,id,head_version_id) REFERENCES file_versions(tenant_id,node_id,id);

CREATE TABLE quota_reservations (
  tenant_id uuid NOT NULL, id uuid NOT NULL, drive_id uuid NOT NULL, upload_id uuid NOT NULL,
  bytes bigint NOT NULL CHECK (bytes >= 0), state text NOT NULL CHECK (state IN ('active','committed','released')),
  expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,upload_id),
  FOREIGN KEY (tenant_id,drive_id) REFERENCES drives(tenant_id,id),
  FOREIGN KEY (tenant_id,upload_id) REFERENCES upload_sessions(tenant_id,id)
);

CREATE TABLE share_links (
  tenant_id uuid NOT NULL, id uuid NOT NULL, principal_id uuid NOT NULL, drive_id uuid NOT NULL,
  resource_id uuid NOT NULL, token_key_generation integer NOT NULL CHECK (token_key_generation > 0),
  token_digest bytea NOT NULL, password_hash text, expires_at timestamptz NOT NULL,
  revocation_generation bigint NOT NULL DEFAULT 1 CHECK (revocation_generation > 0), revoked_at timestamptz,
  created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,token_key_generation,token_digest),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,drive_id,resource_id) REFERENCES nodes(tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,created_by) REFERENCES principals(tenant_id,id),
  CHECK (expires_at <= created_at + interval '30 days')
);

CREATE TABLE direct_shares (
  tenant_id uuid NOT NULL, id uuid NOT NULL, drive_id uuid NOT NULL, resource_id uuid NOT NULL,
  target_principal_id uuid NOT NULL, preset text NOT NULL CHECK (preset IN ('viewer','contributor','manager')),
  inheritance text NOT NULL CHECK (inheritance IN ('self','self_and_descendants')),
  created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), revoked_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id,drive_id,resource_id) REFERENCES nodes(tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,target_principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,created_by) REFERENCES principals(tenant_id,id)
);
CREATE UNIQUE INDEX direct_shares_active_target
  ON direct_shares (tenant_id,resource_id,target_principal_id) WHERE revoked_at IS NULL;
ALTER TABLE acl_entries ADD COLUMN direct_share_id uuid;
ALTER TABLE acl_entries ADD CONSTRAINT acl_entries_direct_share_fk
  FOREIGN KEY (tenant_id,direct_share_id) REFERENCES direct_shares(tenant_id,id);

CREATE TABLE capability_nonces (
  tenant_id uuid NOT NULL REFERENCES tenants(id), nonce_digest bytea NOT NULL,
  operation text NOT NULL, expires_at timestamptz NOT NULL, consumed_at timestamptz,
  PRIMARY KEY (tenant_id,nonce_digest)
);
CREATE INDEX capability_nonces_expiry_index ON capability_nonces (tenant_id,expires_at);

CREATE TABLE authorization_generations (
  tenant_id uuid NOT NULL, session_id uuid NOT NULL, principal_id uuid NOT NULL, drive_id uuid NOT NULL, resource_id uuid NOT NULL,
  membership_generation bigint NOT NULL CHECK (membership_generation > 0),
  drive_acl_generation bigint NOT NULL CHECK (drive_acl_generation > 0),
  namespace_generation bigint NOT NULL CHECK (namespace_generation > 0),
  resource_acl_generation bigint NOT NULL CHECK (resource_acl_generation > 0),
  session_expires_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,session_id,principal_id,resource_id),
  FOREIGN KEY (tenant_id,session_id) REFERENCES api_sessions(tenant_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,drive_id,resource_id) REFERENCES nodes(tenant_id,drive_id,id)
);

-- Capability generation projections are invalidated at the same database
-- boundary as every authority-changing row. ACL changes also advance the
-- locked drive/resource generations, which prevents a concurrent stale API
-- snapshot from being republished after invalidation.
CREATE FUNCTION invalidate_acl_capability_projection() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  changed_tenant uuid := COALESCE(NEW.tenant_id,OLD.tenant_id);
  changed_drive uuid := COALESCE(NEW.drive_id,OLD.drive_id);
  changed_resource uuid := COALESCE(NEW.resource_id,OLD.resource_id);
BEGIN
  UPDATE drives SET acl_generation=acl_generation+1
    WHERE tenant_id=changed_tenant AND id=changed_drive;
  UPDATE nodes SET acl_generation=acl_generation+1
    WHERE tenant_id=changed_tenant AND drive_id=changed_drive AND id=changed_resource;
  DELETE FROM authorization_generations
    WHERE tenant_id=changed_tenant AND drive_id=changed_drive;
  RETURN NULL;
END
$$;
CREATE TRIGGER acl_capability_projection
AFTER INSERT OR UPDATE OR DELETE ON acl_entries
FOR EACH ROW EXECUTE FUNCTION invalidate_acl_capability_projection();

CREATE FUNCTION invalidate_membership_capability_projection() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  changed_tenant uuid := COALESCE(NEW.tenant_id,OLD.tenant_id);
  old_principal uuid := OLD.user_principal_id;
  new_principal uuid := NEW.user_principal_id;
BEGIN
  IF old_principal IS NOT NULL THEN
    UPDATE principals SET generation=generation+1
      WHERE tenant_id=changed_tenant AND id=old_principal;
    DELETE FROM authorization_generations
      WHERE tenant_id=changed_tenant AND principal_id=old_principal;
  END IF;
  IF new_principal IS NOT NULL AND new_principal IS DISTINCT FROM old_principal THEN
    UPDATE principals SET generation=generation+1
      WHERE tenant_id=changed_tenant AND id=new_principal;
    DELETE FROM authorization_generations
      WHERE tenant_id=changed_tenant AND principal_id=new_principal;
  END IF;
  RETURN NULL;
END
$$;
CREATE TRIGGER membership_capability_projection
AFTER INSERT OR UPDATE OR DELETE ON group_memberships
FOR EACH ROW EXECUTE FUNCTION invalidate_membership_capability_projection();

CREATE FUNCTION invalidate_drive_capability_projection() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM authorization_generations
    WHERE tenant_id=NEW.tenant_id AND drive_id=NEW.id;
  RETURN NULL;
END
$$;
CREATE TRIGGER drive_capability_projection
AFTER UPDATE OF acl_generation,namespace_generation ON drives
FOR EACH ROW WHEN (OLD.acl_generation IS DISTINCT FROM NEW.acl_generation OR OLD.namespace_generation IS DISTINCT FROM NEW.namespace_generation)
EXECUTE FUNCTION invalidate_drive_capability_projection();

CREATE FUNCTION invalidate_node_capability_projection() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM authorization_generations
    WHERE tenant_id=NEW.tenant_id AND drive_id=NEW.drive_id;
  RETURN NULL;
END
$$;
CREATE TRIGGER node_capability_projection
AFTER UPDATE OF acl_generation,namespace_generation,parent_id,trash_root_id ON nodes
FOR EACH ROW EXECUTE FUNCTION invalidate_node_capability_projection();

CREATE FUNCTION invalidate_session_capability_projection() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM authorization_generations
    WHERE tenant_id=NEW.tenant_id AND session_id=NEW.id;
  RETURN NULL;
END
$$;
CREATE TRIGGER session_capability_projection
AFTER UPDATE OF revoked_at,absolute_expires_at ON api_sessions
FOR EACH ROW EXECUTE FUNCTION invalidate_session_capability_projection();

CREATE FUNCTION invalidate_user_capability_projection() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM authorization_generations
    WHERE tenant_id=NEW.tenant_id AND principal_id=NEW.principal_id;
  RETURN NULL;
END
$$;
CREATE TRIGGER user_capability_projection
AFTER UPDATE OF status ON users
FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION invalidate_user_capability_projection();

CREATE FUNCTION invalidate_principal_capability_projection() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM authorization_generations
    WHERE tenant_id=NEW.tenant_id AND principal_id=NEW.id;
  RETURN NULL;
END
$$;
CREATE TRIGGER principal_capability_projection
AFTER UPDATE OF disabled_at ON principals
FOR EACH ROW WHEN (OLD.disabled_at IS DISTINCT FROM NEW.disabled_at)
EXECUTE FUNCTION invalidate_principal_capability_projection();

CREATE TABLE jobs (
  tenant_id uuid NOT NULL REFERENCES tenants(id), id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('upload_expire','upload_reconcile','payload_delete','payload_scrub','recursive_namespace')),
  state text NOT NULL CHECK (state IN ('queued','running','retry_wait','terminal','operator_blocked','complete')),
  priority integer NOT NULL DEFAULT 100, aggregate_id uuid, idempotency_key text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb, attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 8),
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(), lease_owner uuid, lease_expires_at timestamptz,
  fencing_token bigint NOT NULL DEFAULT 0 CHECK (fencing_token >= 0), last_error_code text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,kind,idempotency_key)
);
CREATE INDEX jobs_claim_index ON jobs (priority,available_at,created_at) WHERE state IN ('queued','retry_wait');

CREATE TABLE job_attempts (
  tenant_id uuid NOT NULL, job_id uuid NOT NULL, attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 8),
  worker_id uuid NOT NULL, fencing_token bigint NOT NULL CHECK (fencing_token > 0),
  started_at timestamptz NOT NULL DEFAULT clock_timestamp(), finished_at timestamptz, outcome text,
  PRIMARY KEY (tenant_id,job_id,attempt), FOREIGN KEY (tenant_id,job_id) REFERENCES jobs(tenant_id,id) ON DELETE CASCADE
);

CREATE TABLE outbox_events (
  tenant_id uuid NOT NULL REFERENCES tenants(id), id uuid NOT NULL, topic text NOT NULL,
  aggregate_type text NOT NULL, aggregate_id uuid NOT NULL, aggregate_generation bigint NOT NULL CHECK (aggregate_generation > 0),
  partition_key text NOT NULL, payload bytea NOT NULL, occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  publish_attempts integer NOT NULL DEFAULT 0 CHECK (publish_attempts >= 0), next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  published_at timestamptz, PRIMARY KEY (tenant_id,id)
);
CREATE INDEX outbox_pending_index ON outbox_events (next_attempt_at,occurred_at) WHERE published_at IS NULL;
CREATE INDEX outbox_published_retention_index ON outbox_events (tenant_id,published_at,id) WHERE published_at IS NOT NULL;

CREATE TABLE consumer_deduplication (
  consumer text NOT NULL, tenant_id uuid NOT NULL, event_id uuid NOT NULL,
  processed_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY (consumer,tenant_id,event_id),
  FOREIGN KEY (tenant_id,event_id) REFERENCES outbox_events(tenant_id,id)
);

CREATE TABLE audit_events (
  tenant_id uuid NOT NULL REFERENCES tenants(id), id uuid NOT NULL, actor_principal_id uuid,
  target_principal_id uuid, resource_id uuid, action text NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('allowed','denied','conflict','failed')),
  reason_code text NOT NULL, privacy_visible boolean NOT NULL DEFAULT false,
  request_id uuid, details jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id,actor_principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,target_principal_id) REFERENCES principals(tenant_id,id)
);
CREATE INDEX audit_actor_time_index ON audit_events (tenant_id,actor_principal_id,occurred_at DESC);
CREATE INDEX audit_target_privacy_index ON audit_events (tenant_id,target_principal_id,occurred_at DESC) WHERE privacy_visible;

CREATE TABLE notifications (
  tenant_id uuid NOT NULL REFERENCES tenants(id), id uuid NOT NULL, user_id uuid NOT NULL,
  audit_event_id uuid NOT NULL, kind text NOT NULL, read_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,user_id,audit_event_id),
  FOREIGN KEY (tenant_id,user_id) REFERENCES users(tenant_id,id),
  FOREIGN KEY (tenant_id,audit_event_id) REFERENCES audit_events(tenant_id,id)
);

CREATE TABLE idempotency_records (
  tenant_id uuid NOT NULL REFERENCES tenants(id), principal_id uuid NOT NULL,
  route text NOT NULL, key text NOT NULL, request_fingerprint bytea NOT NULL,
  response_status integer NOT NULL, response_body jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL DEFAULT (clock_timestamp() + interval '24 hours'),
  PRIMARY KEY (tenant_id,principal_id,route,key),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id),
  CHECK (expires_at <= created_at + interval '7 days')
);

CREATE INDEX sessions_expiry_index ON api_sessions (idle_expires_at,absolute_expires_at) WHERE revoked_at IS NULL;
CREATE INDEX uploads_expiry_index ON upload_sessions (expires_at) WHERE state = 'open';
CREATE INDEX payload_reconcile_index ON payload_objects (state,created_at);
CREATE INDEX share_links_expiry_index ON share_links (expires_at) WHERE revoked_at IS NULL;
