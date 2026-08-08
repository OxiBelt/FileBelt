-- SPDX-License-Identifier: Apache-2.0

-- Phase 6 mount state is intentionally isolated from adapter implementations.
-- PostgreSQL is authoritative for credentials, sessions, locks, leases, and
-- write publication. Gateways never receive direct table access.

ALTER TABLE principals DROP CONSTRAINT principals_kind_check;
ALTER TABLE principals ADD CONSTRAINT principals_kind_check
  CHECK (kind IN ('user','group','service','share_link','mount_session'));

REVOKE ALL ON SCHEMA filebelt_mount, filebelt_mount_vault FROM PUBLIC;

CREATE TABLE filebelt_mount.policies (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  principal_id uuid NOT NULL,
  protocol text NOT NULL CHECK (protocol IN ('smb','ftps')),
  enabled boolean NOT NULL DEFAULT false,
  read_only boolean NOT NULL DEFAULT true,
  allowed_drive_ids uuid[] NOT NULL DEFAULT '{}',
  authorization_generation bigint NOT NULL DEFAULT 1 CHECK (authorization_generation > 0),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,principal_id,protocol),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id),
  CHECK (cardinality(allowed_drive_ids) <= 256)
);

CREATE TABLE filebelt_mount.credentials (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  principal_id uuid NOT NULL,
  protocol text NOT NULL CHECK (protocol IN ('smb','ftps')),
  username text NOT NULL CHECK (length(username) BETWEEN 16 AND 96),
  verifier_kind text NOT NULL CHECK (verifier_kind IN ('ntlm_verifier','hmac_sha256')),
  credential_generation bigint NOT NULL DEFAULT 1 CHECK (credential_generation > 0),
  authorization_generation bigint NOT NULL DEFAULT 1 CHECK (authorization_generation > 0),
  read_only boolean NOT NULL DEFAULT true,
  allowed_drive_ids uuid[] NOT NULL DEFAULT '{}',
  bound_device_id uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_used_at timestamptz,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,protocol,username),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id),
  CHECK (expires_at > created_at),
  CHECK (cardinality(allowed_drive_ids) <= 256)
);
CREATE INDEX mount_credentials_principal_index
  ON filebelt_mount.credentials (tenant_id,principal_id,protocol,expires_at)
  WHERE revoked_at IS NULL;

CREATE TABLE filebelt_mount.headscale_devices (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  principal_id uuid NOT NULL,
  headscale_node_id text NOT NULL CHECK (length(headscale_node_id) BETWEEN 1 AND 255),
  oidc_issuer text NOT NULL CHECK (length(oidc_issuer) BETWEEN 1 AND 2048),
  oidc_subject text NOT NULL CHECK (length(oidc_subject) BETWEEN 1 AND 512),
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 255),
  tailnet_addresses inet[] NOT NULL DEFAULT '{}',
  node_tags text[] NOT NULL DEFAULT '{}',
  capability_version text NOT NULL,
  ownership_generation bigint NOT NULL DEFAULT 1 CHECK (ownership_generation > 0),
  observed_at timestamptz NOT NULL,
  revoked_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,headscale_node_id),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id),
  CHECK (cardinality(tailnet_addresses) BETWEEN 1 AND 16),
  CHECK (cardinality(node_tags) <= 32)
);
ALTER TABLE filebelt_mount.credentials ADD CONSTRAINT mount_credentials_device_fk
  FOREIGN KEY (tenant_id,bound_device_id)
  REFERENCES filebelt_mount.headscale_devices(tenant_id,id);
CREATE INDEX mount_devices_principal_index
  ON filebelt_mount.headscale_devices (tenant_id,principal_id,observed_at)
  WHERE revoked_at IS NULL;

CREATE TABLE filebelt_mount.gateway_epochs (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  protocol text NOT NULL CHECK (protocol IN ('smb','ftps')),
  shard_key text NOT NULL CHECK (length(shard_key) BETWEEN 1 AND 255),
  gateway_id text NOT NULL CHECK (length(gateway_id) BETWEEN 1 AND 255),
  epoch bigint NOT NULL CHECK (epoch > 0),
  draining boolean NOT NULL DEFAULT false,
  lease_expires_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,protocol,shard_key)
);

CREATE TABLE filebelt_mount.sessions (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  session_principal_id uuid NOT NULL,
  user_principal_id uuid NOT NULL,
  credential_id uuid NOT NULL,
  device_id uuid,
  protocol text NOT NULL CHECK (protocol IN ('smb','ftps')),
  gateway_id text NOT NULL CHECK (length(gateway_id) BETWEEN 1 AND 255),
  gateway_epoch bigint NOT NULL CHECK (gateway_epoch > 0),
  source_address inet NOT NULL,
  credential_generation bigint NOT NULL CHECK (credential_generation > 0),
  authorization_generation bigint NOT NULL CHECK (authorization_generation > 0),
  membership_generation bigint NOT NULL CHECK (membership_generation > 0),
  state text NOT NULL DEFAULT 'active'
    CHECK (state IN ('active','draining','revoked','expired','closed')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_revalidated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_activity_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  idle_expires_at timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  closed_at timestamptz,
  close_reason text,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,session_principal_id),
  FOREIGN KEY (tenant_id,session_principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,user_principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,credential_id) REFERENCES filebelt_mount.credentials(tenant_id,id),
  FOREIGN KEY (tenant_id,device_id) REFERENCES filebelt_mount.headscale_devices(tenant_id,id),
  CHECK (idle_expires_at <= absolute_expires_at),
  CHECK ((state IN ('active','draining')) = (closed_at IS NULL))
);
CREATE INDEX mount_sessions_active_credential_index
  ON filebelt_mount.sessions (tenant_id,credential_id,last_activity_at)
  WHERE state IN ('active','draining');
CREATE INDEX mount_sessions_active_principal_index
  ON filebelt_mount.sessions (tenant_id,user_principal_id,protocol,last_activity_at)
  WHERE state IN ('active','draining');

CREATE TABLE filebelt_mount.session_receipts (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  session_id uuid NOT NULL,
  request_id uuid NOT NULL,
  operation text NOT NULL CHECK (length(operation) BETWEEN 1 AND 64),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
  response_code text NOT NULL CHECK (length(response_code) BETWEEN 1 AND 64),
  response_digest bytea CHECK (response_digest IS NULL OR octet_length(response_digest)=32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,session_id,request_id),
  FOREIGN KEY (tenant_id,session_id) REFERENCES filebelt_mount.sessions(tenant_id,id)
);

CREATE TABLE filebelt_mount.handles (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  session_id uuid NOT NULL,
  drive_id uuid NOT NULL,
  node_id uuid NOT NULL,
  version_id uuid,
  access_actions text[] NOT NULL,
  share_read boolean NOT NULL,
  share_write boolean NOT NULL,
  share_delete boolean NOT NULL,
  delete_pending boolean NOT NULL DEFAULT false,
  credential_generation bigint NOT NULL CHECK (credential_generation > 0),
  authorization_generation bigint NOT NULL CHECK (authorization_generation > 0),
  membership_generation bigint NOT NULL CHECK (membership_generation > 0),
  drive_acl_generation bigint NOT NULL CHECK (drive_acl_generation > 0),
  namespace_generation bigint NOT NULL CHECK (namespace_generation > 0),
  resource_acl_generation bigint NOT NULL CHECK (resource_acl_generation > 0),
  gateway_epoch bigint NOT NULL CHECK (gateway_epoch > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  closed_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id,session_id) REFERENCES filebelt_mount.sessions(tenant_id,id),
  FOREIGN KEY (tenant_id,drive_id,node_id) REFERENCES nodes(tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,node_id,version_id) REFERENCES file_versions(tenant_id,node_id,id),
  CHECK (cardinality(access_actions) BETWEEN 1 AND 19)
);
CREATE INDEX mount_handles_open_node_index
  ON filebelt_mount.handles (tenant_id,drive_id,node_id)
  WHERE closed_at IS NULL;

CREATE TABLE filebelt_mount.byte_locks (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  handle_id uuid NOT NULL,
  drive_id uuid NOT NULL,
  node_id uuid NOT NULL,
  owner_key text NOT NULL CHECK (length(owner_key) BETWEEN 1 AND 255),
  offset_bytes bigint NOT NULL CHECK (offset_bytes >= 0),
  length_bytes bigint NOT NULL CHECK (length_bytes > 0),
  exclusive boolean NOT NULL,
  gateway_epoch bigint NOT NULL CHECK (gateway_epoch > 0),
  expires_at timestamptz NOT NULL,
  released_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id,handle_id) REFERENCES filebelt_mount.handles(tenant_id,id),
  FOREIGN KEY (tenant_id,drive_id,node_id) REFERENCES nodes(tenant_id,drive_id,id)
);
CREATE INDEX mount_byte_locks_active_range_index
  ON filebelt_mount.byte_locks (tenant_id,drive_id,node_id,offset_bytes)
  WHERE released_at IS NULL;

CREATE TABLE filebelt_mount.leases (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  handle_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('writer','smb_read','smb_write','smb_handle')),
  lease_key bytea NOT NULL CHECK (octet_length(lease_key) BETWEEN 16 AND 32),
  state text NOT NULL CHECK (state IN ('granted','breaking','broken','expired','released')),
  fencing_token bigint NOT NULL CHECK (fencing_token > 0),
  gateway_epoch bigint NOT NULL CHECK (gateway_epoch > 0),
  heartbeat_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  released_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,kind,lease_key),
  FOREIGN KEY (tenant_id,handle_id) REFERENCES filebelt_mount.handles(tenant_id,id)
);

CREATE TABLE filebelt_mount.write_sessions (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  mount_session_id uuid NOT NULL,
  handle_id uuid NOT NULL,
  drive_id uuid NOT NULL,
  node_id uuid NOT NULL,
  base_version_id uuid,
  expected_head_version_id uuid,
  staging_payload_id uuid NOT NULL,
  declared_size_bytes bigint CHECK (declared_size_bytes IS NULL OR declared_size_bytes >= 0),
  logical_size_bytes bigint NOT NULL DEFAULT 0 CHECK (logical_size_bytes >= 0),
  reserved_bytes bigint NOT NULL DEFAULT 0 CHECK (reserved_bytes >= 0),
  state text NOT NULL DEFAULT 'open'
    CHECK (state IN ('open','flushing','committing','committed','aborting','aborted','expired')),
  fencing_token bigint NOT NULL DEFAULT 1 CHECK (fencing_token > 0),
  gateway_epoch bigint NOT NULL CHECK (gateway_epoch > 0),
  authorization_generation bigint NOT NULL CHECK (authorization_generation > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  heartbeat_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  lease_expires_at timestamptz NOT NULL DEFAULT (clock_timestamp()+interval '30 seconds'),
  expires_at timestamptz NOT NULL,
  committed_version_id uuid,
  finished_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,handle_id),
  FOREIGN KEY (tenant_id,mount_session_id) REFERENCES filebelt_mount.sessions(tenant_id,id),
  FOREIGN KEY (tenant_id,handle_id) REFERENCES filebelt_mount.handles(tenant_id,id),
  FOREIGN KEY (tenant_id,drive_id,node_id) REFERENCES nodes(tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,node_id,base_version_id) REFERENCES file_versions(tenant_id,node_id,id),
  FOREIGN KEY (tenant_id,node_id,expected_head_version_id) REFERENCES file_versions(tenant_id,node_id,id),
  FOREIGN KEY (tenant_id,staging_payload_id) REFERENCES payload_objects(tenant_id,id),
  FOREIGN KEY (tenant_id,node_id,committed_version_id) REFERENCES file_versions(tenant_id,node_id,id),
  CHECK (expires_at > created_at),
  CHECK ((state='committed') = (committed_version_id IS NOT NULL))
);
CREATE UNIQUE INDEX mount_one_active_writer_per_node
  ON filebelt_mount.write_sessions (tenant_id,drive_id,node_id)
  WHERE state IN ('open','flushing','committing');

CREATE TABLE filebelt_mount.write_chunks (
  tenant_id uuid NOT NULL,
  write_session_id uuid NOT NULL,
  chunk_number bigint NOT NULL CHECK (chunk_number >= 0),
  source_payload_id uuid,
  source_chunk_number bigint CHECK (source_chunk_number IS NULL OR source_chunk_number >= 0),
  staging_locator uuid,
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  blake3 bytea CHECK (blake3 IS NULL OR octet_length(blake3)=32),
  dirty boolean NOT NULL DEFAULT false,
  state text NOT NULL CHECK (state IN ('linked','writing','ready','published')),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,write_session_id,chunk_number),
  FOREIGN KEY (tenant_id,write_session_id) REFERENCES filebelt_mount.write_sessions(tenant_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,source_payload_id) REFERENCES payload_objects(tenant_id,id),
  CHECK ((state='linked') = (source_payload_id IS NOT NULL AND staging_locator IS NULL)),
  CHECK ((state IN ('writing','ready','published')) = (staging_locator IS NOT NULL))
);

CREATE TABLE filebelt_mount.passive_allocations (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  session_id uuid NOT NULL,
  gateway_id text NOT NULL,
  port integer NOT NULL CHECK (port BETWEEN 50000 AND 50049),
  source_address inet NOT NULL,
  binding_digest bytea NOT NULL CHECK (octet_length(binding_digest)=32),
  state text NOT NULL DEFAULT 'allocated'
    CHECK (state IN ('allocated','connected','consumed','expired','released')),
  allocated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,gateway_id,port),
  FOREIGN KEY (tenant_id,session_id) REFERENCES filebelt_mount.sessions(tenant_id,id)
);

CREATE TABLE filebelt_mount.authentication_throttles (
  tenant_id uuid NOT NULL,
  protocol text NOT NULL CHECK (protocol IN ('smb','ftps')),
  principal_key bytea NOT NULL CHECK (octet_length(principal_key)=32),
  source_key bytea NOT NULL CHECK (octet_length(source_key)=32),
  failures integer NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 1024),
  delay_until timestamptz,
  expires_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,protocol,principal_key,source_key)
);

CREATE TABLE filebelt_mount.deletion_tombstones (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  id uuid NOT NULL,
  object_kind text NOT NULL CHECK (object_kind IN ('credential','session','device')),
  object_id uuid NOT NULL,
  principal_id uuid,
  protocol text CHECK (protocol IS NULL OR protocol IN ('smb','ftps')),
  reason_code text NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 128),
  generation bigint NOT NULL CHECK (generation > 0),
  deleted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  purge_after timestamptz NOT NULL DEFAULT (clock_timestamp()+interval '365 days'),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,object_kind,object_id,generation),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id),
  CHECK (purge_after >= deleted_at+interval '365 days')
);

CREATE TABLE filebelt_mount_vault.secret_envelopes (
  tenant_id uuid NOT NULL,
  credential_id uuid NOT NULL,
  kek_generation integer NOT NULL CHECK (kek_generation > 0),
  secret_kind text NOT NULL CHECK (secret_kind IN ('ntlm_verifier','hmac_sha256')),
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 4096),
  nonce bytea NOT NULL CHECK (octet_length(nonce)=12),
  aad_digest bytea NOT NULL CHECK (octet_length(aad_digest)=32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,credential_id),
  FOREIGN KEY (tenant_id,credential_id) REFERENCES filebelt_mount.credentials(tenant_id,id) ON DELETE CASCADE
);

CREATE FUNCTION filebelt_mount.erase_revoked_credential_secret() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,filebelt_mount,filebelt_mount_vault AS $$
BEGIN
  IF NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL THEN
    DELETE FROM filebelt_mount_vault.secret_envelopes
      WHERE tenant_id=NEW.tenant_id AND credential_id=NEW.id;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER mount_credential_secret_erasure
AFTER UPDATE OF revoked_at ON filebelt_mount.credentials
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.erase_revoked_credential_secret();

CREATE FUNCTION filebelt_mount.advance_authorization_generation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    UPDATE filebelt_mount.credentials
      SET authorization_generation=authorization_generation+1
      WHERE tenant_id=OLD.tenant_id AND principal_id=OLD.principal_id AND protocol=OLD.protocol;
    RETURN OLD;
  END IF;
  UPDATE filebelt_mount.credentials
    SET authorization_generation=authorization_generation+1
    WHERE tenant_id=NEW.tenant_id AND principal_id=NEW.principal_id AND protocol=NEW.protocol;
  RETURN NEW;
END
$$;
CREATE TRIGGER mount_policy_generation
AFTER INSERT OR UPDATE OR DELETE ON filebelt_mount.policies
FOR EACH ROW EXECUTE FUNCTION filebelt_mount.advance_authorization_generation();
