-- SPDX-License-Identifier: Apache-2.0

-- Phase 8 NFS state is additive and dormant until the separately reviewed
-- activation command admits the NFS gateway. PostgreSQL, not Ganesha recovery
-- files or bridge memory, remains the authority for identity, replay, fences,
-- and retained conflicts.

ALTER TABLE filebelt_mount.policies DROP CONSTRAINT policies_protocol_check;
ALTER TABLE filebelt_mount.policies ADD CONSTRAINT policies_protocol_check
  CHECK (protocol IN ('smb','ftps','nfs'));
ALTER TABLE filebelt_mount.credentials DROP CONSTRAINT credentials_protocol_check;
ALTER TABLE filebelt_mount.credentials ADD CONSTRAINT credentials_protocol_check
  CHECK (protocol IN ('smb','ftps','nfs'));
ALTER TABLE filebelt_mount.credentials DROP CONSTRAINT credentials_verifier_kind_check;
ALTER TABLE filebelt_mount.credentials ADD CONSTRAINT credentials_verifier_kind_check
  CHECK (verifier_kind IN ('ntlm_verifier','hmac_sha256','kerberos_principal'));
ALTER TABLE filebelt_mount.gateway_epochs DROP CONSTRAINT gateway_epochs_protocol_check;
ALTER TABLE filebelt_mount.gateway_epochs ADD CONSTRAINT gateway_epochs_protocol_check
  CHECK (protocol IN ('smb','ftps','nfs'));
ALTER TABLE filebelt_mount.sessions DROP CONSTRAINT sessions_protocol_check;
ALTER TABLE filebelt_mount.sessions ADD CONSTRAINT sessions_protocol_check
  CHECK (protocol IN ('smb','ftps','nfs'));
ALTER TABLE filebelt_mount.deletion_tombstones DROP CONSTRAINT deletion_tombstones_protocol_check;
ALTER TABLE filebelt_mount.deletion_tombstones ADD CONSTRAINT deletion_tombstones_protocol_check
  CHECK (protocol IS NULL OR protocol IN ('smb','ftps','nfs'));

CREATE TABLE filebelt_mount.nfs_principal_mappings (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  kerberos_principal text NOT NULL CHECK (length(kerberos_principal) BETWEEN 1 AND 512),
  principal_id uuid NOT NULL,
  credential_id uuid NOT NULL,
  projected_uid bigint NOT NULL CHECK (projected_uid > 0),
  projected_gid bigint NOT NULL CHECK (projected_gid > 0),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, kerberos_principal),
  UNIQUE (tenant_id, projected_uid),
  UNIQUE (tenant_id, projected_gid),
  FOREIGN KEY (tenant_id, principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id, credential_id) REFERENCES filebelt_mount.credentials(tenant_id,id)
);

CREATE TABLE filebelt_mount.nfs_reclaim_records (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 255),
  state_id uuid NOT NULL,
  gateway_epoch bigint NOT NULL CHECK (gateway_epoch > 0),
  expires_at timestamptz NOT NULL,
  reclaimed_at timestamptz,
  PRIMARY KEY (tenant_id, client_id, state_id)
);

CREATE TABLE filebelt_mount.nfs_replay_receipts (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 255),
  slot_id integer NOT NULL CHECK (slot_id BETWEEN 0 AND 1023),
  sequence_id bigint NOT NULL CHECK (sequence_id > 0),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
  response_digest bytea NOT NULL CHECK (octet_length(response_digest)=32),
  gateway_epoch bigint NOT NULL CHECK (gateway_epoch > 0),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, client_id, slot_id, sequence_id)
);

CREATE TABLE filebelt_mount.nfs_write_extents (
  tenant_id uuid NOT NULL,
  write_session_id uuid NOT NULL,
  offset_bytes bigint NOT NULL CHECK (offset_bytes >= 0),
  length_bytes bigint NOT NULL CHECK (length_bytes > 0),
  is_hole boolean NOT NULL,
  digest bytea CHECK (digest IS NULL OR octet_length(digest)=32),
  PRIMARY KEY (tenant_id, write_session_id, offset_bytes),
  FOREIGN KEY (tenant_id, write_session_id)
    REFERENCES filebelt_mount.write_sessions(tenant_id,id) ON DELETE CASCADE
);
