-- SPDX-License-Identifier: Apache-2.0
-- Phase 8 media state is additive and dormant until the coordinated activation.
-- Derivative bytes remain outside PostgreSQL and are rebuildable cache state.

CREATE TABLE filebelt_media.previews (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  id uuid NOT NULL,
  drive_id uuid NOT NULL,
  node_id uuid NOT NULL,
  source_version_id uuid NOT NULL,
  requester_principal_id uuid NOT NULL,
  requester_session_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 256),
  request_fingerprint bytea NOT NULL CHECK (octet_length(request_fingerprint)=32),
  cache_key bytea NOT NULL CHECK (octet_length(cache_key)=32),
  profile_id text NOT NULL CHECK (length(profile_id) BETWEEN 1 AND 128),
  profile_digest bytea NOT NULL CHECK (octet_length(profile_digest)=32),
  transcoder_build_identity bytea NOT NULL CHECK (octet_length(transcoder_build_identity)=32),
  state text NOT NULL DEFAULT 'requested'
    CHECK (state IN ('requested','running','verifying','ready','failed','quarantined','cancelled','evicting','evicted')),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 3),
  job_epoch bigint NOT NULL DEFAULT 0 CHECK (job_epoch >= 0),
  cancellation_requested_at timestamptz,
  ready_at timestamptz,
  last_accessed_at timestamptz,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,requester_session_id,idempotency_key),
  FOREIGN KEY (tenant_id,drive_id) REFERENCES drives(tenant_id,id),
  FOREIGN KEY (tenant_id,drive_id,node_id) REFERENCES nodes(tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,node_id,source_version_id) REFERENCES file_versions(tenant_id,node_id,id),
  FOREIGN KEY (tenant_id,requester_principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,requester_session_id) REFERENCES api_sessions(tenant_id,id)
);
CREATE INDEX media_preview_admission_index
  ON filebelt_media.previews (tenant_id,state,created_at)
  WHERE state IN ('requested','running','verifying');
CREATE INDEX media_preview_cache_index
  ON filebelt_media.previews (tenant_id,cache_key,ready_at DESC)
  WHERE state='ready';
CREATE INDEX media_preview_expiry_index
  ON filebelt_media.previews (expires_at,id)
  WHERE state='ready' AND expires_at IS NOT NULL;

CREATE TABLE filebelt_media.attempts (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  preview_id uuid NOT NULL,
  job_epoch bigint NOT NULL CHECK (job_epoch > 0),
  state text NOT NULL DEFAULT 'running'
    CHECK (state IN ('running','verifying','failed','quarantined','cancelled','complete')),
  source_capability_digest bytea NOT NULL CHECK (octet_length(source_capability_digest)=32),
  output_capability_digest bytea NOT NULL CHECK (octet_length(output_capability_digest)=32),
  callback_capability_digest bytea NOT NULL CHECK (octet_length(callback_capability_digest)=32),
  started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  finished_at timestamptz,
  last_error_code text,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,preview_id,job_epoch),
  FOREIGN KEY (tenant_id,preview_id) REFERENCES filebelt_media.previews(tenant_id,id) ON DELETE CASCADE,
  CHECK ((state IN ('failed','quarantined','cancelled','complete')) = (finished_at IS NOT NULL))
);

CREATE TABLE filebelt_media.reservations (
  tenant_id uuid NOT NULL,
  preview_id uuid NOT NULL,
  reserved_bytes bigint NOT NULL CHECK (reserved_bytes >= 0),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','released','consumed')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  released_at timestamptz,
  PRIMARY KEY (tenant_id,preview_id),
  FOREIGN KEY (tenant_id,preview_id) REFERENCES filebelt_media.previews(tenant_id,id) ON DELETE CASCADE,
  CHECK ((state='active') = (released_at IS NULL))
);

CREATE TABLE filebelt_media.segment_receipts (
  tenant_id uuid NOT NULL,
  preview_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  job_epoch bigint NOT NULL CHECK (job_epoch > 0),
  ordinal bigint NOT NULL CHECK (ordinal >= 0),
  segment_id uuid NOT NULL,
  blake3 bytea NOT NULL CHECK (octet_length(blake3)=32),
  byte_length bigint NOT NULL CHECK (byte_length > 0),
  start_time_milliseconds bigint NOT NULL CHECK (start_time_milliseconds >= 0),
  duration_milliseconds bigint NOT NULL CHECK (duration_milliseconds > 0),
  initialization_segment boolean NOT NULL DEFAULT false,
  verified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,preview_id,attempt_id,ordinal),
  UNIQUE (tenant_id,preview_id,attempt_id,segment_id),
  FOREIGN KEY (tenant_id,preview_id) REFERENCES filebelt_media.previews(tenant_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,attempt_id) REFERENCES filebelt_media.attempts(tenant_id,id) ON DELETE CASCADE
);

CREATE TABLE filebelt_media.manifest_revisions (
  tenant_id uuid NOT NULL,
  preview_id uuid NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  attempt_id uuid NOT NULL,
  job_epoch bigint NOT NULL CHECK (job_epoch > 0),
  manifest_id uuid NOT NULL,
  manifest_blake3 bytea NOT NULL CHECK (octet_length(manifest_blake3)=32),
  manifest_byte_length bigint NOT NULL CHECK (manifest_byte_length > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,preview_id,revision),
  UNIQUE (tenant_id,manifest_id),
  FOREIGN KEY (tenant_id,preview_id) REFERENCES filebelt_media.previews(tenant_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,attempt_id) REFERENCES filebelt_media.attempts(tenant_id,id) ON DELETE CASCADE
);

CREATE TABLE filebelt_media.cache_artifacts (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  preview_id uuid NOT NULL,
  manifest_revision bigint NOT NULL,
  state text NOT NULL DEFAULT 'ready' CHECK (state IN ('ready','unavailable','evicting','evicted')),
  charged_bytes bigint NOT NULL CHECK (charged_bytes > 0),
  last_accessed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,preview_id,manifest_revision),
  FOREIGN KEY (tenant_id,preview_id,manifest_revision)
    REFERENCES filebelt_media.manifest_revisions(tenant_id,preview_id,revision) ON DELETE RESTRICT,
  CHECK (expires_at <= last_accessed_at+interval '30 days')
);
CREATE INDEX media_cache_eviction_index
  ON filebelt_media.cache_artifacts (expires_at,last_accessed_at,id)
  WHERE state='ready';

CREATE TABLE filebelt_media.playback_sessions (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  preview_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  api_session_id uuid NOT NULL,
  token_digest bytea NOT NULL CHECK (octet_length(token_digest)=32),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,token_digest),
  FOREIGN KEY (tenant_id,preview_id) REFERENCES filebelt_media.previews(tenant_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,api_session_id) REFERENCES api_sessions(tenant_id,id),
  CHECK (expires_at <= created_at+interval '60 seconds')
);
CREATE INDEX media_playback_expiry_index ON filebelt_media.playback_sessions (expires_at,id);

CREATE TABLE filebelt_media.deletion_intents (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  artifact_id uuid NOT NULL,
  fencing_token bigint NOT NULL CHECK (fencing_token > 0),
  state text NOT NULL DEFAULT 'requested' CHECK (state IN ('requested','running','complete','failed')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,artifact_id),
  FOREIGN KEY (tenant_id,artifact_id) REFERENCES filebelt_media.cache_artifacts(tenant_id,id) ON DELETE CASCADE,
  CHECK ((state='complete') = (completed_at IS NOT NULL))
);

CREATE TABLE filebelt_media.diagnostics (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  preview_id uuid NOT NULL,
  attempt_id uuid,
  reason_code text NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 96),
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  purge_after timestamptz NOT NULL DEFAULT (clock_timestamp()+interval '24 hours'),
  PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id,preview_id) REFERENCES filebelt_media.previews(tenant_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,attempt_id) REFERENCES filebelt_media.attempts(tenant_id,id) ON DELETE CASCADE,
  CHECK (purge_after <= created_at+interval '24 hours')
);
CREATE INDEX media_diagnostics_purge_index ON filebelt_media.diagnostics (purge_after,id);
