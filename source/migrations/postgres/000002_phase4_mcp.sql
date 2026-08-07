-- SPDX-License-Identifier: Apache-2.0

-- MCP metadata and policy state are deliberately separated from encrypted
-- credential material. Runtime grants are maintained in grants.sql.
CREATE SCHEMA IF NOT EXISTS filebelt_mcp;
CREATE SCHEMA IF NOT EXISTS filebelt_mcp_vault;

CREATE TABLE filebelt_mcp.service_principals (
  tenant_id uuid NOT NULL, id uuid NOT NULL, principal_id uuid NOT NULL,
  display_name text NOT NULL, status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active','suspended','deleted')),
  revocation_generation bigint NOT NULL DEFAULT 1 CHECK (revocation_generation > 0),
  created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(), deleted_at timestamptz,
  PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,principal_id),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES public.principals(tenant_id,id),
  FOREIGN KEY (tenant_id,created_by) REFERENCES public.principals(tenant_id,id),
  CHECK ((status = 'deleted') = (deleted_at IS NOT NULL))
);

CREATE TABLE filebelt_mcp.service_identity_bindings (
  tenant_id uuid NOT NULL, id uuid NOT NULL, service_id uuid NOT NULL,
  spiffe_uri text NOT NULL CHECK (spiffe_uri ~ '^spiffe://[^[:space:]]+$'),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), revoked_at timestamptz,
  PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,spiffe_uri),
  FOREIGN KEY (tenant_id,service_id)
    REFERENCES filebelt_mcp.service_principals(tenant_id,id)
);
CREATE UNIQUE INDEX service_identity_bindings_active
  ON filebelt_mcp.service_identity_bindings (tenant_id,service_id)
  WHERE revoked_at IS NULL;

CREATE FUNCTION filebelt_mcp.require_service_principal() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  actual_kind text;
BEGIN
  SELECT kind INTO actual_kind FROM public.principals
    WHERE tenant_id=NEW.tenant_id AND id=NEW.principal_id;
  IF actual_kind IS DISTINCT FROM 'service' THEN
    RAISE EXCEPTION 'MCP service identity must reference a service principal';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER service_principal_kind
BEFORE INSERT OR UPDATE OF tenant_id,principal_id
ON filebelt_mcp.service_principals
FOR EACH ROW EXECUTE FUNCTION filebelt_mcp.require_service_principal();

CREATE TABLE filebelt_mcp.managed_templates (
  tenant_id uuid NOT NULL REFERENCES public.tenants(id), id uuid NOT NULL,
  display_name text NOT NULL, description text NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
  transport text NOT NULL CHECK (transport IN ('streamable_http','stdio_catalog')),
  endpoint_uri text, trust_profile text, catalog_entry text,
  enabled boolean NOT NULL DEFAULT false, policy jsonb NOT NULL DEFAULT '{}'::jsonb,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  revocation_generation bigint NOT NULL DEFAULT 1 CHECK (revocation_generation > 0),
  created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(), deleted_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id,created_by) REFERENCES public.principals(tenant_id,id),
  CHECK ((transport = 'streamable_http') = (endpoint_uri IS NOT NULL)),
  CHECK ((transport = 'stdio_catalog') = (catalog_entry IS NOT NULL)),
  CHECK (jsonb_typeof(policy) = 'object')
);

CREATE TABLE filebelt_mcp.template_assignments (
  tenant_id uuid NOT NULL, template_id uuid NOT NULL, subject_principal_id uuid NOT NULL,
  subject_kind text NOT NULL CHECK (subject_kind IN ('user','group','service')),
  created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at timestamptz,
  PRIMARY KEY (tenant_id,template_id,subject_principal_id),
  FOREIGN KEY (tenant_id,template_id)
    REFERENCES filebelt_mcp.managed_templates(tenant_id,id),
  FOREIGN KEY (tenant_id,subject_principal_id)
    REFERENCES public.principals(tenant_id,id),
  FOREIGN KEY (tenant_id,created_by) REFERENCES public.principals(tenant_id,id)
);

CREATE TABLE filebelt_mcp.registrations (
  tenant_id uuid NOT NULL REFERENCES public.tenants(id), id uuid NOT NULL,
  owner_principal_id uuid NOT NULL,
  owner_kind text NOT NULL CHECK (owner_kind IN ('user','service')),
  source_kind text NOT NULL CHECK (source_kind IN ('personal','managed')),
  template_id uuid, display_name text NOT NULL,
  description text NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
  transport text NOT NULL CHECK (transport IN ('streamable_http','stdio_catalog')),
  endpoint_uri text, trust_profile text, catalog_entry text,
  validation_state text NOT NULL DEFAULT 'never_tested'
    CHECK (validation_state IN ('never_tested','valid','invalid')),
  authentication_state text NOT NULL DEFAULT 'required'
    CHECK (authentication_state IN ('none_required','required','authorized','failed')),
  capability_state text NOT NULL DEFAULT 'undiscovered'
    CHECK (capability_state IN ('undiscovered','pending_review','approved','drifted')),
  quarantine_state text NOT NULL DEFAULT 'clear'
    CHECK (quarantine_state IN ('clear','quarantined')),
  enabled boolean NOT NULL DEFAULT false, policy jsonb NOT NULL DEFAULT '{}'::jsonb,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  revocation_generation bigint NOT NULL DEFAULT 1 CHECK (revocation_generation > 0),
  credential_generation bigint NOT NULL DEFAULT 1 CHECK (credential_generation > 0),
  credential_kind text NOT NULL DEFAULT 'none'
    CHECK (credential_kind IN ('none','bearer','api_key','oauth')),
  protocol_version text, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(), revoked_at timestamptz,
  deleted_at timestamptz,
  PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,owner_principal_id,id),
  FOREIGN KEY (tenant_id,owner_principal_id)
    REFERENCES public.principals(tenant_id,id),
  FOREIGN KEY (tenant_id,template_id)
    REFERENCES filebelt_mcp.managed_templates(tenant_id,id),
  CHECK ((source_kind = 'managed') = (template_id IS NOT NULL)),
  CHECK ((transport = 'streamable_http') = (endpoint_uri IS NOT NULL)),
  CHECK ((transport = 'stdio_catalog') = (catalog_entry IS NOT NULL)),
  CHECK (jsonb_typeof(policy) = 'object'),
  CHECK (NOT enabled OR (
    validation_state = 'valid' AND
    authentication_state IN ('none_required','authorized') AND
    capability_state = 'approved' AND quarantine_state = 'clear' AND
    revoked_at IS NULL AND deleted_at IS NULL
  )),
  CHECK (revoked_at IS NULL OR NOT enabled),
  CHECK (deleted_at IS NULL OR revoked_at IS NOT NULL)
);
CREATE INDEX registrations_owner_index
  ON filebelt_mcp.registrations (tenant_id,owner_principal_id,updated_at DESC)
  WHERE deleted_at IS NULL;

CREATE TABLE filebelt_mcp.admin_block_rules (
  tenant_id uuid NOT NULL REFERENCES public.tenants(id), id uuid NOT NULL,
  scope text NOT NULL CHECK (scope IN ('origin','trust_profile','catalog_entry','registration','capability')),
  matcher text NOT NULL CHECK (length(matcher) BETWEEN 1 AND 2048),
  reason_code text NOT NULL, enabled boolean NOT NULL DEFAULT true,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(), deleted_at timestamptz,
  PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,scope,matcher),
  FOREIGN KEY (tenant_id,created_by) REFERENCES public.principals(tenant_id,id)
);

CREATE FUNCTION filebelt_mcp.require_principal_kind() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  expected_kind text;
  actual_kind text;
BEGIN
  IF TG_TABLE_NAME = 'template_assignments' THEN
    expected_kind := NEW.subject_kind;
    SELECT kind INTO actual_kind FROM public.principals
      WHERE tenant_id=NEW.tenant_id AND id=NEW.subject_principal_id;
  ELSE
    expected_kind := NEW.owner_kind;
    SELECT kind INTO actual_kind FROM public.principals
      WHERE tenant_id=NEW.tenant_id AND id=NEW.owner_principal_id;
  END IF;
  IF actual_kind IS DISTINCT FROM expected_kind THEN
    RAISE EXCEPTION 'MCP principal kind does not match authoritative principal';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER registration_principal_kind
BEFORE INSERT OR UPDATE OF tenant_id,owner_principal_id,owner_kind
ON filebelt_mcp.registrations
FOR EACH ROW EXECUTE FUNCTION filebelt_mcp.require_principal_kind();
CREATE TRIGGER assignment_principal_kind
BEFORE INSERT OR UPDATE OF tenant_id,subject_principal_id,subject_kind
ON filebelt_mcp.template_assignments
FOR EACH ROW EXECUTE FUNCTION filebelt_mcp.require_principal_kind();

CREATE TABLE filebelt_mcp.capability_snapshots (
  tenant_id uuid NOT NULL, id uuid NOT NULL, registration_id uuid NOT NULL,
  credential_generation bigint NOT NULL CHECK (credential_generation > 0),
  fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
  protocol_version text NOT NULL, document jsonb NOT NULL,
  discovered_at timestamptz NOT NULL DEFAULT clock_timestamp(), superseded_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,id,registration_id),
  UNIQUE (tenant_id,registration_id,credential_generation,fingerprint),
  FOREIGN KEY (tenant_id,registration_id)
    REFERENCES filebelt_mcp.registrations(tenant_id,id),
  CHECK (jsonb_typeof(document) = 'object')
);
CREATE UNIQUE INDEX capability_snapshots_current
  ON filebelt_mcp.capability_snapshots (tenant_id,registration_id)
  WHERE superseded_at IS NULL;

CREATE TABLE filebelt_mcp.capabilities (
  tenant_id uuid NOT NULL, snapshot_id uuid NOT NULL, fingerprint bytea NOT NULL,
  primitive text NOT NULL CHECK (primitive IN ('resource_read','prompt_get','tool_call')),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
  read_only_hint boolean, descriptor jsonb NOT NULL,
  PRIMARY KEY (tenant_id,snapshot_id,fingerprint),
  UNIQUE (tenant_id,snapshot_id,primitive,name),
  FOREIGN KEY (tenant_id,snapshot_id)
    REFERENCES filebelt_mcp.capability_snapshots(tenant_id,id) ON DELETE CASCADE,
  CHECK (octet_length(fingerprint) = 32),
  CHECK (primitive <> 'tool_call' OR read_only_hint IS TRUE),
  CHECK (jsonb_typeof(descriptor) = 'object')
);

CREATE TABLE filebelt_mcp.capability_reviews (
  tenant_id uuid NOT NULL, registration_id uuid NOT NULL, snapshot_id uuid NOT NULL,
  capability_fingerprint bytea NOT NULL,
  reviewer_principal_id uuid NOT NULL, decision text NOT NULL CHECK (decision IN ('approved','denied')),
  constraints jsonb NOT NULL DEFAULT '{}'::jsonb,
  reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp(), revoked_at timestamptz,
  PRIMARY KEY (tenant_id,snapshot_id,capability_fingerprint),
  FOREIGN KEY (tenant_id,snapshot_id,registration_id)
    REFERENCES filebelt_mcp.capability_snapshots(tenant_id,id,registration_id),
  FOREIGN KEY (tenant_id,snapshot_id,capability_fingerprint)
    REFERENCES filebelt_mcp.capabilities(tenant_id,snapshot_id,fingerprint),
  FOREIGN KEY (tenant_id,reviewer_principal_id)
    REFERENCES public.principals(tenant_id,id),
  CHECK (octet_length(capability_fingerprint) = 32),
  CHECK (jsonb_typeof(constraints) = 'object')
);

CREATE TABLE filebelt_mcp.approval_rules (
  tenant_id uuid NOT NULL, id uuid NOT NULL, registration_id uuid NOT NULL,
  principal_id uuid NOT NULL, intent_id uuid NOT NULL, session_id uuid,
  application_id text NOT NULL,
  primitive text NOT NULL CHECK (primitive IN ('resource_read','prompt_get','tool_call')),
  capability_name text NOT NULL, capability_fingerprint bytea NOT NULL,
  argument_digest bytea NOT NULL, attachment_digest bytea NOT NULL,
  single_use boolean NOT NULL DEFAULT true, consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,id,registration_id,principal_id),
  UNIQUE (tenant_id,intent_id),
  FOREIGN KEY (tenant_id,principal_id,registration_id)
    REFERENCES filebelt_mcp.registrations(tenant_id,owner_principal_id,id),
  CHECK (octet_length(capability_fingerprint) = 32),
  CHECK (octet_length(argument_digest) = 32),
  CHECK (octet_length(attachment_digest) = 32),
  CHECK (expires_at <= created_at + interval '1 hour'),
  CHECK (consumed_at IS NULL OR single_use)
);
CREATE INDEX approval_rules_active
  ON filebelt_mcp.approval_rules (tenant_id,principal_id,registration_id,expires_at)
  WHERE revoked_at IS NULL AND consumed_at IS NULL;

CREATE TABLE filebelt_mcp.data_grants (
  tenant_id uuid NOT NULL, id uuid NOT NULL, principal_id uuid NOT NULL,
  registration_id uuid NOT NULL, drive_id uuid NOT NULL, resource_id uuid NOT NULL,
  version_id uuid NOT NULL,
  allow_metadata boolean NOT NULL, allow_content boolean NOT NULL,
  acl_generation bigint NOT NULL CHECK (acl_generation > 0),
  namespace_generation bigint NOT NULL CHECK (namespace_generation > 0),
  registration_generation bigint NOT NULL CHECK (registration_generation > 0),
  created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL, revoked_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES public.principals(tenant_id,id),
  FOREIGN KEY (tenant_id,principal_id,registration_id)
    REFERENCES filebelt_mcp.registrations(tenant_id,owner_principal_id,id),
  FOREIGN KEY (tenant_id,drive_id,resource_id)
    REFERENCES public.nodes(tenant_id,drive_id,id),
  FOREIGN KEY (tenant_id,resource_id,version_id)
    REFERENCES public.file_versions(tenant_id,node_id,id),
  FOREIGN KEY (tenant_id,created_by) REFERENCES public.principals(tenant_id,id),
  CHECK (allow_metadata OR allow_content),
  CHECK (expires_at <= created_at + interval '30 days')
);
CREATE INDEX data_grants_active
  ON filebelt_mcp.data_grants
    (tenant_id,principal_id,registration_id,drive_id,resource_id,version_id,expires_at)
  WHERE revoked_at IS NULL;

CREATE TABLE filebelt_mcp.service_invocation_grants (
  tenant_id uuid NOT NULL, id uuid NOT NULL, service_id uuid NOT NULL,
  registration_id uuid NOT NULL, capability_fingerprint bytea NOT NULL,
  primitive text NOT NULL CHECK (primitive IN ('resource_read','prompt_get','tool_call')),
  capability_name text NOT NULL, constraints jsonb NOT NULL DEFAULT '{}'::jsonb,
  application_id text NOT NULL, quota jsonb NOT NULL DEFAULT '{}'::jsonb,
  max_invocations_per_hour integer NOT NULL CHECK (max_invocations_per_hour BETWEEN 1 AND 600),
  created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL, revoked_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id,service_id)
    REFERENCES filebelt_mcp.service_principals(tenant_id,id),
  FOREIGN KEY (tenant_id,registration_id)
    REFERENCES filebelt_mcp.registrations(tenant_id,id),
  FOREIGN KEY (tenant_id,created_by) REFERENCES public.principals(tenant_id,id),
  CHECK (octet_length(capability_fingerprint) = 32),
  CHECK (jsonb_typeof(constraints) = 'object'),
  CHECK (jsonb_typeof(quota) = 'object'),
  CHECK (expires_at <= created_at + interval '30 days')
);

CREATE TABLE filebelt_mcp.service_grant_data_grants (
  tenant_id uuid NOT NULL, service_grant_id uuid NOT NULL, data_grant_id uuid NOT NULL,
  PRIMARY KEY (tenant_id,service_grant_id,data_grant_id),
  FOREIGN KEY (tenant_id,service_grant_id)
    REFERENCES filebelt_mcp.service_invocation_grants(tenant_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,data_grant_id)
    REFERENCES filebelt_mcp.data_grants(tenant_id,id)
);

CREATE TABLE filebelt_mcp.oauth_attempts (
  tenant_id uuid NOT NULL, id uuid NOT NULL, registration_id uuid NOT NULL,
  owner_principal_id uuid NOT NULL, session_id uuid NOT NULL, state_digest bytea NOT NULL,
  credential_generation bigint NOT NULL CHECK (credential_generation > 0),
  issuer text NOT NULL, redirect_path text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,state_digest),
  FOREIGN KEY (tenant_id,owner_principal_id,registration_id)
    REFERENCES filebelt_mcp.registrations(tenant_id,owner_principal_id,id),
  CHECK (expires_at <= created_at + interval '10 minutes')
);
CREATE INDEX oauth_attempts_retention
  ON filebelt_mcp.oauth_attempts (tenant_id,expires_at,consumed_at);

CREATE TABLE filebelt_mcp.invocation_intents (
  tenant_id uuid NOT NULL, id uuid NOT NULL, registration_id uuid NOT NULL,
  principal_id uuid NOT NULL, session_id uuid NOT NULL, application_id text NOT NULL,
  primitive text NOT NULL CHECK (primitive IN ('resource_read','prompt_get','tool_call')),
  capability_fingerprint bytea NOT NULL CHECK (octet_length(capability_fingerprint) = 32),
  argument_digest bytea NOT NULL CHECK (octet_length(argument_digest) = 32),
  attachment_digest bytea NOT NULL CHECK (octet_length(attachment_digest) = 32),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,id,registration_id,principal_id),
  FOREIGN KEY (tenant_id,principal_id,registration_id)
    REFERENCES filebelt_mcp.registrations(tenant_id,owner_principal_id,id),
  CHECK (expires_at <= created_at + interval '5 minutes')
);
CREATE INDEX invocation_intents_retention
  ON filebelt_mcp.invocation_intents (tenant_id,expires_at,consumed_at);
ALTER TABLE filebelt_mcp.approval_rules
  ADD FOREIGN KEY (tenant_id,intent_id,registration_id,principal_id)
    REFERENCES filebelt_mcp.invocation_intents(tenant_id,id,registration_id,principal_id);

CREATE TABLE filebelt_mcp.policy_generations (
  tenant_id uuid PRIMARY KEY REFERENCES public.tenants(id),
  admin_block_generation bigint NOT NULL DEFAULT 1
    CHECK (admin_block_generation > 0),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE filebelt_mcp.runner_slot_admission (
  tenant_id uuid PRIMARY KEY REFERENCES public.tenants(id)
);

CREATE TABLE filebelt_mcp.runner_slot_reservations (
  tenant_id uuid NOT NULL, invocation_id uuid NOT NULL, principal_id uuid NOT NULL,
  lease_expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(), released_at timestamptz,
  PRIMARY KEY (tenant_id,invocation_id),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES public.principals(tenant_id,id)
);
CREATE INDEX runner_slot_reservations_active
  ON filebelt_mcp.runner_slot_reservations (tenant_id,principal_id,lease_expires_at)
  WHERE released_at IS NULL;

CREATE TABLE filebelt_mcp.invocations (
  tenant_id uuid NOT NULL, id uuid NOT NULL, registration_id uuid NOT NULL,
  principal_id uuid NOT NULL, application_id text NOT NULL,
  primitive text NOT NULL CHECK (primitive IN ('resource_read','prompt_get','tool_call')),
  capability_fingerprint bytea NOT NULL, approval_id uuid,
  registration_generation bigint NOT NULL CHECK (registration_generation > 0),
  authority_generation bigint NOT NULL CHECK (authority_generation > 0),
  admin_block_generation bigint NOT NULL CHECK (admin_block_generation > 0),
  state text NOT NULL CHECK (state IN ('pending','running','succeeded','denied','failed','cancelled','interrupted')),
  request_bytes bigint NOT NULL DEFAULT 0 CHECK (request_bytes >= 0),
  response_bytes bigint NOT NULL DEFAULT 0 CHECK (response_bytes >= 0),
  reason_code text, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  started_at timestamptz, finished_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id,principal_id,registration_id)
    REFERENCES filebelt_mcp.registrations(tenant_id,owner_principal_id,id),
  FOREIGN KEY (tenant_id,approval_id,registration_id,principal_id)
    REFERENCES filebelt_mcp.approval_rules(tenant_id,id,registration_id,principal_id),
  CHECK (octet_length(capability_fingerprint) = 32),
  CHECK ((state IN ('succeeded','denied','failed','cancelled','interrupted')) = (finished_at IS NOT NULL))
);
CREATE INDEX invocations_principal_activity
  ON filebelt_mcp.invocations (tenant_id,principal_id,created_at DESC);
CREATE INDEX invocations_active
  ON filebelt_mcp.invocations (tenant_id,principal_id,registration_id,created_at)
  WHERE state IN ('pending','running');

CREATE TABLE filebelt_mcp.invocation_attachments (
  tenant_id uuid NOT NULL, invocation_id uuid NOT NULL, ordinal integer NOT NULL,
  version_id uuid NOT NULL, sent_content boolean NOT NULL, sent_basename boolean NOT NULL,
  sent_media_type boolean NOT NULL, sent_size boolean NOT NULL, bytes_sent bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id,invocation_id,ordinal),
  FOREIGN KEY (tenant_id,invocation_id)
    REFERENCES filebelt_mcp.invocations(tenant_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,version_id) REFERENCES public.file_versions(tenant_id,id),
  CHECK (ordinal BETWEEN 0 AND 3), CHECK (bytes_sent >= 0)
);

CREATE TABLE filebelt_mcp.rate_buckets (
  tenant_id uuid NOT NULL, principal_id uuid NOT NULL, bucket text NOT NULL,
  window_started_at timestamptz NOT NULL, used bigint NOT NULL DEFAULT 0 CHECK (used >= 0),
  limit_value bigint NOT NULL CHECK (limit_value > 0), expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,principal_id,bucket,window_started_at),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES public.principals(tenant_id,id)
);
CREATE INDEX rate_buckets_expiry ON filebelt_mcp.rate_buckets (expires_at);

CREATE TABLE filebelt_mcp.runner_leases (
  tenant_id uuid NOT NULL, invocation_id uuid NOT NULL, pod_name text NOT NULL,
  catalog_entry text NOT NULL, image_digest text NOT NULL,
  controller_id uuid, fencing_token bigint NOT NULL DEFAULT 1 CHECK (fencing_token > 0),
  state text NOT NULL CHECK (state IN ('requested','starting','connected','terminating','deleted','failed')),
  lease_expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,invocation_id), UNIQUE (tenant_id,pod_name),
  FOREIGN KEY (tenant_id,invocation_id)
    REFERENCES filebelt_mcp.invocations(tenant_id,id)
);

CREATE TABLE filebelt_mcp.deletion_tombstones (
  tenant_id uuid NOT NULL, id uuid NOT NULL, object_kind text NOT NULL,
  object_id uuid NOT NULL, owner_principal_id uuid, revocation_generation bigint NOT NULL,
  remote_revocation_deadline timestamptz, remote_revocation_outcome text,
  deleted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,object_kind,object_id),
  FOREIGN KEY (tenant_id,owner_principal_id)
    REFERENCES public.principals(tenant_id,id)
);

CREATE TABLE filebelt_mcp_vault.secret_envelopes (
  tenant_id uuid NOT NULL, registration_id uuid NOT NULL, owner_principal_id uuid NOT NULL,
  issuer text NOT NULL DEFAULT '', secret_kind text NOT NULL
    CHECK (secret_kind IN ('oauth_client','oauth_access','oauth_refresh','bearer','api_key')),
  credential_generation bigint NOT NULL CHECK (credential_generation > 0),
  ciphertext bytea NOT NULL, nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
  wrapped_dek bytea NOT NULL, wrap_nonce bytea NOT NULL CHECK (octet_length(wrap_nonce) = 12),
  kek_generation integer NOT NULL CHECK (kek_generation > 0),
  aad_version integer NOT NULL DEFAULT 1 CHECK (aad_version = 1),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(), deleted_at timestamptz,
  PRIMARY KEY (tenant_id,registration_id,owner_principal_id,issuer,secret_kind),
  UNIQUE (tenant_id,nonce), UNIQUE (tenant_id,wrap_nonce),
  FOREIGN KEY (tenant_id,registration_id)
    REFERENCES filebelt_mcp.registrations(tenant_id,id),
  FOREIGN KEY (tenant_id,owner_principal_id)
    REFERENCES public.principals(tenant_id,id)
);

CREATE TABLE filebelt_mcp_vault.oauth_attempt_secrets (
  tenant_id uuid NOT NULL, attempt_id uuid NOT NULL, registration_id uuid NOT NULL,
  owner_principal_id uuid NOT NULL, ciphertext bytea NOT NULL,
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 12), wrapped_dek bytea NOT NULL,
  wrap_nonce bytea NOT NULL CHECK (octet_length(wrap_nonce) = 12),
  kek_generation integer NOT NULL CHECK (kek_generation > 0),
  aad_version integer NOT NULL DEFAULT 1 CHECK (aad_version = 1),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,attempt_id), UNIQUE (tenant_id,nonce), UNIQUE (tenant_id,wrap_nonce),
  FOREIGN KEY (tenant_id,attempt_id)
    REFERENCES filebelt_mcp.oauth_attempts(tenant_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,registration_id)
    REFERENCES filebelt_mcp.registrations(tenant_id,id),
  FOREIGN KEY (tenant_id,owner_principal_id)
    REFERENCES public.principals(tenant_id,id)
);

-- Configuration replacement is a broker-only, vault-aware transaction. The
-- caller never receives or supplies ciphertext, and direct configuration DML
-- is not granted to the broker.
CREATE FUNCTION filebelt_mcp.replace_registration_configuration_and_erase(
  p_tenant_id uuid, p_registration_id uuid, p_owner_principal_id uuid,
  p_expected_revision bigint, p_display_name text, p_description text,
  p_endpoint_uri text, p_trust_profile text, p_catalog_entry text, p_policy jsonb
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF length(p_display_name) NOT BETWEEN 1 AND 255 OR
     length(p_description) > 1000 OR jsonb_typeof(p_policy) <> 'object' THEN
    RAISE EXCEPTION 'invalid MCP registration configuration' USING ERRCODE='22023';
  END IF;
  PERFORM 1 FROM filebelt_mcp.registrations
    WHERE tenant_id=p_tenant_id AND id=p_registration_id
      AND owner_principal_id=p_owner_principal_id AND revision=p_expected_revision
      AND revoked_at IS NULL AND deleted_at IS NULL
    FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'stale MCP registration configuration' USING ERRCODE='40001';
  END IF;
  DELETE FROM filebelt_mcp.oauth_attempts
    WHERE tenant_id=p_tenant_id AND registration_id=p_registration_id
      AND owner_principal_id=p_owner_principal_id;
  DELETE FROM filebelt_mcp_vault.secret_envelopes
    WHERE tenant_id=p_tenant_id AND registration_id=p_registration_id
      AND owner_principal_id=p_owner_principal_id;
  UPDATE filebelt_mcp.registrations SET
    display_name=p_display_name, description=p_description,
    endpoint_uri=p_endpoint_uri, trust_profile=p_trust_profile,
    catalog_entry=p_catalog_entry, policy=p_policy, enabled=false,
    validation_state='never_tested', authentication_state='required',
    capability_state='undiscovered', quarantine_state='clear',
    protocol_version=NULL, credential_kind='none', revision=revision+1,
    revocation_generation=revocation_generation+1,
    credential_generation=credential_generation+1,
    updated_at=clock_timestamp()
    WHERE tenant_id=p_tenant_id AND id=p_registration_id
      AND owner_principal_id=p_owner_principal_id AND revision=p_expected_revision;
END
$$;

-- Registration revocation invalidates all active delegated policy in the same
-- authoritative transaction. Ciphertext remains available only for bounded
-- remote revocation and is then cryptographically erased by the broker.
CREATE FUNCTION filebelt_mcp.invalidate_registration_policy() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.revocation_generation > OLD.revocation_generation OR
     (NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL) THEN
    UPDATE filebelt_mcp.approval_rules SET revoked_at=COALESCE(revoked_at,clock_timestamp())
      WHERE tenant_id=NEW.tenant_id AND registration_id=NEW.id AND revoked_at IS NULL;
    UPDATE filebelt_mcp.service_invocation_grants
      SET revoked_at=COALESCE(revoked_at,clock_timestamp())
      WHERE tenant_id=NEW.tenant_id AND registration_id=NEW.id AND revoked_at IS NULL;
    UPDATE filebelt_mcp.data_grants
      SET revoked_at=COALESCE(revoked_at,clock_timestamp())
      WHERE tenant_id=NEW.tenant_id AND registration_id=NEW.id AND revoked_at IS NULL;
    UPDATE filebelt_mcp.capability_snapshots
      SET superseded_at=COALESCE(superseded_at,clock_timestamp())
      WHERE tenant_id=NEW.tenant_id AND registration_id=NEW.id AND superseded_at IS NULL;
    UPDATE filebelt_mcp.capability_reviews
      SET revoked_at=COALESCE(revoked_at,clock_timestamp())
      WHERE tenant_id=NEW.tenant_id AND registration_id=NEW.id AND revoked_at IS NULL;
    UPDATE filebelt_mcp.invocations SET state='cancelled',finished_at=clock_timestamp(),
      reason_code='mcp.registration_revoked'
      WHERE tenant_id=NEW.tenant_id AND registration_id=NEW.id
        AND state IN ('pending','running');
  END IF;
  RETURN NULL;
END
$$;
CREATE TRIGGER registration_policy_invalidation
AFTER UPDATE OF revocation_generation,revoked_at ON filebelt_mcp.registrations
FOR EACH ROW EXECUTE FUNCTION filebelt_mcp.invalidate_registration_policy();

CREATE FUNCTION filebelt_mcp.invalidate_service_policy() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE public.principals
    SET disabled_at=CASE WHEN NEW.status = 'active' THEN NULL ELSE clock_timestamp() END,
        generation=generation+1
    WHERE tenant_id=NEW.tenant_id AND id=NEW.principal_id;
  IF NEW.status <> 'active' OR NEW.revocation_generation > OLD.revocation_generation THEN
    UPDATE filebelt_mcp.service_invocation_grants
      SET revoked_at=COALESCE(revoked_at,clock_timestamp())
      WHERE tenant_id=NEW.tenant_id AND service_id=NEW.id AND revoked_at IS NULL;
    UPDATE filebelt_mcp.invocations
      SET state='cancelled',finished_at=clock_timestamp(),reason_code='mcp.service_revoked'
      WHERE tenant_id=NEW.tenant_id AND principal_id=NEW.principal_id
        AND state IN ('pending','running');
  END IF;
  IF NEW.status <> 'active' THEN
    UPDATE filebelt_mcp.registrations
      SET enabled=false,revocation_generation=revocation_generation+1,
          revision=revision+1,updated_at=clock_timestamp()
      WHERE tenant_id=NEW.tenant_id AND owner_principal_id=NEW.principal_id
        AND deleted_at IS NULL;
  END IF;
  IF NEW.status = 'deleted' THEN
    UPDATE filebelt_mcp.data_grants
      SET revoked_at=COALESCE(revoked_at,clock_timestamp())
      WHERE tenant_id=NEW.tenant_id AND principal_id=NEW.principal_id
        AND revoked_at IS NULL;
  END IF;
  RETURN NULL;
END
$$;
CREATE TRIGGER service_policy_invalidation
AFTER UPDATE OF status,revocation_generation ON filebelt_mcp.service_principals
FOR EACH ROW WHEN (
  OLD.status IS DISTINCT FROM NEW.status OR
  OLD.revocation_generation IS DISTINCT FROM NEW.revocation_generation
) EXECUTE FUNCTION filebelt_mcp.invalidate_service_policy();

CREATE FUNCTION filebelt_mcp.invalidate_template_policy() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT NEW.enabled OR NEW.revocation_generation > OLD.revocation_generation THEN
    UPDATE filebelt_mcp.registrations
      SET enabled=false,revocation_generation=revocation_generation+1,
          revision=revision+1,updated_at=clock_timestamp()
      WHERE tenant_id=NEW.tenant_id AND template_id=NEW.id AND deleted_at IS NULL;
  END IF;
  RETURN NULL;
END
$$;
CREATE TRIGGER template_policy_invalidation
AFTER UPDATE OF enabled,revocation_generation ON filebelt_mcp.managed_templates
FOR EACH ROW WHEN (
  OLD.enabled IS DISTINCT FROM NEW.enabled OR
  OLD.revocation_generation IS DISTINCT FROM NEW.revocation_generation
) EXECUTE FUNCTION filebelt_mcp.invalidate_template_policy();
