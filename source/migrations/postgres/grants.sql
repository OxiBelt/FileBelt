-- SPDX-License-Identifier: Apache-2.0
-- Run as the database owner after every migration. There are deliberately no
-- default privileges: newly added objects remain inaccessible until this
-- reviewed allowlist and the verifier are updated.

REVOKE ALL ON SCHEMA public, filebelt_mcp, filebelt_mcp_vault FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public, filebelt_mcp, filebelt_mcp_vault
  FROM filebelt_api, filebelt_io, filebelt_maintenance,
       filebelt_audit_exporter, filebelt_recovery, filebelt_mcp_broker;
REVOKE CREATE ON SCHEMA public, filebelt_mcp, filebelt_mcp_vault
  FROM filebelt_api, filebelt_io, filebelt_maintenance,
       filebelt_audit_exporter, filebelt_recovery, filebelt_mcp_broker;

GRANT USAGE ON SCHEMA public
  TO filebelt_api, filebelt_io, filebelt_maintenance,
     filebelt_audit_exporter, filebelt_recovery, filebelt_mcp_broker;
GRANT USAGE ON SCHEMA filebelt_mcp TO filebelt_api, filebelt_recovery, filebelt_mcp_broker;
GRANT USAGE ON SCHEMA filebelt_mcp_vault TO filebelt_recovery, filebelt_mcp_broker;

-- The API's public-schema privileges are intentionally explicit. Do not
-- restore an ALL TABLES grant: it would silently expose future policy or
-- credential tables.
GRANT SELECT, INSERT, UPDATE ON
  tenants, principals, users, external_identities, tenant_admin_bindings,
  groups, group_memberships, drives, nodes, node_ancestry, acl_entries,
  api_sessions, oidc_login_attempts, user_preferences, storage_backends,
  payload_objects, upload_sessions, upload_parts, file_versions,
  quota_reservations, share_links, direct_shares, capability_nonces,
  authorization_generations, jobs, job_attempts, outbox_events,
  consumer_deduplication, notifications, idempotency_records
  TO filebelt_api;
GRANT SELECT, INSERT ON audit_events TO filebelt_api;
GRANT DELETE ON authorization_generations, acl_entries, oidc_login_attempts TO filebelt_api;

GRANT SELECT (id, slug) ON tenants TO filebelt_io, filebelt_maintenance;
GRANT SELECT, UPDATE ON payload_objects, upload_sessions, upload_parts TO filebelt_io;
GRANT SELECT ON storage_backends TO filebelt_io;
GRANT UPDATE (capacity_total_bytes, capacity_free_bytes, capacity_checked_at, storage_ready)
  ON storage_backends TO filebelt_io;
GRANT SELECT, INSERT ON capability_nonces TO filebelt_io;
GRANT SELECT ON authorization_generations TO filebelt_io;

GRANT SELECT, INSERT, UPDATE, DELETE ON jobs, job_attempts, outbox_events,
  consumer_deduplication, payload_objects, upload_sessions, upload_parts,
  quota_reservations, capability_nonces TO filebelt_maintenance;
GRANT SELECT (tenant_id, id, reserved_bytes), UPDATE (reserved_bytes)
  ON drives TO filebelt_maintenance;

GRANT SELECT (id, slug) ON tenants TO filebelt_audit_exporter;
GRANT SELECT (
  tenant_id, id, actor_principal_id, target_principal_id, resource_id, action,
  outcome, reason_code, privacy_visible, request_id, details, occurred_at
) ON audit_events TO filebelt_audit_exporter;

GRANT SELECT (id, slug) ON tenants TO filebelt_recovery;
GRANT SELECT (tenant_id, id) ON principals, users, groups, nodes, drives
  TO filebelt_recovery;
GRANT SELECT (tenant_id, id, kind) ON storage_backends TO filebelt_recovery;
GRANT SELECT (
  tenant_id, id, drive_id, backend_id, locator, layout, state, size_bytes, blake3
) ON payload_objects TO filebelt_recovery;
GRANT SELECT (tenant_id, id, node_id, payload_id, size_bytes, blake3)
  ON file_versions TO filebelt_recovery;
GRANT SELECT (tenant_id, id, state) ON jobs TO filebelt_recovery;
GRANT SELECT (tenant_id, id, published_at) ON outbox_events TO filebelt_recovery;
GRANT SELECT (tenant_id, id, occurred_at) ON audit_events TO filebelt_recovery;
GRANT SELECT (tenant_id, token_key_generation) ON api_sessions, share_links
  TO filebelt_recovery;
GRANT SELECT (version, description, success, checksum) ON _sqlx_migrations
  TO filebelt_recovery;

-- API access is limited to non-secret MCP control-plane state. Secret writes
-- are mediated by the broker and no API grant exists on filebelt_mcp_vault.
GRANT SELECT, INSERT, UPDATE ON
  filebelt_mcp.service_principals, filebelt_mcp.service_identity_bindings,
  filebelt_mcp.managed_templates, filebelt_mcp.template_assignments,
  filebelt_mcp.admin_block_rules,
  filebelt_mcp.capability_reviews,
  filebelt_mcp.approval_rules, filebelt_mcp.data_grants,
  filebelt_mcp.service_invocation_grants,
  filebelt_mcp.service_grant_data_grants, filebelt_mcp.invocation_intents,
  filebelt_mcp.policy_generations
  TO filebelt_api;
GRANT SELECT, INSERT ON filebelt_mcp.registrations TO filebelt_api;
GRANT UPDATE (
  validation_state, authentication_state, capability_state, quarantine_state,
  enabled, protocol_version, revision, revocation_generation,
  credential_generation, credential_kind, revoked_at, deleted_at, updated_at
) ON filebelt_mcp.registrations TO filebelt_api;
GRANT SELECT ON filebelt_mcp.capability_snapshots, filebelt_mcp.capabilities,
  filebelt_mcp.oauth_attempts, filebelt_mcp.invocations,
  filebelt_mcp.invocation_attachments, filebelt_mcp.deletion_tombstones
  TO filebelt_api;
GRANT INSERT ON filebelt_mcp.deletion_tombstones TO filebelt_api;
GRANT INSERT ON filebelt_mcp.invocations TO filebelt_api;
GRANT UPDATE (superseded_at) ON filebelt_mcp.capability_snapshots TO filebelt_api;
GRANT UPDATE (state, response_bytes, reason_code, finished_at)
  ON filebelt_mcp.invocations TO filebelt_api;

-- The broker can revalidate principal generations but cannot read sessions,
-- OIDC identity, ACL rows, user records, or payload locators.
GRANT SELECT (id, slug) ON tenants TO filebelt_mcp_broker;
GRANT SELECT (tenant_id, id, kind, generation, disabled_at) ON principals
  TO filebelt_mcp_broker;
GRANT SELECT (tenant_id, id, drive_id, acl_generation, namespace_generation)
  ON nodes TO filebelt_mcp_broker;
GRANT SELECT (tenant_id, id, node_id) ON file_versions TO filebelt_mcp_broker;
GRANT SELECT ON
  filebelt_mcp.registrations, filebelt_mcp.capability_snapshots,
  filebelt_mcp.capabilities, filebelt_mcp.capability_reviews,
  filebelt_mcp.approval_rules, filebelt_mcp.data_grants,
  filebelt_mcp.service_invocation_grants, filebelt_mcp.service_grant_data_grants,
  filebelt_mcp.oauth_attempts, filebelt_mcp.invocation_intents,
  filebelt_mcp.invocations, filebelt_mcp.invocation_attachments,
  filebelt_mcp.rate_buckets, filebelt_mcp.runner_leases,
  filebelt_mcp.deletion_tombstones,
  filebelt_mcp.service_principals, filebelt_mcp.service_identity_bindings,
  filebelt_mcp.managed_templates, filebelt_mcp.template_assignments,
  filebelt_mcp.admin_block_rules
  TO filebelt_mcp_broker;
GRANT SELECT, INSERT ON filebelt_mcp.runner_slot_admission TO filebelt_mcp_broker;
GRANT SELECT, INSERT, UPDATE ON filebelt_mcp.runner_slot_reservations
  TO filebelt_mcp_broker;
GRANT SELECT, INSERT ON filebelt_mcp.policy_generations TO filebelt_mcp_broker;
GRANT INSERT ON filebelt_mcp.oauth_attempts, filebelt_mcp.invocation_attachments,
  filebelt_mcp.rate_buckets TO filebelt_mcp_broker;
GRANT UPDATE (
  validation_state, authentication_state, capability_state, quarantine_state,
  enabled, protocol_version, revision, revocation_generation,
  credential_generation, credential_kind, updated_at
) ON filebelt_mcp.registrations TO filebelt_mcp_broker;
GRANT UPDATE (consumed_at, revoked_at)
  ON filebelt_mcp.approval_rules TO filebelt_mcp_broker;
GRANT UPDATE (revoked_at)
  ON filebelt_mcp.service_invocation_grants TO filebelt_mcp_broker;
GRANT UPDATE (revoked_at) ON filebelt_mcp.data_grants TO filebelt_mcp_broker;
GRANT UPDATE (revoked_at) ON filebelt_mcp.capability_reviews TO filebelt_mcp_broker;
GRANT UPDATE (superseded_at) ON filebelt_mcp.capability_snapshots TO filebelt_mcp_broker;
GRANT UPDATE (consumed_at) ON filebelt_mcp.oauth_attempts TO filebelt_mcp_broker;
GRANT UPDATE (consumed_at) ON filebelt_mcp.invocation_intents TO filebelt_mcp_broker;
GRANT UPDATE (state, response_bytes, reason_code, finished_at)
  ON filebelt_mcp.invocations TO filebelt_mcp_broker;
GRANT UPDATE (used, limit_value, expires_at)
  ON filebelt_mcp.rate_buckets TO filebelt_mcp_broker;
GRANT UPDATE (remote_revocation_deadline, remote_revocation_outcome)
  ON filebelt_mcp.deletion_tombstones TO filebelt_mcp_broker;
GRANT DELETE ON filebelt_mcp.oauth_attempts, filebelt_mcp.rate_buckets
  TO filebelt_mcp_broker;
GRANT SELECT, INSERT, UPDATE, DELETE ON filebelt_mcp_vault.secret_envelopes
  TO filebelt_mcp_broker;
GRANT SELECT, INSERT, DELETE ON filebelt_mcp_vault.oauth_attempt_secrets
  TO filebelt_mcp_broker;

-- Recovery can prove that every encrypted row has a recoverable key generation
-- without gaining ciphertext, nonces, wrapped keys, issuers, or secret kinds.
GRANT SELECT (tenant_id, registration_id, kek_generation, deleted_at)
  ON filebelt_mcp_vault.secret_envelopes TO filebelt_recovery;
GRANT SELECT (tenant_id, attempt_id, kek_generation)
  ON filebelt_mcp_vault.oauth_attempt_secrets TO filebelt_recovery;
GRANT SELECT (tenant_id, id, deleted_at)
  ON filebelt_mcp.registrations TO filebelt_recovery;
GRANT SELECT (tenant_id, invocation_id, principal_id, lease_expires_at, released_at)
  ON filebelt_mcp.runner_slot_reservations TO filebelt_recovery;
GRANT SELECT (tenant_id, id, object_kind, object_id, revocation_generation, deleted_at)
  ON filebelt_mcp.deletion_tombstones TO filebelt_recovery;

REVOKE ALL ON FUNCTION filebelt_mcp.require_principal_kind() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mcp.require_service_principal() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mcp.invalidate_registration_policy() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mcp.invalidate_service_policy() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mcp.invalidate_template_policy() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.invalidate_acl_capability_projection() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.invalidate_membership_capability_projection() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.invalidate_drive_capability_projection() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.invalidate_node_capability_projection() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.invalidate_session_capability_projection() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.invalidate_user_capability_projection() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.invalidate_principal_capability_projection() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mcp.replace_registration_configuration_and_erase(
  uuid,uuid,uuid,bigint,text,text,text,text,text,jsonb
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION filebelt_mcp.replace_registration_configuration_and_erase(
  uuid,uuid,uuid,bigint,text,text,text,text,text,jsonb
) TO filebelt_mcp_broker;
