-- SPDX-License-Identifier: Apache-2.0
-- Run as the database owner after every migration. There are deliberately no
-- default privileges: newly added objects remain inaccessible until this
-- reviewed allowlist and the verifier are updated.

-- End the database-scoped migration window opened by roles.sql. Keep this
-- dynamic so deployments are not required to name their database `filebelt`.
DO $$
BEGIN
  EXECUTE format(
    'REVOKE CREATE ON DATABASE %I FROM filebelt_migrator',
    current_database()
  );
END
$$;

REVOKE ALL ON SCHEMA public, filebelt_mcp, filebelt_mcp_vault, filebelt_collaboration,
  filebelt_mount, filebelt_mount_vault, filebelt_document, filebelt_media,
  filebelt_phase8, filebelt_security, filebelt_revision FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public, filebelt_mcp, filebelt_mcp_vault,
  filebelt_collaboration, filebelt_mount, filebelt_mount_vault, filebelt_document,
  filebelt_media, filebelt_phase8, filebelt_security, filebelt_revision
  FROM filebelt_api, filebelt_io, filebelt_maintenance,
       filebelt_audit_exporter, filebelt_recovery, filebelt_mcp_broker,
       filebelt_collaboration, filebelt_vfs, filebelt_headscale_sync,
       filebelt_document, filebelt_media, filebelt_revision;

-- The no-login definer can take the row locks required by the fixed-shape
-- collaboration functions without extending either runtime role's DML.
REVOKE ALL ON ALL TABLES IN SCHEMA public, filebelt_mcp, filebelt_mcp_vault,
  filebelt_collaboration, filebelt_mount, filebelt_mount_vault, filebelt_document,
  filebelt_media, filebelt_phase8, filebelt_security, filebelt_revision
  FROM filebelt_collaboration_definer;
REVOKE CREATE ON SCHEMA public, filebelt_mcp, filebelt_mcp_vault,
  filebelt_collaboration, filebelt_mount, filebelt_mount_vault, filebelt_document,
  filebelt_media, filebelt_phase8, filebelt_security, filebelt_revision
  FROM filebelt_api, filebelt_io, filebelt_maintenance,
       filebelt_audit_exporter, filebelt_recovery, filebelt_mcp_broker,
       filebelt_collaboration, filebelt_vfs, filebelt_headscale_sync,
       filebelt_document, filebelt_media, filebelt_revision;
-- Converge databases that applied an earlier revision-role draft. The I/O
-- worker receives signed physical locators and never queries revision metadata.
REVOKE USAGE ON SCHEMA filebelt_revision FROM filebelt_io;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA filebelt_revision FROM filebelt_io;

GRANT USAGE ON SCHEMA public
  TO filebelt_api, filebelt_io, filebelt_maintenance,
     filebelt_audit_exporter, filebelt_recovery, filebelt_mcp_broker,
     filebelt_collaboration, filebelt_vfs, filebelt_headscale_sync,
     filebelt_document, filebelt_media, filebelt_revision;
GRANT USAGE ON SCHEMA public, filebelt_collaboration
  TO filebelt_collaboration_definer;
GRANT USAGE ON SCHEMA filebelt_mcp
  TO filebelt_api, filebelt_maintenance, filebelt_recovery, filebelt_mcp_broker,
     filebelt_collaboration;
GRANT USAGE ON SCHEMA filebelt_mcp_vault TO filebelt_recovery, filebelt_mcp_broker;
GRANT USAGE ON SCHEMA filebelt_collaboration
  TO filebelt_api, filebelt_io, filebelt_maintenance, filebelt_recovery,
     filebelt_collaboration;
GRANT USAGE ON SCHEMA filebelt_mount
  TO filebelt_api, filebelt_io, filebelt_maintenance, filebelt_recovery,
     filebelt_vfs, filebelt_headscale_sync;
GRANT USAGE ON SCHEMA filebelt_mount_vault
  TO filebelt_maintenance, filebelt_recovery, filebelt_vfs;
GRANT USAGE ON SCHEMA filebelt_document
  TO filebelt_document, filebelt_io, filebelt_maintenance, filebelt_recovery;
GRANT USAGE ON SCHEMA filebelt_media
  TO filebelt_api, filebelt_io, filebelt_maintenance, filebelt_recovery,
     filebelt_media;
GRANT USAGE ON SCHEMA filebelt_phase8
  TO filebelt_api, filebelt_io, filebelt_maintenance, filebelt_recovery,
     filebelt_collaboration, filebelt_vfs, filebelt_document, filebelt_media;
GRANT USAGE ON SCHEMA filebelt_security TO filebelt_api, filebelt_recovery;
GRANT USAGE ON SCHEMA filebelt_revision
  TO filebelt_api, filebelt_maintenance, filebelt_recovery,
     filebelt_collaboration, filebelt_vfs, filebelt_document, filebelt_revision;
GRANT EXECUTE ON FUNCTION filebelt_revision.attach_legacy_content()
  TO filebelt_api, filebelt_document, filebelt_collaboration, filebelt_revision;
GRANT EXECUTE ON FUNCTION filebelt_revision.create_tenant_activation_state()
  TO filebelt_api;

GRANT SELECT ON filebelt_revision.contents, filebelt_revision.git_revisions,
  filebelt_revision.git_repositories, filebelt_revision.chunk_manifests,
  filebelt_revision.activation_state, filebelt_revision.holds
  TO filebelt_api;

GRANT SELECT, INSERT, UPDATE, DELETE ON
  filebelt_revision.contents, filebelt_revision.git_repositories,
  filebelt_revision.git_revisions, filebelt_revision.chunk_objects,
  filebelt_revision.chunk_manifests, filebelt_revision.chunk_members,
  filebelt_revision.operations, filebelt_revision.backfill_jobs,
  filebelt_revision.holds, filebelt_revision.activation_state
  TO filebelt_revision;
GRANT SELECT (id,slug) ON tenants TO filebelt_revision;
GRANT SELECT (tenant_id,id,kind,generation,disabled_at) ON principals
  TO filebelt_revision;
GRANT SELECT (tenant_id,id,principal_id,status) ON users TO filebelt_revision;
GRANT SELECT (tenant_id,id,user_id,principal_id,idle_expires_at,absolute_expires_at,revoked_at)
  ON api_sessions TO filebelt_revision;
GRANT SELECT ON groups, group_memberships, node_ancestry, acl_entries,
  authorization_generations TO filebelt_revision;
GRANT SELECT ON drives TO filebelt_revision;
GRANT UPDATE (reserved_bytes,used_physical_bytes) ON drives TO filebelt_revision;
GRANT SELECT ON nodes TO filebelt_revision;
GRANT UPDATE (head_version_id,namespace_generation,updated_at)
  ON nodes TO filebelt_revision;
GRANT SELECT, INSERT ON file_versions, audit_events, outbox_events, jobs
  TO filebelt_revision;

GRANT SELECT, INSERT, UPDATE, DELETE ON filebelt_revision.chunk_objects,
  filebelt_revision.chunk_manifests, filebelt_revision.chunk_members,
  filebelt_revision.operations, filebelt_revision.backfill_jobs,
  filebelt_revision.holds TO filebelt_maintenance;
GRANT SELECT ON filebelt_revision.contents, filebelt_revision.git_repositories,
  filebelt_revision.git_revisions, filebelt_revision.chunk_objects,
  filebelt_revision.chunk_manifests, filebelt_revision.chunk_members,
  filebelt_revision.operations, filebelt_revision.backfill_jobs,
  filebelt_revision.holds, filebelt_revision.activation_state
  TO filebelt_recovery;

-- The API's public-schema privileges are intentionally explicit. Do not
-- restore an ALL TABLES grant: it would silently expose future policy or
-- credential tables.
GRANT SELECT, INSERT, UPDATE ON
  tenants, principals, users, external_identities, tenant_admin_bindings,
  groups, group_memberships, drives, nodes, node_ancestry, acl_entries,
  node_xattrs,
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
GRANT SELECT (tenant_id,node_id,id,payload_id,size_bytes) ON file_versions TO filebelt_io;
GRANT SELECT (tenant_id,payload_id) ON file_versions TO filebelt_maintenance;
GRANT UPDATE (capacity_total_bytes, capacity_free_bytes, capacity_checked_at, storage_ready)
  ON storage_backends TO filebelt_io;
GRANT SELECT, INSERT ON capability_nonces TO filebelt_io;
GRANT SELECT ON authorization_generations TO filebelt_io;

GRANT SELECT, INSERT, UPDATE, DELETE ON jobs, job_attempts, outbox_events,
  consumer_deduplication, payload_objects, upload_sessions, upload_parts,
  quota_reservations, capability_nonces TO filebelt_maintenance;
GRANT SELECT (tenant_id, id, reserved_bytes, used_physical_bytes),
  UPDATE (reserved_bytes, used_physical_bytes)
  ON drives TO filebelt_maintenance;

GRANT SELECT (id, slug) ON tenants TO filebelt_audit_exporter;
GRANT SELECT (
  tenant_id, id, actor_principal_id, target_principal_id, resource_id, action,
  outcome, reason_code, privacy_visible, request_id, details, occurred_at
) ON audit_events TO filebelt_audit_exporter;

GRANT SELECT (id, slug) ON tenants TO filebelt_recovery;
GRANT SELECT (tenant_id, id) ON principals, users, groups, drives
  TO filebelt_recovery;
GRANT SELECT (tenant_id,id,kind,handle_generation) ON nodes TO filebelt_recovery;
GRANT SELECT (tenant_id,source) ON acl_entries TO filebelt_recovery;
GRANT SELECT (tenant_id) ON node_xattrs TO filebelt_recovery;
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
GRANT INSERT ON filebelt_mcp.capability_snapshots, filebelt_mcp.capabilities
  TO filebelt_api;
GRANT UPDATE (superseded_at) ON filebelt_mcp.capability_snapshots TO filebelt_api;
GRANT SELECT (tenant_id, principal_id, operation_id, result, api_completed_at)
  ON filebelt_mcp.broker_operation_receipts TO filebelt_api;
GRANT UPDATE (api_completed_at) ON filebelt_mcp.broker_operation_receipts TO filebelt_api;
GRANT UPDATE (state, response_bytes, reason_code, semantic_output_digest, finished_at)
  ON filebelt_mcp.invocations TO filebelt_api;

-- The broker can revalidate principal generations but cannot read sessions,
-- OIDC identity, ACL rows, user records, or payload locators.
GRANT SELECT (id, slug) ON tenants TO filebelt_mcp_broker;
GRANT SELECT (tenant_id, id, kind, generation, disabled_at) ON principals
  TO filebelt_mcp_broker;
GRANT SELECT (tenant_id, id, acl_generation) ON drives TO filebelt_mcp_broker;
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
GRANT SELECT (
  tenant_id, principal_id, registration_id, operation, operation_id,
  request_fingerprint, result, api_completed_at, expires_at
) ON filebelt_mcp.broker_operation_receipts TO filebelt_mcp_broker;
GRANT INSERT (
  tenant_id, principal_id, registration_id, operation, operation_id, request_fingerprint
) ON filebelt_mcp.broker_operation_receipts TO filebelt_mcp_broker;
GRANT UPDATE (
  registration_id, operation, request_fingerprint, result, api_completed_at,
  created_at, expires_at
) ON filebelt_mcp.broker_operation_receipts TO filebelt_mcp_broker;
GRANT SELECT (
  tenant_id, principal_id, operation_id, result, api_completed_at, expires_at
) ON filebelt_mcp.broker_operation_receipts TO filebelt_maintenance;
GRANT DELETE ON filebelt_mcp.broker_operation_receipts TO filebelt_maintenance;
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

-- Collaboration control and data roles are deliberately disjoint. The API
-- authorizes rooms and commits versions; the collaboration role sequences
-- durable CRDT manifests but cannot mutate nodes or file_versions.
GRANT SELECT, INSERT, UPDATE ON
  filebelt_collaboration.rooms, filebelt_collaboration.epochs,
  filebelt_collaboration.join_grants, filebelt_collaboration.checkpoints,
  filebelt_collaboration.import_intents
  TO filebelt_api;
GRANT SELECT ON filebelt_collaboration.update_groups,
  filebelt_collaboration.snapshots, filebelt_collaboration.objects
  TO filebelt_api;

GRANT SELECT (id, slug) ON tenants TO filebelt_collaboration;
GRANT SELECT (tenant_id,id,kind,generation,disabled_at) ON principals
  TO filebelt_collaboration;
GRANT SELECT (tenant_id,id,kind,storage_ready,capacity_total_bytes,capacity_free_bytes,capacity_checked_at)
  ON storage_backends TO filebelt_collaboration;
GRANT SELECT (tenant_id,id,user_id,principal_id,idle_expires_at,absolute_expires_at,revoked_at)
  ON api_sessions TO filebelt_collaboration;
GRANT SELECT (tenant_id,id,status) ON users TO filebelt_collaboration;
GRANT SELECT (tenant_id,id,drive_id,head_version_id,acl_generation,namespace_generation,trash_root_id)
  ON nodes TO filebelt_collaboration;
GRANT SELECT (tenant_id,id,node_id,size_bytes,blake3,media_type)
  ON file_versions TO filebelt_collaboration;
GRANT SELECT (tenant_id,id,acl_generation,namespace_generation,reserved_bytes,used_physical_bytes,quota_bytes),
  UPDATE (reserved_bytes,used_physical_bytes) ON drives TO filebelt_collaboration;
GRANT SELECT ON authorization_generations TO filebelt_collaboration;
GRANT SELECT (tenant_id,id,principal_id,application_id,state,semantic_node_id,
  semantic_base_version_id,semantic_input_digest,semantic_output_digest)
  ON filebelt_mcp.invocations TO filebelt_collaboration;
GRANT SELECT, INSERT, UPDATE ON filebelt_collaboration.payload_objects
  TO filebelt_collaboration;
GRANT SELECT, UPDATE ON filebelt_collaboration.payload_objects
  TO filebelt_io, filebelt_maintenance;
GRANT SELECT, INSERT, UPDATE ON
  filebelt_collaboration.rooms, filebelt_collaboration.epochs,
  filebelt_collaboration.objects, filebelt_collaboration.object_reservations,
  filebelt_collaboration.update_groups, filebelt_collaboration.update_chunks,
  filebelt_collaboration.snapshots, filebelt_collaboration.join_grants,
  filebelt_collaboration.checkpoints, filebelt_collaboration.leases,
  filebelt_collaboration.participants
  TO filebelt_collaboration;
GRANT DELETE ON filebelt_collaboration.participants
  TO filebelt_collaboration;
ALTER FUNCTION filebelt_collaboration.reserve_posix_storage_backend(uuid)
  OWNER TO filebelt_collaboration_definer;
ALTER FUNCTION filebelt_collaboration.lock_authorization_fence(uuid,uuid,uuid,uuid,uuid)
  OWNER TO filebelt_collaboration_definer;
ALTER FUNCTION filebelt_collaboration.lock_epoch(uuid,uuid,bigint)
  OWNER TO filebelt_collaboration_definer;
ALTER FUNCTION filebelt_collaboration.finalize_object(uuid,uuid,bigint,bytea)
  OWNER TO filebelt_collaboration_definer;
GRANT EXECUTE ON FUNCTION
  filebelt_collaboration.reserve_posix_storage_backend(uuid)
  TO filebelt_collaboration;
GRANT EXECUTE ON FUNCTION
  filebelt_collaboration.lock_authorization_fence(uuid,uuid,uuid,uuid,uuid)
  TO filebelt_api, filebelt_io, filebelt_collaboration;
GRANT EXECUTE ON FUNCTION filebelt_collaboration.lock_epoch(uuid,uuid,bigint)
  TO filebelt_io;
GRANT EXECUTE ON FUNCTION
  filebelt_collaboration.finalize_object(uuid,uuid,bigint,bytea)
  TO filebelt_io;
GRANT SELECT, UPDATE ON storage_backends, api_sessions, users, principals, drives, nodes
  TO filebelt_collaboration_definer;
GRANT SELECT, UPDATE ON filebelt_collaboration.epochs
  TO filebelt_collaboration_definer;
GRANT SELECT, UPDATE ON filebelt_collaboration.objects,
  filebelt_collaboration.object_reservations
  TO filebelt_collaboration_definer;
GRANT INSERT ON jobs TO filebelt_collaboration;

GRANT SELECT, UPDATE ON payload_objects TO filebelt_io;
GRANT SELECT ON filebelt_collaboration.objects,
  filebelt_collaboration.object_reservations TO filebelt_io;
GRANT SELECT ON filebelt_collaboration.epochs TO filebelt_io;

GRANT SELECT, UPDATE, DELETE ON
  filebelt_collaboration.epochs,
  filebelt_collaboration.objects, filebelt_collaboration.object_reservations,
  filebelt_collaboration.update_groups, filebelt_collaboration.update_chunks,
  filebelt_collaboration.snapshots, filebelt_collaboration.join_grants,
  filebelt_collaboration.checkpoints, filebelt_collaboration.import_intents,
  filebelt_collaboration.leases, filebelt_collaboration.participants
  TO filebelt_maintenance;

GRANT SELECT ON filebelt_collaboration.rooms, filebelt_collaboration.epochs,
  filebelt_collaboration.objects, filebelt_collaboration.update_groups,
  filebelt_collaboration.snapshots, filebelt_collaboration.checkpoints
  TO filebelt_recovery;
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

-- Mount control-plane reads never expose encrypted verifiers to the API.
GRANT SELECT, INSERT, UPDATE ON
  filebelt_mount.policies, filebelt_mount.credentials,
  filebelt_mount.session_receipts, filebelt_mount.deletion_tombstones
  TO filebelt_api;
GRANT SELECT ON filebelt_mount.headscale_devices, filebelt_mount.sessions
  TO filebelt_api;
GRANT EXECUTE ON FUNCTION filebelt_mount.cancel_credential_operation(uuid,uuid,uuid)
  TO filebelt_api;
GRANT EXECUTE ON FUNCTION filebelt_mount.prepare_credential_creation_operation(uuid,uuid),
  filebelt_mount.cancel_credential_creation_operation(uuid,uuid,uuid,bigint)
  TO filebelt_api;

-- The VFS is the only runtime role that can combine credential verification,
-- authoritative mount state, namespace/ACL projections, and scoped I/O
-- delegation. It still receives no payload filesystem mount.
GRANT SELECT (id,slug) ON tenants TO filebelt_vfs;
GRANT SELECT (tenant_id,id,kind,generation,disabled_at) ON principals TO filebelt_vfs;
GRANT SELECT (tenant_id,id,principal_id,status) ON users TO filebelt_vfs;
GRANT SELECT ON groups, group_memberships, drives, nodes, node_ancestry,
  acl_entries, node_xattrs, direct_shares, file_versions,
  authorization_generations TO filebelt_vfs;
GRANT SELECT, INSERT ON audit_events, outbox_events, capability_nonces TO filebelt_vfs;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  filebelt_mount.policies, filebelt_mount.credentials,
  filebelt_mount.gateway_epochs, filebelt_mount.sessions,
  filebelt_mount.session_receipts, filebelt_mount.handles,
  filebelt_mount.byte_locks, filebelt_mount.leases,
  filebelt_mount.write_sessions, filebelt_mount.write_chunks,
  filebelt_mount.passive_allocations,
  filebelt_mount.authentication_throttles,
  filebelt_mount.deletion_tombstones TO filebelt_vfs;
GRANT SELECT ON filebelt_mount.headscale_devices TO filebelt_vfs;
GRANT SELECT, INSERT, UPDATE, DELETE ON filebelt_mount_vault.secret_envelopes
  TO filebelt_vfs;

-- The document core revalidates common policy, stages UUID-addressed payloads,
-- and commits immutable versions. It cannot read identity emails, browser
-- cookies or adapter-owned callback/JWT state and receives no payload mount.
GRANT SELECT (id,slug) ON tenants TO filebelt_document;
GRANT SELECT ON principals TO filebelt_document;
GRANT SELECT (tenant_id,id,principal_id,status,display_name) ON users TO filebelt_document;
GRANT SELECT (tenant_id,id,user_id,principal_id,idle_expires_at,absolute_expires_at,revoked_at)
  ON api_sessions TO filebelt_document;
GRANT SELECT ON groups, group_memberships, drives, nodes, node_ancestry,
  acl_entries, file_versions, authorization_generations TO filebelt_document;
GRANT UPDATE (head_version_id,acl_generation,updated_at) ON nodes TO filebelt_document;
GRANT UPDATE (acl_generation,reserved_bytes,used_physical_bytes) ON drives TO filebelt_document;
GRANT SELECT, INSERT, UPDATE ON payload_objects TO filebelt_document;
GRANT INSERT ON file_versions, audit_events, outbox_events, jobs TO filebelt_document;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  filebelt_document.sessions, filebelt_document.participants,
  filebelt_document.launch_grants, filebelt_document.revisions,
  filebelt_document.revision_contributors,
  filebelt_document.reconciliation_jobs, filebelt_document.session_events,
  filebelt_document.operation_receipts
  TO filebelt_document;
GRANT SELECT ON filebelt_document.data_migrations TO filebelt_document;
GRANT EXECUTE ON FUNCTION filebelt_document.create_session_principal(uuid,uuid)
  TO filebelt_document;

GRANT SELECT, UPDATE ON filebelt_document.revisions TO filebelt_io;
GRANT INSERT ON filebelt_document.reconciliation_jobs TO filebelt_io;
GRANT SELECT (tenant_id,id,session_principal_id,drive_id,node_id,base_version_id,
  expected_head_version_id,provider_id,state,fencing_token,created_at,absolute_expires_at,
  reconnect_until,close_reason) ON filebelt_document.sessions TO filebelt_io;
GRANT SELECT (tenant_id,id,document_session_id,user_principal_id,api_session_id,mode,state,
  last_activity_at,disconnected_until,membership_generation,drive_acl_generation,
  namespace_generation,resource_acl_generation) ON filebelt_document.participants TO filebelt_io;
GRANT SELECT, UPDATE ON filebelt_document.sessions, filebelt_document.participants TO filebelt_maintenance;
GRANT SELECT, UPDATE, DELETE ON
  filebelt_document.launch_grants, filebelt_document.revisions,
  filebelt_document.revision_contributors,
  filebelt_document.reconciliation_jobs, filebelt_document.session_events,
  filebelt_document.operation_receipts
  TO filebelt_maintenance;
GRANT SELECT ON filebelt_document.sessions TO filebelt_maintenance;
GRANT SELECT ON
  filebelt_document.sessions, filebelt_document.participants,
  filebelt_document.revisions, filebelt_document.revision_contributors,
  filebelt_document.reconciliation_jobs
  TO filebelt_recovery;

-- Headscale synchronization can project external node ownership but cannot
-- read credentials, sessions, ACL rows, payload metadata, or vault content.
GRANT SELECT (id,slug) ON tenants TO filebelt_headscale_sync;
GRANT SELECT (tenant_id,id,kind,generation,disabled_at) ON principals
  TO filebelt_headscale_sync;
GRANT SELECT (tenant_id,id,principal_id,status) ON users TO filebelt_headscale_sync;
GRANT SELECT (tenant_id,user_id,issuer,subject,disabled_at) ON external_identities
  TO filebelt_headscale_sync;
GRANT SELECT, INSERT, UPDATE ON filebelt_mount.headscale_devices
  TO filebelt_headscale_sync;

-- The I/O worker handles immutable range reads and UUID-scoped mount staging
-- only after fbcap2 admission. Lock and policy decisions remain in
-- VFS/PostgreSQL; the I/O role receives no mount-vault access.
GRANT SELECT ON filebelt_mount.write_sessions,
  filebelt_mount.write_chunks TO filebelt_io;
GRANT SELECT ON filebelt_mount.policies, filebelt_mount.credentials,
  filebelt_mount.headscale_devices, filebelt_mount.gateway_epochs,
  filebelt_mount.sessions, filebelt_mount.handles TO filebelt_io;
GRANT SELECT (tenant_id,id,kind,generation,disabled_at) ON principals TO filebelt_io;
GRANT SELECT (tenant_id,id,principal_id,status) ON users TO filebelt_io;
GRANT SELECT (tenant_id,group_id,user_principal_id) ON group_memberships TO filebelt_io;
GRANT SELECT (tenant_id,id,acl_generation) ON drives TO filebelt_io;
GRANT SELECT (tenant_id,drive_id,id,kind,trash_root_id,acl_generation,namespace_generation)
  ON nodes TO filebelt_io;

GRANT SELECT, UPDATE, DELETE ON
  filebelt_mount.sessions, filebelt_mount.session_receipts,
  filebelt_mount.handles, filebelt_mount.byte_locks,
  filebelt_mount.leases, filebelt_mount.write_sessions,
  filebelt_mount.write_chunks, filebelt_mount.passive_allocations,
  filebelt_mount.authentication_throttles TO filebelt_maintenance;
GRANT SELECT, DELETE ON filebelt_mount_vault.secret_envelopes
  TO filebelt_maintenance;

GRANT SELECT ON filebelt_mount.policies, filebelt_mount.credentials,
  filebelt_mount.headscale_devices, filebelt_mount.gateway_epochs,
  filebelt_mount.sessions, filebelt_mount.handles,
  filebelt_mount.byte_locks, filebelt_mount.leases,
  filebelt_mount.write_sessions, filebelt_mount.write_chunks,
  filebelt_mount.deletion_tombstones TO filebelt_recovery;
GRANT SELECT (tenant_id,credential_id,principal_id,state,created_at,cancelled_at)
  ON filebelt_mount.credential_operation_fences TO filebelt_recovery;
GRANT SELECT (tenant_id,principal_id,operation_id,operation_generation,state,
              prepared_at,expires_at,committed_at,cancelled_at)
  ON filebelt_mount.credential_creation_slots TO filebelt_recovery;
GRANT SELECT (name,removed_cancelled_fences,completed_at)
  ON filebelt_mount.credential_creation_cutovers TO filebelt_recovery;
GRANT SELECT (tenant_id,credential_id,kek_generation,secret_kind,created_at)
  ON filebelt_mount_vault.secret_envelopes TO filebelt_recovery;

-- Phase 8 NFS control/recovery projections. The API may manage explicit
-- Kerberos mappings but never reads the keytab or GSS material; VFS owns the
-- replay/reclaim/write-state mutations.
GRANT SELECT, INSERT, UPDATE ON filebelt_mount.nfs_principal_mappings
  TO filebelt_api;
GRANT SELECT ON
  filebelt_mount.nfs_mapping_proposals,
  filebelt_mount.nfs_approved_active_mappings,
  filebelt_mount.nfs_feature_state,
  filebelt_mount.nfs_exports,
  filebelt_mount.nfs_posix_groups,
  filebelt_mount.nfs_posix_users TO filebelt_api;
GRANT UPDATE (state,generation) ON filebelt_mount.nfs_feature_state
  TO filebelt_api;
GRANT INSERT (tenant_id,drive_id,export_id),
  UPDATE (desired_state,desired_generation) ON filebelt_mount.nfs_exports
  TO filebelt_api;
GRANT INSERT (tenant_id,group_id,posix_name,projected_gid)
  ON filebelt_mount.nfs_posix_groups TO filebelt_api;
GRANT EXECUTE ON FUNCTION filebelt_mount.fence_nfs_mapping_sessions(
  uuid,uuid,uuid,bigint,text
) TO filebelt_api;
GRANT EXECUTE ON FUNCTION filebelt_mount.create_nfs_mapping_proposal(
  uuid,uuid,uuid,uuid,uuid,text,text,uuid,bigint,bigint,uuid[],uuid,bigint,bytea
), filebelt_mount.approve_nfs_mapping_proposal(
  uuid,uuid,uuid,uuid,bigint
), filebelt_mount.transition_nfs_mapping_proposal(
  uuid,uuid,uuid,uuid,bigint,text
) TO filebelt_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  filebelt_mount.nfs_reclaim_records TO filebelt_vfs;
GRANT SELECT ON filebelt_mount.nfs_write_extents TO filebelt_vfs;
GRANT SELECT, INSERT ON filebelt_mount.nfs_replay_receipts TO filebelt_vfs;
GRANT SELECT, INSERT ON filebelt_mount.nfs_write_operations TO filebelt_vfs;
GRANT SELECT ON filebelt_mount.nfs_io_receipts TO filebelt_vfs;
GRANT SELECT ON filebelt_mount.nfs_write_conflicts TO filebelt_api;
GRANT SELECT (tenant_id,id,reserved_bytes) ON filebelt_mount.write_sessions TO filebelt_api;
GRANT SELECT ON filebelt_mount.nfs_write_conflicts,
  filebelt_mount.nfs_feature_state, filebelt_mount.nfs_exports TO filebelt_io;
GRANT SELECT (
  tenant_id,credential_id,principal_id,posix_group_id,generation,revoked_at
) ON filebelt_mount.nfs_principal_mappings TO filebelt_io;
GRANT SELECT ON
  filebelt_mount.nfs_principal_mappings,
  filebelt_mount.nfs_approved_active_mappings,
  filebelt_mount.nfs_feature_state,
  filebelt_mount.nfs_exports,
  filebelt_mount.nfs_posix_groups,
  filebelt_mount.nfs_posix_users,
  filebelt_mount.nfs_replay_slots,
  filebelt_mount.nfs_managed_traversal,
  filebelt_mount.nfs_managed_group_memberships TO filebelt_vfs;
GRANT EXECUTE ON FUNCTION filebelt_mount.reconcile_nfs_export_manifest(
  uuid,text,bigint,bigint,bigint,bytea,bigint[],bigint[],bytea[]
) TO filebelt_vfs;
GRANT SELECT ON filebelt_mount.nfs_write_extents TO filebelt_io;
GRANT SELECT, UPDATE, DELETE ON
  filebelt_mount.nfs_reclaim_records TO filebelt_maintenance;
GRANT SELECT ON
  filebelt_mount.nfs_write_conflicts,
  filebelt_mount.nfs_write_extents,
  filebelt_mount.nfs_replay_receipts,
  filebelt_mount.nfs_replay_slots,
  filebelt_mount.nfs_write_operations,
  filebelt_mount.nfs_io_receipts TO filebelt_maintenance;
GRANT EXECUTE ON FUNCTION filebelt_mount.expire_nfs_mapping_proposals(uuid,integer),
  filebelt_mount.purge_nfs_mapping_proposals(uuid,integer)
  TO filebelt_maintenance;
GRANT SELECT ON
  filebelt_mount.nfs_principal_mappings,
  filebelt_mount.nfs_mapping_proposals,
  filebelt_mount.nfs_approved_active_mappings,
  filebelt_mount.nfs_feature_state,
  filebelt_mount.nfs_exports,
  filebelt_mount.nfs_posix_groups,
  filebelt_mount.nfs_posix_users,
  filebelt_mount.nfs_reclaim_records,
  filebelt_mount.nfs_replay_slots,
  filebelt_mount.nfs_replay_receipts,
  filebelt_mount.nfs_pending_protocol_operations,
  filebelt_mount.nfs_io_admissions,
  filebelt_mount.nfs_write_extents,
  filebelt_mount.nfs_io_receipts,
  filebelt_mount.nfs_staging_cleanup_jobs,
  filebelt_mount.nfs_write_lock_cleanup_jobs,
  filebelt_mount.nfs_write_operations,
  filebelt_mount.nfs_write_conflicts,
  filebelt_mount.nfs_managed_traversal,
  filebelt_mount.nfs_managed_group_memberships TO filebelt_recovery;
GRANT EXECUTE ON FUNCTION filebelt_mount.mutate_nfs_namespace(
  uuid,uuid,text,text,integer,bigint,integer,text,bytea,bigint,bytea,jsonb,bytea,bytea
) TO filebelt_vfs;
GRANT EXECUTE ON FUNCTION filebelt_mount.commit_nfs_write(
  uuid,uuid,text,text,integer,bigint,integer,text,bytea,bigint,bytea,jsonb,
  bytea,bytea,bytea,bytea
) TO filebelt_vfs;
GRANT EXECUTE ON FUNCTION filebelt_mount.start_nfs_write_replayed(
  uuid,uuid,bigint,bytea,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,
  uuid,uuid,uuid,uuid,uuid,bigint,text,text,integer,bigint,integer,bytea,bytea,bytea
) TO filebelt_vfs;
GRANT EXECUTE ON FUNCTION filebelt_mount.prepare_nfs_replay_sequence(
  uuid,uuid,text,text,integer,bigint,integer,bigint
) TO filebelt_vfs;
GRANT EXECUTE ON FUNCTION filebelt_mount.lock_nfs_replay_receipt(
  uuid,uuid,text,text,integer,bigint,integer,text,bytea,bigint
) TO filebelt_vfs;
GRANT EXECUTE ON FUNCTION filebelt_mount.authorize_nfs_mutation(
  uuid,uuid,bigint,bytea,uuid,uuid,bigint,bigint,bigint,bigint,bigint
) TO filebelt_vfs;
GRANT EXECUTE ON FUNCTION filebelt_mount.authorize_nfs_handle_open(
  uuid,uuid,bigint,bytea,uuid,uuid,bigint,bigint,bigint,bigint,bigint,text[]
) TO filebelt_vfs;
GRANT EXECUTE ON FUNCTION filebelt_mount.preauthorize_nfs_io(
  uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,
  bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,
  text,text,integer,bigint,integer,text,bytea,
  uuid,uuid,bytea,uuid,text,bytea,bytea,bigint,bigint,bigint
) TO filebelt_vfs;
GRANT EXECUTE ON FUNCTION filebelt_mount.lookup_nfs_io_preauthorization(
  uuid,uuid,text,text,integer,bigint,integer,text,bytea,bigint,uuid,uuid,uuid,
  bytea,bytea,text,uuid,bytea,bigint,bigint,bigint,bigint
) TO filebelt_vfs;
GRANT EXECUTE ON FUNCTION filebelt_mount.inspect_nfs_pending_io(
  uuid,uuid,text,text,integer,bigint,integer,text,bytea,bigint
) TO filebelt_vfs;
GRANT EXECUTE ON FUNCTION filebelt_mount.reissue_nfs_io(
  uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,
  bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,
  text,text,integer,bigint,integer,text,bytea,uuid,uuid,text,bytea,
  bigint,bigint,uuid,bytea,bytea,bigint
) TO filebelt_vfs;
GRANT EXECUTE ON FUNCTION filebelt_mount.read_nfs_io_receipt(
  uuid,bytea,uuid,uuid,text,bytea,bytea
) TO filebelt_io;
GRANT EXECUTE ON FUNCTION filebelt_mount.read_nfs_write_operation(
  uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,
  bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,
  uuid,text,bigint,bigint
) TO filebelt_io;
GRANT EXECUTE ON FUNCTION filebelt_mount.begin_nfs_io_receipt(
  uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,
  bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,
  uuid,bytea,text,bytea,bytea,bigint,bigint
) TO filebelt_io;
GRANT EXECUTE ON FUNCTION filebelt_mount.complete_nfs_io_receipt(
  uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,
  bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,
  uuid,bytea,text,bytea,bytea,jsonb
) TO filebelt_io;
GRANT EXECUTE ON FUNCTION filebelt_mount.fence_pending_nfs_io_cleanup(
  uuid,uuid,bigint,bytea,bytea,text,bytea
) TO filebelt_io;
GRANT EXECUTE ON FUNCTION filebelt_mount.reserve_nfs_write_bytes(uuid,uuid,bigint,bigint)
  TO filebelt_vfs;
GRANT EXECUTE ON FUNCTION filebelt_mount.replace_nfs_write_extents(
  uuid,uuid,bigint,uuid,bigint[],bigint[],boolean[],bytea[]
) TO filebelt_vfs;
GRANT EXECUTE ON FUNCTION filebelt_mount.apply_completed_nfs_write_operation(
  uuid,uuid,bigint,uuid,text,bytea
) TO filebelt_vfs;
GRANT EXECUTE ON FUNCTION filebelt_mount.finalize_nfs_internal_io_replay(
  uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,
  bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,
  bytea,text,text,integer,bigint,integer,text,bytea,text,bytea,bytea
) TO filebelt_vfs;
GRANT EXECUTE ON FUNCTION filebelt_mount.require_completed_nfs_internal_terminal(
  uuid,uuid,text,text,integer,bigint,integer,text,bytea,bigint,uuid
) TO filebelt_vfs;
GRANT EXECUTE ON FUNCTION filebelt_mount.enqueue_nfs_staging_cleanup(
  uuid,uuid,text,bytea,text
) TO filebelt_vfs,filebelt_io,filebelt_api,filebelt_maintenance,filebelt_recovery;
GRANT EXECUTE ON FUNCTION filebelt_mount.claim_nfs_staging_cleanup(
  uuid,uuid,uuid,uuid
) TO filebelt_io,filebelt_maintenance;
GRANT EXECUTE ON FUNCTION filebelt_mount.mark_nfs_staging_cleanup_physical_deleted(
  uuid,uuid,uuid,uuid,bigint
) TO filebelt_io,filebelt_maintenance;
GRANT EXECUTE ON FUNCTION filebelt_mount.complete_nfs_staging_cleanup(
  uuid,uuid,uuid,uuid,bigint
) TO filebelt_io,filebelt_maintenance;
GRANT EXECUTE ON FUNCTION filebelt_mount.claim_next_nfs_staging_cleanup(
  uuid,uuid,uuid
) TO filebelt_io,filebelt_maintenance;
GRANT EXECUTE ON FUNCTION filebelt_mount.heartbeat_nfs_staging_cleanup(
  uuid,uuid,uuid,uuid,bigint
) TO filebelt_io,filebelt_maintenance;
GRANT EXECUTE ON FUNCTION filebelt_mount.sweep_expired_nfs_writers(
  uuid,integer
) TO filebelt_maintenance;
GRANT EXECUTE ON FUNCTION filebelt_mount.complete_nfs_write_conflict_copy(
  uuid,uuid,uuid,uuid,uuid,text,text,uuid,uuid
) TO filebelt_api;
GRANT EXECUTE ON FUNCTION filebelt_mount.discard_nfs_write_conflict(
  uuid,uuid,uuid,uuid
) TO filebelt_api;
GRANT EXECUTE ON FUNCTION filebelt_mount.sweep_expired_nfs_write_conflicts(
  uuid,integer
) TO filebelt_maintenance;
GRANT EXECUTE ON FUNCTION filebelt_mount.enqueue_nfs_write_lock_cleanup(
  uuid,uuid
) TO filebelt_vfs,filebelt_io,filebelt_maintenance,filebelt_recovery;
GRANT EXECUTE ON FUNCTION filebelt_mount.claim_nfs_write_lock_cleanup(
  uuid,uuid,uuid,uuid
) TO filebelt_io,filebelt_maintenance;
GRANT EXECUTE ON FUNCTION filebelt_mount.claim_next_nfs_write_lock_cleanup(
  uuid,uuid,uuid
) TO filebelt_io,filebelt_maintenance;
GRANT EXECUTE ON FUNCTION filebelt_mount.heartbeat_nfs_write_lock_cleanup(
  uuid,uuid,uuid,uuid,bigint
) TO filebelt_io,filebelt_maintenance;
GRANT EXECUTE ON FUNCTION filebelt_mount.complete_nfs_write_lock_cleanup(
  uuid,uuid,uuid,uuid,bigint
) TO filebelt_io,filebelt_maintenance;
GRANT EXECUTE ON FUNCTION filebelt_mount.advance_nfs_restore_generation(uuid,bigint)
  TO filebelt_recovery;

-- Media bytes remain behind scoped I/O. These grants expose only durable job,
-- receipt, manifest, and rebuildable-cache metadata.
GRANT SELECT, INSERT, UPDATE ON
  filebelt_media.previews, filebelt_media.playback_sessions,
  filebelt_media.deletion_intents TO filebelt_api;
GRANT SELECT ON
  filebelt_media.segment_receipts, filebelt_media.manifest_revisions,
  filebelt_media.cache_artifacts TO filebelt_api;
GRANT SELECT, INSERT, UPDATE ON
  filebelt_media.segment_receipts, filebelt_media.manifest_revisions,
  filebelt_media.cache_artifacts TO filebelt_io;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  filebelt_media.previews, filebelt_media.attempts,
  filebelt_media.reservations, filebelt_media.segment_receipts,
  filebelt_media.manifest_revisions, filebelt_media.cache_artifacts,
  filebelt_media.playback_sessions, filebelt_media.deletion_intents,
  filebelt_media.diagnostics TO filebelt_media;
GRANT SELECT, UPDATE, DELETE ON
  filebelt_media.previews, filebelt_media.attempts,
  filebelt_media.reservations, filebelt_media.segment_receipts,
  filebelt_media.manifest_revisions, filebelt_media.cache_artifacts,
  filebelt_media.playback_sessions, filebelt_media.deletion_intents,
  filebelt_media.diagnostics TO filebelt_maintenance;
GRANT SELECT ON
  filebelt_media.previews, filebelt_media.attempts,
  filebelt_media.reservations, filebelt_media.segment_receipts,
  filebelt_media.manifest_revisions, filebelt_media.cache_artifacts,
  filebelt_media.playback_sessions, filebelt_media.deletion_intents,
  filebelt_media.diagnostics TO filebelt_recovery;

GRANT SELECT (id,slug) ON tenants TO filebelt_media;
GRANT SELECT (tenant_id,id,kind,generation,disabled_at) ON principals TO filebelt_media;
GRANT SELECT (tenant_id,id,principal_id,status) ON users TO filebelt_media;
GRANT SELECT (tenant_id,id,user_id,principal_id,idle_expires_at,absolute_expires_at,revoked_at)
  ON api_sessions TO filebelt_media;
GRANT SELECT ON groups, group_memberships, drives, nodes, node_ancestry,
  acl_entries, file_versions, authorization_generations TO filebelt_media;
GRANT UPDATE (reserved_bytes,used_physical_bytes) ON drives TO filebelt_media;
GRANT INSERT ON audit_events, outbox_events, jobs TO filebelt_media;

GRANT SELECT ON filebelt_phase8.activation_state
  TO filebelt_api, filebelt_io, filebelt_maintenance, filebelt_collaboration,
     filebelt_vfs, filebelt_document, filebelt_media;
GRANT SELECT ON filebelt_phase8.managed_traversal,
  filebelt_phase8.managed_group_memberships TO filebelt_vfs;
GRANT SELECT ON filebelt_phase8.activation_state,
  filebelt_phase8.activation_events, filebelt_phase8.role_compatibility,
  filebelt_phase8.managed_traversal,
  filebelt_phase8.managed_group_memberships TO filebelt_recovery;

REVOKE ALL ON FUNCTION filebelt_mcp.require_principal_kind() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mcp.require_service_principal() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mcp.invalidate_registration_policy() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mcp.invalidate_service_policy() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mcp.invalidate_template_policy() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.invalidate_acl_capability_projection() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.invalidate_inserted_acl_capability_projection() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.invalidate_deleted_acl_capability_projection() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.invalidate_updated_acl_capability_projection() FROM PUBLIC;
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
REVOKE ALL ON FUNCTION filebelt_mount.erase_revoked_credential_secret() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.advance_authorization_generation() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.reserve_credential_operation() FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.cancel_credential_operation(uuid,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.prepare_credential_creation_operation(uuid,uuid)
  FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.cancel_credential_creation_operation(uuid,uuid,uuid,bigint)
  FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.create_session_principal(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION filebelt_mount.create_nfs_session(
  uuid,text,bytea,text,bigint,inet,timestamptz,uuid,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION filebelt_mount.create_session_principal(uuid,uuid),
  filebelt_mount.create_nfs_session(
    uuid,text,bytea,text,bigint,inet,timestamptz,uuid,uuid
  )
  TO filebelt_vfs;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA filebelt_security
  FROM PUBLIC, filebelt_api, filebelt_io, filebelt_maintenance,
       filebelt_audit_exporter, filebelt_recovery, filebelt_mcp_broker,
       filebelt_collaboration, filebelt_vfs, filebelt_headscale_sync,
       filebelt_document, filebelt_media;
GRANT EXECUTE ON FUNCTION filebelt_security.descendant_share_admission_open(uuid)
  TO filebelt_api;
GRANT EXECUTE ON FUNCTION filebelt_security.descendant_shares_status(uuid,uuid),
  filebelt_security.repair_descendant_shares(uuid,uuid,text,uuid,integer),
  filebelt_security.verify_descendant_shares(uuid,uuid,text,uuid),
  filebelt_security.activate_descendant_shares(uuid,uuid,text,uuid)
  TO filebelt_recovery;
