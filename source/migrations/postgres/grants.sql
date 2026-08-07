-- SPDX-License-Identifier: Apache-2.0
-- Run as the database owner after every migration. There are deliberately no
-- default table privileges: newly added tables remain inaccessible until this
-- reviewed allowlist is updated.

GRANT USAGE ON SCHEMA public TO filebelt_api, filebelt_io, filebelt_maintenance,
  filebelt_audit_exporter, filebelt_recovery;

-- These operator roles are read-only, column-scoped capabilities. Reset their
-- direct table grants so applying this reviewed allowlist also removes stale
-- privilege left by an earlier release.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM filebelt_audit_exporter, filebelt_recovery;
REVOKE CREATE ON SCHEMA public FROM filebelt_audit_exporter, filebelt_recovery;

GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO filebelt_api;
-- Authority-changing triggers remove stale capability projections in the same
-- transaction as API mutations. Share revocation removes its owned ACL entry.
-- Keep these narrower than broad DELETE access.
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

REVOKE UPDATE, DELETE ON audit_events FROM filebelt_api, filebelt_io, filebelt_maintenance;
REVOKE ALL ON tenant_admin_bindings, acl_entries, group_memberships, drives,
  nodes, node_ancestry, file_versions, share_links, direct_shares FROM filebelt_io;
REVOKE ALL ON tenant_admin_bindings, acl_entries, group_memberships, nodes,
  node_ancestry, file_versions, share_links, direct_shares FROM filebelt_maintenance;

-- Restore the narrow maintenance grant after broad table-level revocation.
GRANT SELECT (tenant_id, id, reserved_bytes), UPDATE (reserved_bytes)
  ON drives TO filebelt_maintenance;
