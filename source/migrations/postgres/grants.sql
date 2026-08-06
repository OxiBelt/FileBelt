-- SPDX-License-Identifier: Apache-2.0
-- Run as the database owner after every migration. There are deliberately no
-- default table privileges: newly added tables remain inaccessible until this
-- reviewed allowlist is updated.

GRANT USAGE ON SCHEMA public TO filebelt_api, filebelt_io, filebelt_maintenance;

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

REVOKE UPDATE, DELETE ON audit_events FROM filebelt_api, filebelt_io, filebelt_maintenance;
REVOKE ALL ON tenant_admin_bindings, acl_entries, group_memberships, drives,
  nodes, node_ancestry, file_versions, share_links, direct_shares FROM filebelt_io;
REVOKE ALL ON tenant_admin_bindings, acl_entries, group_memberships, nodes,
  node_ancestry, file_versions, share_links, direct_shares FROM filebelt_maintenance;

-- Restore the narrow maintenance grant after broad table-level revocation.
GRANT SELECT (tenant_id, id, reserved_bytes), UPDATE (reserved_bytes)
  ON drives TO filebelt_maintenance;
