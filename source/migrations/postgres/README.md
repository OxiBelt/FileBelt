<!-- SPDX-License-Identifier: Apache-2.0 -->

# PostgreSQL migrations

SQLx migrations are immutable forward-only `NNNNNN_description.sql` files as
defined by the
[storage and durability specification](../../../docs/StorageAndDurability.md).
Apply `roles.sql` as a role administrator, provision
deployment-specific login roles as members of exactly one group role, and run
`filebeltctl database migrate` with the migrator credential. Apply
`grants.sql` as the database owner after every migration; it deliberately uses
an explicit allowlist instead of default table privileges. Finish by running
`filebeltctl database verify-grants` with the migrator credential. Verification
checks the compiled migration checksums, required privileges, prohibited excess
privileges, and the non-login properties of every group role.

Use the read-only, column-scoped `filebelt_audit_exporter` group for
`filebeltctl audit export` and `filebelt_recovery` for `filebeltctl recovery`.
Scrub orchestration writes durable maintenance jobs and therefore uses a login
that is a member only of `filebelt_maintenance`.

`000001_phase2_core.sql` is the Phase 2 baseline; later migrations add MCP,
Markdown collaboration, and mount-protocol state without rewriting released
files. The Phase 6 mount vault envelope is completed by
`000005_phase6_mount_vault.sql` before any mount runtime is enabled. PostgreSQL
metadata and policy state are authoritative; migrations never infer state from
the payload volume or an event stream.

`000010_onlyoffice_origin_isolation.sql` is a forward-only security cutover.
Apply it only while document admission and every old launch-capable binary are
stopped. It preserves revisions and reconciliation state while revoking
affected live browser sessions and fencing live document state; follow
[`docs/operations/onlyoffice.md`](../../../docs/operations/onlyoffice.md) for
rollout, verification, and rollback requirements.

`000011_security_descendant_shares.sql` starts every tenant with descendant
share admission blocked. It records a resumable, audited repair run that
revokes every active legacy `self_and_descendants` direct share (and deletes
its ACL rows) plus every active pre-drive-fence MCP data grant. Recovery
operators call, in order, `descendant_shares_status`, bounded
`repair_descendant_shares` batches (maximum total limit 1000) until `remaining`
is zero, `verify_descendant_shares`, then `activate_descendant_shares`. Each
mutating call requires the exact tenant-slug confirmation and supplied live
tenant administrator, the same operation UUID and compiled source revision,
and serializes per tenant with an advisory lock; status is a checkpoint read
and accepts an operation UUID without an administrator.
Only activation opens POST admission. The API may read only
`descendant_share_admission_open`; it must treat SQLSTATE `FB001` with message
`filebelt descendant-share admission is blocked` as the authoritative
close-race result. The migration keeps historical MCP rows with a NULL drive
ACL generation only after revocation; newly inserted grants require a positive
drive fence.
