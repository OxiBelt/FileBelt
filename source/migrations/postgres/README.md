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

`roles.sql` temporarily grants the migrator database `CREATE` for immutable
idempotent schema statements and assigns ownership of `filebelt_revision` to
the migrator. `grants.sql` revokes database `CREATE` immediately after the
migrations, and verification treats a retained grant as a failure. Neither
script grants database ownership, `CREATEDB`, or role-administration rights.

`000017_nfs_worker_trigger_dispatch.sql` repairs the immutable migration 14
worker-authority trigger by dispatching on the trigger relation before reading
relation-specific `OLD` fields. It preserves fail-closed NFS staging denial
while allowing ordinary upload and collaboration payload transitions.

`000018_collaboration_backend_reservation.sql` preserves the backend row lock
used by collaboration object allocation without granting the collaboration
runtime role table write privileges. Its fixed-search-path security-definer
functions return only the selected backend UUID or the four authorization
generations plus the session expiry required for grant publication.
`grants.sql` permits the API and collaboration roles to execute the fence and
only `filebelt_collaboration` to reserve a backend. The I/O role receives
execute-only access to the one-shot object finalizer: the definer locks and
consumes the matching staging object and active reservation before it converts
reserved drive bytes to used bytes. I/O can read, but cannot directly update,
those authoritative accounting rows.

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

`000020_acl_children_scope.sql` admits the stable `children` ACL scope and
updates the live NFS traversal projection so it reaches exactly immediate
children. It preserves existing ACL rows and source tags. Older binaries that
cannot parse `children` must remain stopped after the migration; rollback is a
route quiesce followed by roll-forward, never a constraint or checksum edit.

`000021_collaboration_checkpoint_limit.sql` aligns durable checkpoint admission
with the existing configurable 16 MiB Markdown edit ceiling. It changes no
stored bytes; older binaries remain compatible with rows below their own
runtime limit, while rollback is a route quiesce and roll-forward because a
smaller constraint cannot be restored after larger checkpoints are admitted.

`000022_document_close_idempotency.sql` admits transaction-bound coordinator
receipts for own-session revoke and manager force-close. Keep document close
routes quiesced until the migration and release-matched API and coordinator are
active; response-loss retries then replay the committed close result before the
API finalizes its public receipt. Rollback retains the expanded constraint and
keeps the close routes quiesced until roll-forward. The migration does not add
replay semantics to one-use launch handoffs.

`000023_mount_credential_cancellation_fence.sql` serializes caller-chosen mount
credential UUID creation and recovery revocation. Missing revocation commits a
durable cancellation row before returning not found, and the credential insert
trigger rejects any later create for that UUID. Keep credential routes quiesced
until the release-matched API and grants are active; rollback retains the
additive fence and requires those routes to remain disabled on older APIs.

`000025_mount_credential_creation_slots.sql` replaces new runtime fence writes
with one reusable, two-minute creation slot per tenant/principal. PostgreSQL
issues the UUID and monotonic generation; SMB/FTPS inserts require the exact
unexpired tuple, while NFS remains on its separately approved path. Apply only
after quiescing and draining the old credential routes. The migration fails on
an unexpected non-cancelled orphan, removes cancelled no-credential legacy
fences, records the count in a singleton cutover receipt, and preserves every
fence linked to a credential. Apply release-matched grants and deploy API, VFS,
and Web together. Rollback keeps credential creation/recovery disabled and
rolls forward; old SMB/FTPS writers fail closed.

`000024_mcp_broker_operation_receipts.sql` adds the digest-only, 24-hour broker
journal for signed management/probe operation UUIDs. Keep the seven affected
MCP routes quiesced until the migration, grants, API, and broker are all
release-matched. Rollback retains the additive journal and requires those
routes to stay quiesced on older binaries; rows contain no credential, OAuth
state/verifier, authorization URL, or token material.
Maintenance removes at most 1,000 expired rows per tenant sweep and only when a
safe broker result and the transaction-bound API completion marker are both
present. A broker-complete/API-incomplete delete or probe saga is deliberately
retained for exact resumption; do not manually purge it during rollback.

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
