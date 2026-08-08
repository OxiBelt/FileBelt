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
files. PostgreSQL metadata and policy state are authoritative; migrations never
infer state from the payload volume or an event stream.
