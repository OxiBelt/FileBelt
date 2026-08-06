<!-- SPDX-License-Identifier: Apache-2.0 -->

# PostgreSQL migrations

SQLx migrations are immutable forward-only `NNNNNN_description.sql` files as
defined by ADR-0005. Apply `roles.sql` as a role administrator, provision
deployment-specific login roles as members of exactly one group role, and run
`filebeltctl database migrate` with the migrator credential. Apply
`grants.sql` as the database owner after every migration; it deliberately uses
an explicit allowlist instead of default table privileges.

`000001_phase2_core.sql` is the Phase 2 baseline. PostgreSQL metadata and policy
state are authoritative; migrations never infer state from the payload volume.
