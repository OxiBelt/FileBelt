<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0005: PostgreSQL migrations and compatibility

- Status: Accepted
- Date: 2026-08-06
- Owners: `@PiQuark6046`
- Reviewers: none
- Supersedes: none
- Affected license regions: Apache-2.0

## Context

PostgreSQL will be authoritative for FileBelt metadata. Migrations must remain
auditable, ordered, compatible with rolling Kubernetes upgrades, and safe after
release.

## Decision

Use SQLx and forward-only SQL files named `NNNNNN_description.sql` under
`source/migrations/postgres/`. SQLx's migration ledger records versions and
checksums. A released file is immutable; a correction is a new migration.

Production migrations run through a dedicated `filebeltctl database migrate`
command and later migration image. API replicas check compatibility but do not
race to apply production migrations.

Schema evolution uses expand/migrate/contract:

1. add backward-compatible structures;
2. deploy dual-compatible code;
3. run an idempotent checkpointed backfill;
4. switch writes and verify invariants;
5. remove the old representation in a later coordinated release.

Released persisted data is always migrated forward, including before 1.0.
Public API and configuration breaks may occur before 1.0 when documented, with
a one-minor compatibility window where practical. Down migrations are not used;
rollback relies on the compatibility window until contract, and on restore plus
forward repair after an irreversible contract migration.

## Alternatives considered

Automatic per-replica migration was rejected because it complicates locking and
rollout. Destructive pre-1.0 resets were rejected because self-hosted user data
must not become disposable.

## Consequences and verification

Migration CI will cover empty-to-head, supported-release-to-head, checksum
drift, lock contention, interrupted backfill, and binary/schema compatibility.
Phase 0 creates only the directory contract and no SQL migration.

## Rollback

There is no Phase 0 database state. Future releases document the latest binary
that remains compatible with each schema version.

## Open questions

None.
