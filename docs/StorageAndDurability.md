<!-- SPDX-License-Identifier: Apache-2.0 -->

# Storage and Durability

This specification defines FileBelt's current persistence, payload, job, and
recovery contracts. PostgreSQL is authoritative for metadata and policy, the
POSIX payload root stores UUID-addressed bytes, and Apache Iggy is an optional
notification path. No event stream or filesystem scan can reconstruct or
replace committed PostgreSQL state.

Identity, namespace, and policy semantics are defined in
[Namespace and Authorization](NamespaceAndAuthorization.md). Public and worker
contracts are defined in
[Interfaces and Capabilities](InterfacesAndCapabilities.md). Production
topology is defined in [Runtime and Deployment](RuntimeAndDeployment.md).

## PostgreSQL authority and schema

FileBelt supports PostgreSQL 18. The schema persists tenants, principals and
external identities, groups and memberships, drives, namespace nodes and
closure ancestry, trash snapshots, ACLs and generations, sessions and OIDC
attempts, immutable versions and payload manifests, uploads and parts, quota
reservations, jobs and leases, outbox and publication deduplication, audit,
notification state, preferences, and idempotency records.

Logical identifiers and physical storage locators are independently generated
UUIDv4 values. Public UUID strings use canonical lowercase form. Composite
keys and foreign keys carry tenant and drive boundaries. A transactional
closure table represents the strict namespace tree; live sibling comparison
keys are unique, and moves use deterministic lock ordering and cycle checks.

Pre-created group roles separate migration, API, I/O worker, maintenance,
audit export, and recovery privileges. Deployment-specific logins inherit
exactly one group role. Grants provide defense in depth but do not replace the
Virtual ACL evaluator:

- the API resolves identity and makes policy decisions but has no payload
  mount;
- the I/O worker sees only operation, payload, replay, and generation
  projections; and
- the maintenance worker leases and reconciles only its owned durable state.

Services refuse an incompatible schema or missing configured tenant.
`filebeltctl tenant bootstrap` idempotently creates the configured tenant and
exact administrator identities before API startup.

## Migration and compatibility contract

SQLx migrations are forward-only files named `NNNNNN_description.sql` under
[`source/migrations/postgres/`](../source/migrations/postgres/). SQLx records
their versions and checksums. Once released, a migration is immutable; every
correction is a new migration.

Production migration is an explicit `filebeltctl database migrate` operation
using the migrator credential. API replicas check compatibility and never race
to apply migrations. After each migration, the database owner applies the
release-matched `grants.sql`, and the migrator runs
`filebeltctl database verify-grants`. The chart never receives a database-owner
credential.

Schema evolution uses expand, migrate, and contract:

1. add structures that are compatible with the running binary;
2. deploy code that can use both representations;
3. run an idempotent, checkpointed backfill;
4. switch writes and verify invariants; and
5. remove the old representation only in a later coordinated release.

Persisted data is migrated forward even before 1.0. Public configuration or
API compatibility may change before 1.0 when documented, with a one-minor
compatibility window where practical. Rollback uses the previous compatible
binary while the schema remains expanded. After an irreversible contract
migration, the only supported recovery is restore into fresh targets followed
by forward repair; down migrations, migration deletion, checksum edits, and
persisted-state resets are prohibited.

## Versions, trash, and quota

Every committed content change, including zero-byte content, creates an
immutable linear version. The file head advances only when the expected head
matches. Metadata-only changes create no content version. Restoring history
creates a new head that references retained immutable content; it does not
mutate an old version or create sibling conflict versions.

Versions remain until permanent node purge. Moving a node to trash snapshots
its retention deadline and original location. Purge first records a fenced
deletion intent. Physical garbage collection removes an unreferenced payload
before PostgreSQL reaches `DELETED`.

Quota charges retained physical payload bytes once per drive plus active
declared-byte reservations. An upload reserves its declared bytes in the same
transaction that precedes upload authority. Abort or expiry releases the
reservation. A committed payload remains charged until its final reference is
purged and physical deletion succeeds. The defaults are 1 TiB for a private
drive and 10 TiB for a shared drive; tenant-admin overrides remain bounded by
operator configuration.

## Payload layout and write durability

One configured storage root and one persisted backend ID are supported. The
volume supplies encryption at rest. FileBelt currently has no application
encryption, deduplication, multi-root placement, online payload migration, or
content-addressed physical identity.

Tenant IDs, drive IDs, logical names, and user-controlled path components never
appear in physical paths. UUID locator bytes select fixed shard directories
under whole, chunk, staging, and quarantine roots. Workers reject symlinks,
special files, unexpected owner or mode, short reads, size mismatch, and
checksum mismatch.

Payloads at or below 32 MiB use one whole object. Larger payloads use
server-selected fixed 16 MiB chunks except for the final part. The server
computes BLAKE3 from stored bytes for each part and for the concatenated
payload. A client digest is only an early-error hint and never proves stored
content.

A part is acknowledged only after the worker has written exactly the declared
bytes, fsynced the file and required parent-directory state, and durably
recorded the operation result. Finalization:

1. validates a complete manifest;
2. atomically claims an owner- and fence-bound `FINALIZING` lease;
3. hashes in a detached task that heartbeats a 120-second lease every 30
   seconds;
4. renames within the same storage filesystem and fsyncs both affected
   directories; and
5. records the payload as `FINALIZED` before a later API transaction may
   reference it from a version.

Concurrent grants cannot enter filesystem finalization. A failed attempt
reopens with a new fence, and maintenance reopens an expired lease after a
worker crash. An expired or aborted upload becomes `ABANDONED`; it retains
recovery evidence without inventing a whole-object digest, and maintenance
removes staged parts only after the configured grace period.

Startup probes exclusive creation, no-follow behavior, ownership and mode,
file fsync, directory fsync, and same-filesystem atomic rename. Unsupported
semantics fail readiness. Corruption moves to `QUARANTINED`, blocks reads,
preserves evidence, and identifies affected versions. It is never reported as
successful deletion.

Before serving a Range, the worker verifies the manifest and hashes every
whole object or chunk overlapping the requested bytes. It does not hash
unrelated chunks. Scheduled scrubs provide complete payload coverage.

New reservations stop when usable free capacity, after reservations, is below
either 5 percent or 10 GiB. Capacity observations must be fresh. Maintenance
reconciles on startup and every 60 seconds, preserves finalized unreferenced
objects for 24 hours, and preserves expired parts until 24 hours after upload
expiry.

## Configuration safety envelope

Configuration validation rejects arithmetic overflow and inconsistent
combinations, including a chunk-size and part-count combination that cannot
represent the maximum file size.

| Setting | Default | Accepted envelope |
| --- | ---: | ---: |
| Whole threshold | 32 MiB | 0--1 GiB |
| Chunk size | 16 MiB | power of two, 1--256 MiB |
| Part count | 65,536 | 1--1,048,576 |
| Maximum file | 1 TiB | 1 MiB--64 TiB; zero-byte content remains valid |
| Upload lifetime | 7 days | 5 minutes--30 days |
| Authorization generation recheck | 60 seconds | 1--60 seconds |
| Finalized-orphan grace | 24 hours | 1 hour--30 days |
| Expired-part grace | 24 hours | 0--7 days |
| Drive quota | private 1 TiB; shared 10 TiB | 1 GiB--1 PiB |

## Durable jobs, outbox, and Iggy

Initial durable jobs expire and reconcile uploads and delete or scrub
payloads. Workers lease jobs using PostgreSQL time for 30 seconds, heartbeat
every 10 seconds, carry a monotonically changing fence, and make idempotent
state transitions. One attempt may renew for no more than six hours. Retryable
failures use exponential full-jitter backoff for at most eight attempts,
capped at five minutes. Terminal and operator-blocked state remains in
PostgreSQL and requires explicit inspection before an operator retry.

Every authoritative transaction that needs an event writes a transactional
outbox row. The publisher uses one `filebelt` Iggy stream with 16 partitions,
keyed by tenant and aggregate, for versioned ACL, membership, namespace,
payload, job, and notification topics. Iggy retention is seven days;
publication and consumer-deduplication evidence remains in PostgreSQL for 30
days and is then removed in bounded batches.

Iggy is optional acceleration. During an outage, commits continue, the outbox
accumulates, and workers poll PostgreSQL every five seconds. Any consumer must
treat events as hints, deduplicate them, and read authoritative state from
PostgreSQL. After event retention expires it rebuilds from PostgreSQL. A dead
letter stream never becomes the durable record of terminal state.

## Backup, restore, and rollback

The supported recovery boundary is a coordinated, quiesced PostgreSQL and
payload snapshot. Operators drain and fence every writer, record a bounded
versioned checkpoint, snapshot both external planes, and restore into a fresh
database, namespace, and RWX volume. Migration, grants verification,
reconciliation, checkpoint comparison, a complete physical BLAKE3 scrub, and
two-user authorization acceptance must pass before traffic returns.

FileBelt does not currently promise online backup, PITR, high availability, or
numeric RPO/RTO. The detailed procedures are
[Kubernetes recovery](operations/kubernetes-recovery.md),
[Kubernetes rollback](operations/kubernetes-rollback.md), and the historical
[Phase 2 Docker operator guide](operations/phase2.md).

## Changing this contract

A change to persisted state, migration compatibility, payload layout,
durability acknowledgement, quota accounting, lease or fencing behavior,
Iggy topology, configuration envelopes, or recovery guarantees requires an
explicit architecture and policy review in the same pull request. The review
records rationale, alternatives, compatibility and migration effects, crash
and retry behavior, security and license impact, rollout, and rollback. Update
this specification, the threat model, operator documentation, and regression
coverage together with the implementation.
