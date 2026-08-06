<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0010: PostgreSQL, storage, and job durability

- Status: Accepted
- Date: 2026-08-06
- Owners: `@PiQuark6046`
- Reviewers: none
- Supersedes: none
- Affected license regions: Apache-2.0

## Context

Phase 2 persists the namespace, versions, policy, operation state, audit, and
job state while placing payload bytes on a UUID-addressed POSIX filesystem.
PostgreSQL and filesystem rename cannot share a transaction. Iggy delivery is
also independent of both. Every crash window therefore needs an explicit,
idempotent recovery rule rather than an assumed distributed transaction.

## Decision drivers

- Preserve PostgreSQL as the sole metadata and policy authority.
- Acknowledge payload durability only after filesystem guarantees are met.
- Recover deterministically from process death before or after every database,
  fsync, rename, and publication boundary.
- Operate correctly without Iggy and without content-addressed identity.

## Decision

### Schema and database roles

Phase 2 supports PostgreSQL 18 only and applies forward SQLx migrations through
`filebeltctl database migrate` under ADR-0005. Services refuse a missing tenant
or incompatible schema. `filebeltctl tenant bootstrap` idempotently creates the
configured UUID tenant and exact administrator identities before API startup.

The schema persists tenants, principals/users/external identities, groups and
memberships, drives, nodes and closure ancestry, trash snapshots, ACLs and
generations, sessions and OIDC attempts, versions and payload manifests,
uploads and parts, quota reservations, jobs and leases, outbox and publication
deduplication, audit, notification state, preferences, and idempotency records.

All logical IDs and physical storage locators are independently generated
UUIDv4 values. UUID strings on public wires are canonical lowercase. Tenant
and drive boundaries appear in composite keys and foreign keys. A
transactional closure table represents the strict tree; live sibling
comparison keys are unique and moves use deterministic lock ordering and
cycle checks.

Pre-created roles separate migration, API, I/O worker, and maintenance worker
privileges. Database grants are defense in depth, not the Virtual ACL engine:
the API performs policy decisions, the I/O worker may access only operation,
payload, replay, and generation projections, and the maintenance worker may
lease and reconcile only its owned state.

### Versions, trash, and quota

Every committed content change, including zero bytes, creates an immutable
linear version and advances the head only when the expected head matches.
Metadata-only changes create no content version. Restoring history creates a
new head referencing retained immutable content; sibling conflict versions are
not created.

All versions remain until permanent node purge. Trash retention and original
location are snapshotted at deletion. Purge records a fenced deletion intent,
then physical garbage collection removes an unreferenced payload before the
database reaches `DELETED`.

Quota counts retained physical payload bytes once per drive plus active
declared-byte reservations. Reservations are created transactionally before
upload authority is issued and released on abort or expiry. A payload remains
charged until its final reference is purged and physical deletion succeeds.
Defaults are 1 TiB for private drives and 10 TiB for shared drives, with
tenant-admin overrides bounded by operator configuration.

### Payload format and durability

One configured storage root and persisted backend ID are supported. User,
tenant, drive, and logical names never appear in physical paths. UUID locator
bytes select fixed shard directories below whole, chunk, staging, and
quarantine roots. The volume provides encryption at rest. Phase 2 has no
application encryption, deduplication, multi-root placement, or online payload
migration.

Whole payloads are used at or below 32 MiB. Larger payloads use server-selected
fixed 16 MiB chunks except for the last part. Defaults allow 65,536 parts, a
1 TiB file, and a seven-day upload. The server computes BLAKE3 for each part
and the concatenated whole file from stored bytes. A client digest is only an
optional early-error hint and never proves stored content.

The worker acknowledges a part only after writing exact declared bytes,
fsyncing the file and required parent directory state, and durably recording
the operation result. Finalization validates a complete manifest and whole
digest, but first atomically claims an owner- and fence-bound `FINALIZING`
lease. The detached finalization task heartbeats while hashing, atomically
renames within the same storage filesystem, fsyncs both affected directories,
and records the payload `FINALIZED`. Concurrent grants cannot enter the
filesystem work. A failed attempt reopens with a new fence; maintenance also
reopens an expired lease after a worker crash. Only a later API transaction may
reference the payload from a version.

An expired or aborted upload moves its never-finalized payload manifest to
`ABANDONED`. This preserves recovery evidence without inventing a whole-object
digest for bytes that were never finalized; maintenance removes its staged
parts only after the configured expired-part grace period.

Startup probes exclusive creation, no-follow behavior, file fsync, directory
fsync, and same-filesystem atomic rename. Unsupported semantics fail readiness.
Workers reject symlinks, special files, unexpected owner/mode, short reads,
size mismatch, and checksum mismatch. Corruption moves to explicit
`QUARANTINED` state, blocks reads, preserves evidence, and identifies affected
versions; it is never hidden as successful deletion.

Before serving a Range, the worker validates the manifest and hashes every
whole object or chunk that overlaps the requested bytes. It does not hash
unrelated chunks, so a tiny authorized Range cannot induce a full-payload scan.
Scheduled scrubs retain whole-payload integrity coverage.

New reservations stop when free capacity is below either 5 percent or 10 GiB.
The maintenance worker reconciles on startup and every 60 seconds, preserves a
finalized unreferenced object for 24 hours, and preserves expired parts until
24 hours after upload expiry.

Configuration accepts these safety envelopes and rejects arithmetic overflow
or inconsistent combinations:

| Setting | Default | Absolute envelope |
| --- | ---: | ---: |
| Whole threshold | 32 MiB | 0--1 GiB |
| Chunk size | 16 MiB | power of two, 1--256 MiB |
| Part count | 65,536 | 1--1,048,576 |
| Maximum file | 1 TiB | 1 MiB--64 TiB; zero-byte content allowed |
| Upload lifetime | 7 days | 5 minutes--30 days |
| Authorization recheck | 60 seconds | 1--60 seconds |
| Orphan grace | 24 hours | 1 hour--30 days |
| Expired-part grace | 24 hours | 0--7 days |
| Drive quota | private 1 TiB; shared 10 TiB | 1 GiB--1 PiB |

Changing an absolute envelope requires a new ADR.

### Jobs, outbox, and Iggy

Initial durable jobs expire/reconcile uploads and delete/scrub payloads. A
worker leases using PostgreSQL time for 30 seconds, heartbeats every 10
seconds, carries a monotonically changing fencing value, and makes idempotent
state transitions. A single attempt can renew its lease for no more than six
hours. Retryable failures receive exponential full-jitter backoff, at most
eight attempts, capped at five minutes. Terminal and operator-blocked states
remain in PostgreSQL and `filebeltctl` provides explicit inspection and retry.

Every authoritative transaction that needs an event writes a transactional
outbox row. A publisher sends versioned ACL, membership, namespace, payload,
job, and notification topics to one `filebelt` Iggy stream with 16 partitions
keyed by tenant plus aggregate. Iggy retains events for seven days;
publication/deduplication evidence remains in PostgreSQL for 30 days.
Missing Iggy streams/topics are provisioned idempotently with that topology;
published outbox and consumer-deduplication evidence is then removed in
bounded batches only after the 30-day retention boundary.

Iggy is optional acceleration. During an outage, commits continue, the outbox
accumulates, and workers poll PostgreSQL every five seconds. Consumers are
idempotent and rebuild from PostgreSQL after Iggy retention expires. A dead
letter stream is not authoritative; terminal state remains in PostgreSQL.

### Backup boundary

Phase 2 documents only a quiesced Docker backup and restore procedure. Operators stop new
writes, drain or fence in-flight operations, record the database/storage
watermark, snapshot PostgreSQL and the payload root, restore both into fresh
volumes, run migrations and reconciliation, and verify manifests and BLAKE3.
This establishes recoverability for development/integration but makes no
online backup, PITR, HA, RPO, or RTO promise.

## Alternatives considered

An event-sourced authority, automatic per-replica migration, two-phase commit
with the filesystem, client-trusted digests, content-addressed physical names,
deduplication, multiple storage roots, and treating Docker Compose as a
production topology were rejected or deferred. PostgreSQL polling remains
required because notification availability cannot become a correctness
dependency.

## Consequences

The schema carries explicit intermediate states and more reconciliation data,
but every crash result is explainable. Physical cleanup is deliberately later
than logical deletion. A supported filesystem must satisfy the startup probe;
network filesystems with weaker or undocumented behavior are unsupported.

## Security, data, and license analysis

Database credentials are role-specific secret files. Backups contain identity,
policy, audit, and user payload data and require confidentiality, integrity,
access control, and tested disposal. Database rows and operator diagnostics
must not expose raw session, share, capability, or CSRF tokens or physical host
paths.

SQLx repositories, storage protocols, workers, migration SQL, and operational
tools remain Apache-2.0. PostgreSQL and Iggy are replaceable external processes
and are not linked into FileBelt packages.

## Verification

- Empty-to-head and supported-to-head migration, checksum, lock-contention,
  role-grant, and tenant/composite-key tests.
- Concurrent sibling, move/cycle, expected-head, idempotency, quota, lease,
  fencing, outbox, and audit tests against PostgreSQL 18.
- Whole, chunked, zero-byte, resume, Range, checksum, low-space, quarantine,
  deletion, and scrub integration tests.
- Deterministic failpoints before and after file fsync, rename, finalization,
  version commit, response loss, deletion intent, and outbox publication.
- Real Iggy outage, duplicate, backlog replay, and retention-expiry rebuild
  tests plus a rehearsable quiesced backup/restore procedure.

## Rollout and rollback

Roll out additive migrations and database roles first, storage probes and
reconciliation second, then workers, API writes, and Iggy publication. Keep
the previous binary compatible throughout expand/migrate. For rollback,
quiesce writes, preserve storage and PostgreSQL snapshots, stop new leases,
deploy the previous compatible binary, and reconcile; never delete a migration
or reset persisted state. After a contract migration, restore and forward
repair are the only rollback path under ADR-0005.

## Open questions

None.
