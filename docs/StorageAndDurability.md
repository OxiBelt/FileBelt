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
Migration `000002_phase4_mcp.sql` additionally creates tenant-scoped MCP
service principals and SPIFFE bindings, managed templates and assignments,
registrations, capability snapshots/reviews, exact approvals and data grants,
service invocation grants, OAuth attempts, invocation intents/activity,
rate buckets, PostgreSQL runner-slot reservations, runner leases, deletion
tombstones, and a separate encrypted vault schema.

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
  projections;
- the maintenance worker leases and reconciles only its owned durable state;
- the MCP broker revalidates narrow principal and policy projections and owns
  the MCP vault rows, but cannot read browser sessions, OIDC identity, ACL rows,
  user records, or payload locators; and
- the API's MCP surface may mutate non-secret MCP control-plane state but has
  no privileges on `filebelt_mcp_vault`; configuration replacement is a signed
  broker request executed through one fully qualified, broker-only
  `SECURITY DEFINER` function that erases old vault material atomically.

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

## MCP policy, vault, and retention

`filebelt_mcp` is authoritative for registrations and policy. Capability
snapshots are immutable JSON documents whose exact descriptor fingerprints are
reviewed separately. Approval rows bind principal, optional session,
registration, application, primitive, capability fingerprint, argument digest,
attachment digest, consumption state, and expiry. Invocation intents retain
only exact digests and expire within five minutes; OAuth attempts expire within
ten minutes; approvals expire within one hour. Data and service invocation
grants expire within 30 days. Revocation and deletion advance generations and
cancel or invalidate dependent active state in the same database transaction.
Credential replacement, credential erasure, and configuration replacement
also delete pending OAuth attempts, supersede capability snapshots, revoke
capability reviews and registration-bound data grants, and disable the
registration before returning. A data grant records the exact registration
generation at creation and cannot survive any later registration generation.

Each MCP data grant is non-recursive and binds an exact principal, destination
registration, drive, node, immutable file version, metadata/content disclosure,
ACL generation, namespace generation, creator, and expiry. A file head change
does not widen the grant. Before bytes or metadata cross the broker boundary,
the current version relationship, Virtual ACL, principal generation,
registration generation, grant state, and expiry are revalidated. The broker
does not infer authority from the filesystem or from an MCP server credential.

`filebelt_mcp_vault` holds no plaintext. A maximum-8,192-byte credential is
encrypted under a random AES-256-GCM data-encryption key, which is itself
AES-256-GCM wrapped by the selected key-encryption-key generation. Associated
data binds tenant, registration, owner principal, issuer, secret kind, and
credential generation. The strict `filebelt.mcp-keyring.v1` document contains
1 through 32 distinct 32-byte keys; generation zero, unknown generations,
nonce reuse, context mismatch, and malformed envelopes fail closed. Pending
OAuth verifier/state material uses a separate envelope row and is deleted when
the one-shot attempt is consumed or any registration credential/configuration
generation changes. Registration deletion first revokes authority and then
cryptographically erases its envelopes; tombstones retain redacted revocation
outcome evidence, not a recoverable secret.

Approval, data-grant, and service-grant POSTs reserve the principal-scoped
idempotency key and create authority in one PostgreSQL transaction. Concurrent
matching retries replay the exact stored status/body; key reuse with a distinct
canonical request fingerprint fails closed, and a failed authority insert rolls
back the key reservation.

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

MCP uses a separate bounded envelope:

| Setting | Default | Accepted envelope |
| --- | ---: | ---: |
| Connect timeout | 5 seconds | 1--30 seconds |
| Discovery/progress-idle timeout | 15 seconds | 1--60 seconds |
| Operation timeout | 60 seconds | 1--120 seconds |
| Absolute timeout | 120 seconds | operation timeout--300 seconds |
| Input message | 1 MiB | 64 KiB--1 MiB |
| Result | 4 MiB | input-message limit--4 MiB |
| Attachment soft limit | 4 MiB | 1--16 MiB |
| Attachment hard limit | 16 MiB | fixed at 16 MiB |
| Encoded attachment wire limit | 24 MiB | fixed at 25,165,824 bytes |
| Concurrent work | principal 4; registration 2; replica 64 | positive; registration <= principal <= replica <= 256 |
| Admission queue | 16 | 1--64 |
| One-shot runners | principal 1; tenant 8 | positive; tenant >= principal |

An invocation accepts at most four explicit attachment bindings. Interactive
invocation is additionally rate-limited to 60 per principal and 20 per
personal registration per hour. Service invocation is limited to 600 per
principal per hour and its narrower persisted grant quota. Test and discovery
share a ten-per-principal and ten-per-registration ten-minute window.
Before asking Kubernetes to create a one-shot runner, the broker serializes on
a tenant admission row and reserves a PostgreSQL slot keyed by tenant,
principal, and invocation. Expiry marks a reservation for reconciliation but
does not free capacity. The broker releases it only after the controller
confirms idempotent deletion; failed deletion therefore remains fail-closed and
continues to consume quota. The controller Lease elects a writer but is not the
quota authority, and controller Pod counts are defense in depth only.

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

The current checkpoint and verification formats are
`filebelt.recovery.checkpoint.v2` and `filebelt.recovery.verification.v2`.
Version 2 adds MCP registration, deletion-tombstone, active runner-slot,
secret-envelope, and OAuth attempt inventories and records every referenced MCP vault KEK generation
without granting recovery access to ciphertext, nonce, issuer, or secret kind.
The checkpoint remains bounded to 1 MiB. Restore verification fails when an MCP
inventory, KEK generation, migration checksum, audit watermark, or payload
manifest differs. Operators must restore the vault keyring generations required
by the checkpoint before enabling the broker or any MCP authentication flow.

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
