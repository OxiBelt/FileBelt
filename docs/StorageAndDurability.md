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

Migration `000003_phase5_markdown.sql` records tenant-scoped Markdown rooms,
their epochs and frozen/ended state, participants, one-use grant consumption,
and a strictly ordered fenced manifest for every durable Yjs update group and
checkpoint. It also extends MCP invocation activity with an exact Markdown
node/base-version context and domain-separated normalized source digests; raw
Markdown never enters invocation persistence. PostgreSQL is authoritative for
those rooms, manifests, and provenance evidence. CRDT bytes use separately UUID-addressed payload objects through new scoped I/O
capabilities; Iggy may notify a replica but cannot establish room state,
durability, authorization, sequence, or acknowledgement.

Migrations `000004_phase6_mounts.sql` and
`000005_phase6_mount_vault.sql` add read-only mount policy, credential,
gateway, session, handle, share-mode, byte-range-lock, Headscale-device,
authentication-throttle, and encrypted verifier-envelope state. PostgreSQL is
authoritative for every mount fence and lock. Neither a Headscale response,
gateway cache, adapter process, nor tailstate volume can reconstruct or replace
that state.

Migration `000006_phase7_documents.sql` adds provider-neutral external-document
sessions, participants, one-use launch-grant digests, staged revisions,
contributors, reconciliation leases, bounded event metadata, and an idempotent
preset-expansion marker. PostgreSQL is authoritative for callback idempotency,
expected-head conflicts, and commit outcomes; provider callbacks, adapter
memory, and Iggy delivery cannot reconstruct or replace that state.

The descendant-share cutover migration adds a `filebelt_security` tenant
admission state, repair-run/batch checkpoints, and per-row repair receipts.
PostgreSQL seeds every current and future tenant blocked with a durable fence;
direct-share and MCP-data-grant insertion checks fail closed below the API.
Each repair transaction selects no more than 1,000 total eligible rows, records
the row reason and operation UUID, revokes recursive direct shares and
pre-fence active MCP data grants, deletes linked ACL rows, advances generation
projections, and records audit/outbox evidence atomically. Verification and
explicit activation require the same operation, administrator, compiled source
revision, and tenant serialization fence. Recovery inventory must preserve and
verify this admission/repair state; an absent or mismatched projection admits
no new affected grant. Post-activation direct-share rows must carry the current
authorization-model marker, and MCP grants must carry their drive ACL fence;
older writers that omit either value fail closed.

Logical identifiers and physical storage locators are independently generated
UUIDv4 values. Public UUID strings use canonical lowercase form. Composite
keys and foreign keys carry tenant and drive boundaries. A transactional
closure table represents the strict namespace tree; live sibling comparison
keys are unique, and moves use deterministic lock ordering and cycle checks.

Pre-created group roles separate migration, API, I/O worker, maintenance, VFS,
Headscale synchronization, audit export, and recovery privileges.
Deployment-specific logins inherit
exactly one group role. Grants provide defense in depth but do not replace the
Virtual ACL evaluator:

- the API resolves identity and makes policy decisions but has no payload
  mount;
- the I/O worker sees only operation, payload, replay, and generation
  projections;
- the maintenance worker leases and reconciles only its owned durable state;
- the VFS can evaluate mount policy and create fenced sessions, handles, and
  locks but cannot resolve physical payload paths or mount the payload claim;
- the Headscale synchronization role can replace only its validated device
  observation projection and cannot issue credentials or sessions;
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

The database owner opens the migration window with the release-matched
`roles.sql`. That script grants `filebelt_migrator` database `CREATE` only so
immutable migrations can execute their already-released idempotent schema
statements, and makes the migrator the owner of `filebelt_revision` without
granting database or role ownership. The release-matched `grants.sql` closes
the window by revoking database `CREATE`; `verify-grants` fails if any reviewed
group role retains that privilege.

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

## Mount state, verifier vault, and recovery

`filebelt_mount` owns the policy and runtime state used by both protocol
adapters. Policy replacement, credential revocation, device revocation,
gateway epoch change, and session close update dependent fences in the same
transaction. Handle admission locks the exact session, credential, policy,
device, gateway, drive, namespace, membership, and ACL generations before an
operation. Share modes and byte-range locks are database rows scoped to that
handle/session and are removed on close or session expiry; adapter memory is
never lock authority.

Authentication failures are keyed by a domain-separated digest of username
and source address, not raw values, and use a PostgreSQL time window. A
successful authentication clears the corresponding bucket. This rate limit is
defense in depth: verifier comparison, current credential/policy/device fences,
and mTLS gateway identity remain mandatory even when no throttle row exists.

`filebelt_mount_vault` stores only envelope-encrypted protocol verifiers. It
reuses the strict `filebelt.mcp-keyring.v1` keyring parser and AES-256-GCM
envelope implementation, but uses a distinct operator Secret and AAD context
binding tenant, credential, owner principal, protocol namespace, verifier kind,
and credential generation. FTPS stores a random pepper plus HMAC-SHA256 digest;
SMB stores an NTLM verifier for the future Samba authentication bridge. The
plaintext random password exists only during create response construction and
is zeroized after use. Deleting or replacing authority makes the old envelope
unusable even before later physical cleanup.

The Headscale synchronizer treats one successful API response as a full
snapshot. It validates the entire bounded response, rejects duplicate node IDs
and malformed expiry, ignores tagged/service nodes, resolves each exact OIDC
issuer/subject to an active principal, then atomically upserts the complete
observation set and revokes missing devices. A failed or partial response makes
no database change.

Mount reads do not copy or stage payloads. A VFS handle pins one immutable file
version, then a maximum-15-second `fbcap2` admits an exact byte range at the I/O
worker. The worker revalidates the authoritative handle/generation/version
projection and reads the existing UUID-addressed payload. No mount writer is
implemented, so mount access creates no new version, reservation, staging
object, or copy-on-write durable state in this release.

## Versions, trash, and quota

Every committed content change, including zero-byte content, creates an
immutable linear version. The file head advances only when the expected head
matches. Metadata-only changes create no content version. Restoring history
creates a new head that references retained immutable content; it does not
mutate an old version or create sibling conflict versions.

Migration `000016_revision_storage.sql` adds the canonical content indirection,
Git projection, per-drive shared-chunk manifests, persistent text preferences,
content-class policy, backfill jobs, per-version repair holds, and an explicit
tenant activation fence. PostgreSQL remains authoritative for versions,
expected heads, backend choice, chunk references, quota, reconciliation, and
activation. Git and chunk files are replaceable byte planes and never determine
authorization or current head state.

All office and binary content uses fixed 16 MiB chunks except the final chunk,
including zero-length manifests. Reuse is limited to an exact
`(tenant, drive, BLAKE3, size)` match; a physical chunk is charged once to that
drive while every manifest retains its logical size. Publication fsyncs the
immutable chunk and parent directory before the PostgreSQL reference-count and
manifest transaction can commit. Range reads verify only intersecting chunks;
scrub and recovery cover the complete manifest. Delete intent, quarantine, and
reference-count transitions are fenced and never inferred from a directory
scan.

The first compatible release leaves revision writers disabled, creates a
legacy-content row for every existing and concurrent old-format version in the
same transaction, and backfills in the background through purpose-scoped I/O
reads. Validated text targets Git; ODT/ODS/ODP, DOCX/XLSX/PPTX, and other bytes
target shared chunks. A digest, classification, Git, or chunk mismatch creates
one per-version hold instead of blocking unrelated history. Activation requires
zero pending jobs, zero unresolved holds, verified Git refs/chunk refcounts,
and a recorded compatible source revision. The next release may switch writers
only by advancing that PostgreSQL fence; rollback before activation keeps dual
reads, while rollback after activation requires a v4 checkpoint and a binary
that understands both backends.

### Directory Git durability

The compatibility release adds directory-repository metadata keyed by the
immutable root node, its fencing/generation state, accepted `main` projection,
derived per-file version relationships, Git/LFS intake state, retention
deadlines, and durable reconciliation/repair holds. PostgreSQL is authoritative
for repository admission, root membership, `main` projection, derived heads,
quota, retention, recovery, and activation. Git repositories and LFS objects
are replaceable byte planes; non-`main` refs and Git metadata cannot recreate a
PostgreSQL state.

A `main` change is accepted only after bounded validation and a fenced
PostgreSQL operation reserve its complete outcome. It validates the 1 GiB pack,
32 first-parent commits, 10,000 changed paths per commit, 100,000 tree entries,
100 MiB ordinary blobs, and configured LFS max-file limit (default 1 TiB)
before publishing a projected head. The durable transaction records every
affected FileBelt node/version relationship, quota transition, audit/outbox
record, expected root/head fence, and ordinary per-path authorization result.
A crash before it leaves intake quarantined or replayable, never a partially
advanced FileBelt tree; a crash after it reconciles against the recorded `main`
OID and deterministic derived versions.

Repository membership is a namespace invariant, not a Git directory scan. No
root may nest, normal moves cannot cross its boundary, and a same-drive root
move keeps its ID. `.git` is rejected before persistence. Empty directories use
the canonical zero-byte `.filebeltkeep` projection. `main` and derived
per-file history remain until repository purge. Committed unreachable Git/LFS
objects are retained for 30 days; rejected or quarantined intake for 24 hours.

Activation uses two releases. The first keeps directory writers/transports
disabled while it creates compatible rows, inventories eligible roots, and
validates recovery. The later release enables a root only after quiescence and
`filebelt.recovery.checkpoint.v5` verification of PostgreSQL, payload, Git, and
LFS state. Rollback before activation retains additive state with writers
disabled; after activation it requires the matched v5 checkpoint and compatible
binary and never infers a projected tree from Git.

Markdown explicit save consumes a durable collaboration checkpoint through the
ordinary expected-head upload/commit transaction and creates the same linear
immutable version as any other content update. It records validated media type
and provenance (`origin`, optional source version, creator display name, and
MCP-assisted flag). The MCP-assisted flag is true only when a durable group
transaction matched a successful invocation's tenant, principal, node, immutable
base version, and normalized source-before/source-after digests; direct uploads,
saves, and copies cannot attach an invocation identifier. A source-to-Markdown conversion first records an exact
import intent; it is not inferred from an upload declaration or a browser
conversion result. Browser Office conversion is bounded and local-only: it
cannot overwrite the source, create a version without the import intent, or
turn extracted attachments, OCR, or remote assets into payload reads. A concurrent
head change outside a room freezes its dirty state rather than creating a
sibling version or silently applying a CRDT merge.

## Collaboration durability and recovery

The collaboration role is a dedicated Rust process using Yrs `0.27.3`; the
browser uses Yjs `13.6.32`. A room accepts only `yjs-v1` groups no larger than
2 MiB, assembled from chunks no larger than 256 KiB. The role writes each
group through a scoped `fbcap1` collaboration-object capability. It returns an
acknowledgement only after the I/O worker has finalized the UUID payload,
fsynced the file and parent-directory state, and a fenced PostgreSQL
transaction has revalidated the participant session and Virtual ACL generation
projection and committed the corresponding manifest sequence. A restarted
role reconstructs room state from the PostgreSQL manifest sequence and the
referenced payload objects; it never reconstructs authority or order from an
event stream.

Every payload row has an immutable authority class. Collaboration manifests
carry a foreign key to the `collaboration` class, and the collaboration runtime
can access payload rows only through a security-barrier view filtered to that
class. It therefore cannot turn an ordinary file payload into a collaboration
object even if the collaboration database credential and capability signer are
both compromised.

Before the first snapshot, each epoch reconstructs its source bootstrap with a
deterministic Yjs client identifier derived from the room, epoch, and immutable
base version. This keeps bootstrap item identities stable across replica
restarts so acknowledged update groups remain replayable; the identifier is not
an authorization or identity credential.

Dirty rooms retain their latest durable manifests for 30 days after the last
authorized activity. The service records a one-time operator-visible warning
marker at day 23 and then freezes and expires the room at day 30 according to a
fenced retention transition; cleanup removes
only unreferenced CRDT objects after recovery evidence is preserved. Snapshot
compaction supersedes covered update and snapshot objects; maintenance waits a
one-day recovery window before enqueueing their physical deletion. An explicit
discard immediately fences dirty state and advances it to the same cleanup
path. A failed write, finalization, manifest attempt, or snapshot commit marks
its unreferenced object for idempotent deletion; expired staging reservations
and finalized objects without a manifest are reaped by maintenance, with the
reservation or committed-byte accounting released exactly once. Physical
cleanup leaves a never-finalized object and payload in the explicit `abandoned`
terminal state; only an object that acquired a final size and digest reaches
the durable `tombstoned` terminal state. Local
offline edits are deliberately not a durable service record. On external-head,
authorization, or recovery freeze, retained room data is available only for
explicit deterministic diff3 review against its base and current head.

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

## Document-session durability and reconciliation

Forward migration `000006_phase7_documents.sql` adds the provider-neutral
`filebelt_document` schema and the `document_session` principal kind. Sessions
bind provider, node, exact base and expected-head versions, a monotonically
increasing fence, 24-hour absolute expiry, and 100-second reconnect window.
Participants bind one initiating principal and API session to a mode and the
four authorization generations. One-use launch values are stored only as
32-byte BLAKE3 digests and expire within 60 seconds.

Each provider save event has one immutable canonical digest and one revision
row. The row moves through `received`, `staging`, `staged`, `committing`, and a
terminal `checkpoint`, `committed`, `no_op`, `conflict`, `rejected`, or
`failed` result. Payload allocation and drive reservation are transactional.
The I/O worker writes only the allocated whole-payload UUID, recomputes BLAKE3,
fsyncs bytes and directory metadata, and records finalization before the
document service can queue a commit. A response lost at any boundary is
recovered by reading the row, never by allocating another revision.

Non-checkpoint staged revisions create one PostgreSQL reconciliation job. A
worker leases it with PostgreSQL time, an attempt bound, and a fencing token.
It re-locks the participant API session, all four authorization generations,
document session, revision, and current node head in the same transaction that
either inserts one immutable `external_document` file version or records the
terminal conflict. If the finalized bytes match the current head's BLAKE3 and
length, the operation is an idempotent no-op. A successful commit changes the
payload from finalized to referenced, transfers reservation to physical usage,
advances the node head, records contributors and audit/outbox rows, and freezes
other document sessions and an active Markdown room for the old head.

A current-head mismatch never overwrites or merges. The revision and staged
payload move to `conflict` and are retained for seven days for the explicit
conflict-copy workflow. At most one timer checkpoint per session is retained
for 24 hours; a newer checkpoint makes the older one reclaimable. Expired
checkpoint/conflict outputs become payload deletion intent and release their
drive reservation only while still unreferenced; committed and conflict-copy
payloads remain referenced and are never retention-deleted. Session events are
purged after 30 days, launch grants after consumption or expiry, and API
create-operation receipts after their fixed 24-hour replay window. Normal
audit retention remains unchanged. Maintenance performs each transition in
bounded locked batches.

The migration also expands built-in ACL presets with `COMMENT` and `REVIEW`.
It replaces row-level ACL capability invalidation with statement-level
transition-table triggers so a multi-action preset expansion advances each
affected drive/resource generation once. The data migration is idempotently
recorded in `filebelt_document.data_migrations`; no existing content, version,
or ACL row is deleted or rewritten.

Forward migration `000010_onlyoffice_origin_isolation.sql` is a quiesced
security cutover from the former public-origin editor shell. Before applying it,
operators stop document admission and keep binaries that can mint the old
launch action out of service. The migration revokes every still-live API
session linked by any historical document participant, including a participant
that was already closed; unrelated and already-expired API sessions are not
changed. It consumes every outstanding launch grant, closes every active or
disconnected participant, revokes every active or draining document session,
and advances each affected session fence. Privacy-visible audit rows record
API-session revocation and document-session closure, and one durable
`onlyoffice_origin_isolation_v1` receipt records the number of closed document
sessions. Existing revisions, staged payloads, reconciliation jobs, immutable
versions, conflicts, and retention deadlines are deliberately preserved for
normal recovery and maintenance.

Backups include document sessions, participants, revision/contributor state,
reconciliation jobs, retained output deadlines, payload references, and
`document-storage` purpose material. Restore leaves document admission disabled,
expires all restored active sessions and launch grants, advances their fences,
reconciles staged/committing rows against immutable versions, verifies every
referenced payload digest, and only then permits new sessions. Rolling back the
application keeps migration 000006 and its additive data. An older binary may
run only with document admission disabled; the migration is never reversed.
Migration 000010 is also forward-only. Rollback may disable the integration and
restore a compatible core or adapter, but must never restore the public-origin
launcher. Every user whose live session was revoked by the cutover must
authenticate again after the isolated editor hostname is active.

## Phase 8 activation, NFS recovery, and media cache

Migrations `000007_phase8_compatibility.sql`, `000008_phase8_media.sql`, and
`000009_phase8_nfs.sql` establish the additive dormant baseline. The later NFS
authority migrations add feature-scoped activation, reconciled export
manifests, common namespace metadata, immutable filehandle generations,
protocol replay high-water, and staged-writer recovery without enabling a
listener. NFS admission requires the tenant feature state and exact applied
manifest; it does not depend on the legacy global Phase 8 activation snapshot.
The namespace migration replaces mapping-local POSIX uniqueness with one
append-only identity registry per FileBelt principal, allowing multiple
Kerberos aliases only when their POSIX name, UID, primary group, and GID are
identical. An upgrade from the preceding schema stops with a deterministic
conflict inventory when existing aliases disagree; it never rewrites or
chooses an identity during migration.

Forward migration `000015_nfs_mapping_target_approval.sql` adds immutable
`filebelt_mount.nfs_mapping_proposals`, target-approval receipts, exact alias
drive ceilings, and the `filebelt_mount.nfs_approved_active_mappings` authority
view. A proposal binds the tenant, exact Kerberos principal, proposer and
target, POSIX projection, sorted drive UUIDs, expected mapping generation,
creation and 24-hour expiry, and terminal state. At most one pending proposal
exists per tenant and Kerberos principal. Pending proposals are cancelled rather
than edited. States are `pending`, `approved`, `declined`, `cancelled`, and
`expired`. Maintenance purges declined, cancelled, and expired unapproved
proposals after 30 days; approved receipts remain with mapping history, while
audit records retain their ordinary deadline.

Only `filebelt_mount.nfs_approved_active_mappings` can authorize an NFS session,
managed POSIX projection, or derived user policy. Every active mapping records
its `approved_proposal_id`; database constraints and triggers reject a direct
insert or reactivation that lacks an exact approved proposal, including from an
older binary. Approval locks and consumes the proposal, rechecks the target's
recent OIDC authentication, proposer administration, both principals' current
`READ_METADATA` on every drive, user state, POSIX identity, realm, mapping
generation, and exact stored fields, then creates the credential, mapping,
derived policy, approval receipt, audit, outbox, and session fences in one
transaction. Each alias retains an independent approved ceiling. The shared
user policy is recomputed as the sorted union of active alias ceilings; drive
attenuation, approval, and revocation advance generations and close affected
sessions atomically. Mapping revocation preserves its `revocation_reason`.

The migration quarantines every active legacy mapping without grandfathering
or administrator override. It records `target_approval_cutover`, advances
mapping and credential generations, revokes the credential, disables affected
NFS policy, closes sessions with `nfs_mapping_approval_required`, and writes
audit and outbox evidence in the same transaction. Previously revoked mappings
and append-only POSIX identities are preserved. No target proposal is invented
without a current revalidatable administrator; an administrator must create a
fresh proposal after cutover.

`filebeltctl phase8 deactivate` retains the expanded schema and readable state;
it is not a down migration. NFS uses its tenant-scoped feature state to stop new
sessions and writers, drain the applied gateway, and reconcile exports to the
disabled manifest independently of the global compatibility state. Downgrading
to a binary that cannot understand the expanded schema requires restoring the
coordinated pre-activation checkpoint into fresh targets.

The NFS target requires write sessions to durably bind tenant, principal,
API-independent NFS session, authenticated export manifest, drive, node, base
version, expected head, gateway epoch, owner/state identity, quota reservation,
and staging generation. VFS declares each signed byte-plane range before issuing
its capability. The I/O worker records the exact physical result, while the
operation remains blocking until VFS atomically applies the authoritative
extent or seek result and protocol replay receipt. Sparse extents and chunk
receipts remain invisible until COMMIT or final dirty CLOSE atomically creates
an immutable version. A failed expected-head comparison retains the staged
result for seven days. Expired and aborted writers are fenced into leased,
two-phase cleanup jobs; physical deletion, lock removal, quota release, and
receipt completion are crash-recoverable states rather than table-scanner side
effects. A never-finalized staging object may reach terminal `deleted` without a
whole-object digest because no trustworthy digest ever existed; every live,
finalized, referenced, or deletion-in-progress payload state retains the common
digest requirement. Reclaim records, replay receipts, cleanup jobs, and gateway
fencing are PostgreSQL authority; Ganesha `fs_ng` recovery data on its RWO claim
supplies protocol recovery only and cannot authorize a FileBelt commit.

Persisted NFS replay bytes remain durable only as idempotency evidence. The VFS
does not return an ordinary receipt ahead of current session and operation
admission: an operation-specific preflight derives exact generation and handle
proofs, and one repeatable PostgreSQL transaction validates those proofs and
the slot high-water in the snapshot that selects the receipt. Read replay does
not fetch payload bytes again. Atomic open retains its authorization preflight
before its database replay point. `EndSession`
records `mutation_outcome=applied` in the same transaction that closes the
session; a dedicated lookup may recover only its canonical empty success while
the closed row and every external NFS authority fence remain current. No new
table, grant, retention rule, or migration is introduced by this replay rule.

Retained-conflict copy publishes the already-finalized payload, converts its
reservation exactly once, and records the new node/version, audit, outbox, and
HTTP idempotency response in one transaction. Discard retains the inventory row
through its fixed deadline while atomically fencing the payload into cleanup
and releasing reservation only through the cleanup authority.

The NFS gateway is single active. Restart advances its epoch and opens a
90-second reclaim-only grace period, configurable from 30 through 300 seconds.
New state is rejected during grace. Delegations are disabled. Filehandles
survive a healthy restart but become stale when export, node, restore, or
filehandle generations no longer match. The schema and generic messages are
landed, but the current VFS dispatch and adapter do not admit NFS writes; these
rules are a qualification gate, not a claim of a deployable export.

Media jobs, attempts, reservations, segment receipts, manifest revisions,
cache artifacts, playback sessions, deletion intents, and diagnostics are
authoritative PostgreSQL rows. Iggy is only a wake-up. Each manifest revision
references verified immutable segments and is fenced by job epoch. An
infrastructure failure may create at most three attempts with bounded backoff;
malformed input is terminal. Failed attempts publish no new grant, retain
byte-free diagnostics for 24 hours, and quarantine unpublished bytes for
reconciliation.

Derivative bytes are rebuildable cache state on a dedicated claim mounted only
by I/O and maintenance. They are excluded from backup. Metadata is charged to
the source drive, defaults to ten percent of its quota, expires after 30 idle
days, and is evicted between global 80-percent and 70-percent watermarks.
Restore marks READY artifacts unavailable until verified or regenerated. The
controller and playback/cache I/O path are not yet qualified, so only request,
status, and cancellation admission may be enabled in development.

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
`filebelt.recovery.checkpoint.v4` and `filebelt.recovery.verification.v4`.
Version 4 records every purpose name, digest generation, and local signer
generation in its `capability_keysets` inventory; version 2 remains offline-only
and cannot admit the current deployment.
It retains collaboration room/manifest/checkpoint inventory and dirty-room
retention deadlines, plus MCP registration, deletion-tombstone, active
runner-slot, secret-envelope, and OAuth attempt inventories. It records every
referenced MCP vault KEK generation without granting recovery access to
ciphertext, nonce, issuer, or secret kind. Version 4 also hashes every
authoritative revision-storage row and field in deterministic primary-key
batches, including Git refs, shared-chunk manifests and members, reference
counts, operations, backfill jobs, holds, and activation fences. The checkpoint
remains bounded to 1 MiB. Restore verification fails when a revision,
collaboration inventory or retention
deadline, MCP inventory or KEK generation, migration checksum, audit watermark,
or payload manifest differs. Operators must restore purpose-specific public
keysets, digest generation, and local signer generations before enabling I/O,
collaboration, document, or mount reads, and must restore MCP and mount vault KEK
generations before enabling the broker or any MCP or mount authentication flow.
Mount proposal, approval, quarantine, alias-ceiling, policy, credential, device,
gateway, session, handle, and lock rows are part of the same quiesced PostgreSQL
recovery boundary. After restore, keep mount gateways disabled, advance every
gateway epoch, expire restored sessions, handles, and locks, verify that every
active NFS mapping still has its exact approval receipt, run Headscale
synchronization, and only then admit new credentials and sessions. Rollback of
the approval migration is forward-only: disable NFS admission and gateways and
retain the expanded schema. Never restore a binary that can bypass the database
approval gate while NFS state is present.

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
