<!-- SPDX-License-Identifier: Apache-2.0 -->

# Revision storage operations

Revision storage is a two-release, fail-closed migration. The Apache
`filebelt-revision` coordinator and the separate `GPL-2.0-only` Git adapter are
disabled by default. PostgreSQL is the only authority for backend selection,
version heads, chunk references, quota, backfill state, holds, and activation.

## Compatibility release

1. Back up PostgreSQL and the payload root, then deploy configuration format 9
   with revisions disabled. Apply migration `000016_revision_storage.sql` and
   the reviewed roles/grants allowlist.
2. Verify that every `file_versions.content_id` resolves, every legacy content
   row resolves its exact payload, and the tenant activation state is
   `compatibility`. Old-format writers remain valid because their transaction
   creates the legacy content and backfill job through the migration trigger.
3. Provision a dedicated revision database credential, capability key pair,
   coordinator server/API client TLS, coordinator/adapter TLS, and
   coordinator/I/O TLS. None may reuse another capability or mTLS identity.
4. Deploy the external Git chart into its integration namespace with an
   operator-created Git-only RWX claim. Admit only an immutable adapter image
   that enforces exact Git `2.55.0`, SHA-256 objects, source/SBOM/provenance and
   license evidence. Verify the chart's non-selector
   `filebelt.dev/adapter-*` annotations carry the exact SPDX license,
   corresponding-source URL, and source SHA-256. Do not mount FileBelt payloads
   or database credentials.
5. Enable the coordinator and move the tenant to `backfilling`. Watch durable
   backfill jobs and unresolved holds; Iggy delivery has no bearing on
   correctness. Repair the exact held version and choose retry, recovered, or
   explicit binary resolution. Never delete a hold merely to pass admission.
6. Quiesce writers and create a recovery checkpoint v4. Run Git `fsck`, compare
   the sole projected ref with PostgreSQL, verify all shared-chunk digests and
   reference counts, and confirm zero pending jobs/holds. Record the compatible
   source revision and transition to `ready`; do not activate writers in this
   release.

## Writer activation and rollback

The later compatible release may transition `ready` to `active` only while
quiesced and only after restored v4 verification matches. Activation changes
new writes to Git or shared chunks; it does not rewrite immutable version IDs.
Before activation, rollback to the old binary with revisions disabled and keep
the additive schema. After activation, do not run a binary that cannot read
Git/shared-chunk content: restore the matched PostgreSQL, payload, Git PVC, and
shared-chunk snapshot under quiescence, verify the v4 checkpoint, then resume.

## Directory Git compatibility and activation

Directory Git is a separate two-release, disabled-by-default compatibility
unit. A repository root is an explicit `directory_git` directory node; roots
cannot nest and ordinary moves cannot cross their boundary. The root ID stays
stable on a same-drive root move. `.git` is rejected and empty directories
project only as zero-byte `.filebeltkeep`. PostgreSQL, rather than Git or LFS,
remains authoritative for root membership, `main` projection, derived per-file
versions, quota, retention, activation, and recovery.

1. In the compatibility release, apply the forward directory-repository
   migration while leaving the reviewed runtime-grant allowlist unchanged and
   all directory Git writers, HTTPS, SSH, LFS, and mount writes disabled.
   Inventory candidate roots and existing
   histories, take a quiesced checkpoint v5, and verify old binaries continue
   to read their supported representations.
   The compatibility schema and private DTO validators are not writer
   authority. Before any runtime grant is added, the activation release must
   add current `WRITE_REPOSITORY` and signer admission, ruleset/check
   serialization, canonical snapshot-digest verification, idempotent
   operation replay and expiry recovery, root move/trash integration, a
   Git-derived `Verify`/`Promote` receipt, durable fencing-token high-water
   enforcement, and pre-decode resource admission.
2. Admit the isolated Git wrapper/PVC and its source, SBOM, provenance, GPL Git
   executable, notices, mTLS, fsck, and restore evidence. The coordinator has
   no Git or payload mount; no other FileBelt role mounts the Git PVC.
3. Before enabling a root, verify the selected limits: 1 GiB incoming pack, 32
   newly admitted first-parent commits/push, 10,000 changed paths/commit,
   100,000 entries/tree, 100 MiB ordinary blobs, and configured LFS max-file
   limit (default 1 TiB). Verify the 1--365-day HTTPS device-token ceiling
   (30-day default), tailnet SSH fencing, `main`-only projection, retained
   per-file history, 30-day committed-unreachable Git/LFS retention, and
   24-hour rejected/quarantine retention.
4. Enable only after quiesced checkpoint-v5 restore/reconciliation proves the
   recorded PostgreSQL root and every accepted `main` OID agree. Existing
   histories remain retained; new in-root versions do not acquire the old
   per-file Git projection. Other Git refs remain Git-only.

NFS, SMBv3, and FTPS write integration is not an activation prerequisite or a
claimed capability. It stays disabled until independently qualified. A later
mount qualification must prove NFS commits only on `COMMIT` or final dirty
`CLOSE`, SMB uses no durable handles, and FTPS uses no resume; each must pass
current ACL/generation, expected-head, quota, replay, reconnect, and
cross-writer tests before it can project a directory commit.

Rollback before directory activation leaves additive rows and all transports
disabled. After activation, quiesce writers and restore the matched PostgreSQL,
payload, Git, and LFS checkpoint-v5 set; verify grants, fsck, recorded `main`
OIDs, derived versions, quota, retention deadlines, and two-user authorization
before re-enabling traffic. Do not roll back to a binary unable to read retained
directory-repository state, infer state from Git, or delete quarantine/holds to
satisfy a check.

## Comparison admission

The core chart projects `[revisions.limits]` with
`global_comparisons = 2` and `per_user_comparisons = 1` by default. Operators
may set `revisions.limits.globalComparisons` from `1` through `32` and
`revisions.limits.perUserComparisons` from `1` through `8`; the per-user value
must not exceed the global value. Core admits a comparison only when both
permits are immediately available. An HTTP `429` with
`revision.admission_limited` and `Retry-After: 5` is capacity pressure, not a
size failure; HTTP `413` continues to mean that an input or result exceeded a
declared bound.

The Git chart defaults `limits.maxConcurrentPrivateRequests` to `8` and
`limits.maxConcurrentGitProcesses` to `2`, and projects them to the adapter
`serve` flags. Their allowed ranges are `1` through `64` and `1` through `16`,
with Git processes no greater than private requests. Keep the operator-created
adapter ConfigMap. A raw connection above the private-task ceiling closes;
comparison process saturation returns the typed retryable result, while
non-comparison maintenance waits only within its existing request deadline.

Deploy compatible core and protocol handling before the bounded adapter. To
roll back, restore the compatible adapter before removing core support. A
limits-only rollback restores the last validated values and allows active work
to drain; it changes no persisted state and needs no migration. Revisions
remain disabled by default.

## Qualification gate

Production admission requires current `main` evidence for concurrent legacy
writes during migration, restart/retry at every publish boundary, corrupt input
holds, UTF-8/NUL/100 MiB classification, ODF and OOXML preservation, per-drive
dedup/quota races, Range integrity, Git ref CAS/fsck/restore, diff timeout and
atomic bounds, dual-scope comparison saturation and permit recovery, a
controlled maximum of two concurrent Git processes under excess comparison
load, ACL/session revocation, cross-tenant/OID/chunk denial, amd64 and arm64
adapter behavior, and a fresh-target v4 restore. Static Helm rendering, unit
tests, and a local system Git version are not substitutes for that matrix.
