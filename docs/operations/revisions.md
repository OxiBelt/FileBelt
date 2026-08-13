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
   license evidence. Do not mount FileBelt payloads or database credentials.
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
