<!-- SPDX-License-Identifier: Apache-2.0 -->

# Kubernetes rollback

## Invariants

- PostgreSQL migrations are forward-only; Helm rollback never runs a down
  migration.
- The external PVC is retained unchanged through failed installs, upgrades,
  rollbacks, and uninstall.
- Rollback uses recorded image digests, immutable ConfigMaps, Secret
  generations, and overlapping backend certificate trust.
- Iggy contains no rollback authority. PostgreSQL and the payload checkpoint
  determine recovery state.

## Failure before workload rollout

If migration, owner grants, grant verification, bootstrap, or storage probe
fails, stop before changing Deployment pod templates. Preserve the failed Job,
logs, chart revision, SQLx ledger, and exact administrator SQL checksum.

- A migration failure is repaired with a new forward migration; do not edit a
  released migration or retry an unexplained checksum mismatch.
- A grant failure is repaired by reviewing and reapplying the release's
  explicit `grants.sql`; never substitute a broader grant or default privilege.
- A storage-probe failure leaves workloads disabled until the operator fixes
  ownership/provider semantics or selects a known-good fresh claim.

Existing compatible workloads may continue using the expanded schema. Remove
only the opt-in Job in the next Helm revision after evidence is retained.

## Failure during workload rollout

1. Stop further rollout and public admission.
2. Confirm the previous binary is compatible with the current forward schema.
3. Retain both old and new certificate identities and CA roots.
4. Run `helm rollback` to the recorded revision and wait for every Pod to use
   the previous image digest and immutable configuration.
5. Confirm API and I/O mTLS, database readiness, payload probe, worker fencing,
   outbox polling, and two-user authorization behavior.
6. Record the failed digest/config and prevent it from being selected again.

Do not roll back a Secret in place. Restore the previous versioned Secret name
or contents, update the matching generation, and roll Pods deliberately.

## Incompatible schema or inconsistent state

If a contract migration made the old binary incompatible, do not force it to
start and do not attempt a down migration. Quiesce the release, preserve both
planes, restore the last coordinated backup into a fresh database and PVC, and
use [Kubernetes recovery](kubernetes-recovery.md) to verify and migrate forward.

If database and payload snapshots have different watermarks, neither snapshot
is a supported FileBelt restore. Preserve them for diagnosis and select a
coordinated pair or reconstruct under an explicit incident decision.

## Published artifact incident

Published tags are not a mutable rollback mechanism. Pin consumers back to a
known-good digest and publish a new fixed SemVer release. Do not automatically
delete registry versions or attestations; an administrator may revoke an
artifact only through a separately reviewed incident procedure.
