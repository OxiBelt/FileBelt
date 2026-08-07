<!-- SPDX-License-Identifier: Apache-2.0 -->

# Kubernetes backup, restore, and scrub

## Guarantee

FileBelt supports a coordinated quiesced PostgreSQL and payload snapshot. It
does not claim online backup, PITR, high availability, or a numeric RPO/RTO.
The operator owns snapshot scheduling, encryption, retention, transport, and
provider-specific restore commands. A backup is verified only after restore to
fresh targets and a successful full payload scrub.

The versioned recovery checkpoint is bounded metadata, not a backup. Store it
with the external PostgreSQL/PVC snapshot identifiers and protect it as
sensitive operational evidence.

## Create a coordinated backup

1. Record the chart revision, five image digests, ConfigMap identities, Secret
   generations, key generations, and certificate overlap.
2. Upgrade to `deployment.quiesced=true` with no administrative Job enabled.
   Wait for web/API/I/O/maintenance Pods to terminate and for active streams
   and leases to drain or fence.
3. In a second revision, still quiesced, run the recovery checkpoint Job. Save
   its single `filebelt.recovery.checkpoint.v1` JSON document outside the
   cluster.
4. While still quiesced, take the external PostgreSQL backup and RWX volume
   snapshot/copy. Record their immutable provider identifiers alongside the
   checkpoint.
5. Disable the checkpoint Job and unquiesce. Verify normal readiness and the
   two-user acceptance path.

Do not retain database dumps, payload content, keys, cookies, capabilities, or
unredacted logs in ordinary CI artifacts.

## Restore rehearsal

1. Create a new database, namespace, operator Secrets, and empty/fresh RWX PVC.
   Never restore over the source database or PVC.
2. Restore the selected PostgreSQL and payload snapshots whose provider IDs
   were recorded with the same checkpoint.
3. Keep workloads disabled. Apply release-matched roles, forward migrations,
   reviewed grants, and grant/schema verification.
4. Run configuration validation and the storage semantics probe.
5. Run `filebeltctl recovery verify` against the saved checkpoint. Migrations,
   tenant/backend identity, audit watermark, payload counts/bytes, and the
   deterministic expected-payload inventory hash must agree.
6. Run bounded reconciliation. Inspect upload/finalization state, leases,
   deletion intent, quarantine, job attempts, outbox, and audit continuity.
7. Start a full scrub with a new run UUID and the exact tenant-slug
   confirmation. Wait for every scrub job and require zero failed,
   operator-blocked, or quarantined payloads.
8. Enable maintenance, I/O, API, and web in that order. Repeat two-user login,
   list, upload, download/range, version restore, direct share, revoke, and
   cross-user denial checks.
9. Capture only redacted verification metadata. Delete the recovery namespace,
   database, and PVC only after validating their exact deterministic names and
   confirming they are rehearsal-owned.

## Failure handling

- Database intact, payload damaged: preserve the PVC, quarantine mismatches,
  and restore only to a fresh volume. Metadata does not manufacture payload
  bytes.
- Payload intact, database damaged: restore a compatible authoritative
  database. Filesystem discovery never recreates namespace or ACL truth.
- Iggy lost: recreate it and replay/rebuild notifications from PostgreSQL;
  never restore policy state from Iggy.
- Lost signing/digest keys: keep traffic stopped and follow the key-compromise
  procedure. A backup without required key generations may be unusable.
- Partial scrub: rerun the same run UUID to resume idempotently. Do not treat a
  partial run as verification.
