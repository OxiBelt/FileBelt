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

1. Record the chart revision, selected workload image digests, ConfigMap
   identities, Secret generations, every capability purpose/digest/local
   generation and its purpose-specific public keyset, MCP and mount KEK generations, runner
   catalog/root/bundle identities, and certificate overlap.
2. Stop new collaboration grants, fence active rooms, and wait for every
   durable CRDT group to reach a PostgreSQL manifest terminal state. Stop new
   MCP admission and cancel active invocations while the controller is
   still running. Wait for runner Pods and bootstrap Secrets to reconcile, then
   upgrade to `deployment.quiesced=true` with no administrative Job enabled.
   Wait for web/API/I/O/maintenance/broker/controller Pods and all remaining
   streams and leases to drain or fence.
3. In a second revision, still quiesced, run the recovery checkpoint Job. Save
   its single `filebelt.recovery.checkpoint.v3` JSON document outside the
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
   tenant/backend identity, audit watermark, payload counts/bytes,
   collaboration room/manifest inventory and dirty-retention deadlines, MCP
   registration/tombstone/vault inventories, every referenced MCP KEK
   generation, retained mount policy/vault inventory and every referenced mount
   KEK generation, descendant-share admission state/fence/repair inventory, and
   the deterministic expected-payload inventory hash must
   agree. The emitted schema is `filebelt.recovery.verification.v3`.
6. Run bounded reconciliation. Inspect upload/finalization state, leases,
   deletion intent, quarantine, collaboration manifest/checkpoint fences, MCP
   invocation/runner leases and revocation tombstones, mount
   device/gateway/session/handle/lock fences, job attempts, outbox, and audit
   continuity. Advance gateway epochs and expire restored mount runtime state;
   keep mount workloads disabled.
7. Start a full scrub with a new run UUID and the exact tenant-slug
   confirmation. Wait for every scrub job and require zero failed,
   operator-blocked, or quarantined payloads.
8. Enable maintenance, I/O, API, web, and collaboration in that order. Enable the broker and
   controller later and separately. Repeat two-user login,
   list, upload, download/range, version restore, direct share, revoke, and
   cross-user denial, collaboration durable-ACK/reconnect/freeze checks,
   followed by MCP registration, explicit approval,
   exact-version data disclosure, broker-mediated authenticated test, and
   revocation checks.
   If restored descendant-share admission is blocked, run the documented
   repair, verification, and explicit activation sequence before either
   direct-share or MCP data-grant admission.
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
- Lost MCP KEK: keep MCP admission and broker traffic stopped. A matching
  PostgreSQL snapshot without every checkpoint-v2 MCP vault generation cannot
  recover the affected credentials; restore a complete coordinated set or
  revoke and cryptographically erase the registrations under an explicit
  incident plan. Core file operations may resume only after proving they remain
  isolated from the disabled MCP path.
- Lost mount KEK or `mount-storage` signing material: keep mount admission
  disabled. Revoke affected credentials and gateway runtime state under an
  explicit incident plan; do not derive a verifier from a tailstate volume or
  reuse an API/collaboration signing key.
- Partial scrub: rerun the same run UUID to resume idempotently. Do not treat a
  partial run as verification.
Recovery v3 records each capability purpose, digest generation, and local
generation. Recovery verification may wait up to 120 seconds for MCP quiesce
and reconciliation. Version-2 evidence is offline-only: it can inform an
investigation but cannot be used to admit a v8 runtime. After v8 admission,
repair incompatibilities forward; never roll a running deployment back to v7.
