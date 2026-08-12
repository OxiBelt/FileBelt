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
- MCP policy/vault schemas are forward-only. Retain every KEK generation named
  by `filebelt.recovery.checkpoint.v3`; disabling MCP never authorizes dropping
  its tables or deleting encrypted rows.
- Collaboration room and manifest schemas are forward-only. A rollback fences
  active rooms and retains their UUID CRDT objects and PostgreSQL manifest
  evidence through the 30-day dirty-state retention period; Iggy and an
  in-memory replica never substitute for that evidence.
- Mount policy/vault schemas are forward-only. Keep gateways disabled, retain
  every admitted `mount-storage` public key and every referenced mount KEK, and never use
  tailstate or adapter caches to reconstruct PostgreSQL state.
- Descendant-share repair state is forward-only and fail-closed. A Helm rollback,
  older API image, or Job deletion never reopens its tenant admission gate;
  retain the repair receipts, fence, audit, and outbox evidence.

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
- An MCP grant/vault verification failure leaves broker and runners disabled.
  Repair only with a new forward migration or the reviewed narrow grants; never
  grant the API access to `filebelt_mcp_vault`.
- A VFS/Headscale grant or mount-vault verification failure leaves
  `mounts.enabled=false`. Do not grant adapters database/vault access or give
  VFS a payload mount to bypass the failure.

Existing compatible workloads may continue using the expanded schema. Remove
only the opt-in Job in the next Helm revision after evidence is retained.

## Failure during workload rollout

1. Stop further rollout and public admission.
2. Confirm the previous binary is compatible with the current forward schema.
3. Retain both old and new certificate identities and CA roots.
4. Run `helm rollback` to the recorded revision and wait for every Pod to use
   the previous image digest and immutable configuration.
5. Confirm API and I/O mTLS, database readiness, payload probe, worker fencing,
   outbox polling, and two-user authorization behavior. If MCP remains enabled,
   also confirm broker/gateway mTLS, explicit approval, exact-version grant,
   revocation, and cross-user denial.
   If collaboration remains enabled, also confirm first-frame grant replay
   denial, 60-second reauthorization, durable ACK after manifest finalization,
   external-head freeze, and retained diff3 review state.
6. Record the failed digest/config and prevent it from being selected again.

Do not roll back a Secret in place. After v8 admission, configuration and
keyset incompatibilities are forward-fix-only: keep the v8 purpose records and
replace only the affected immutable Secret/generation. Restore the previous versioned Secret name
or contents, update the matching generation, and roll Pods deliberately.

## Descendant-share cutover rollback

If the migration, repair, verification, or activation fails, leave the gate
blocked. Preserve the operation UUID, tenant confirmation, actor identity,
batch receipts, Job logs, audit rows, and outbox watermark. A schema-compatible
previous binary may serve unaffected routes, but it cannot be used to create a
direct share or MCP data grant while blocked. Repair the defect with a reviewed
forward migration or rerun the same idempotent repair operation; never delete
security rows, disable an admission trigger, or use owner credentials to mark a
run verified/active.

## Collaboration rollback

Disable new collaboration grants at the API before removing an edge route or
scaling the collaboration role. Drain connections, fence every remaining room,
and wait until PostgreSQL records its final manifest state. Do not acknowledge
or discard a group merely because a WebSocket connection closes.
The previous binary may be selected only when it understands the expanded
room/manifest schema; otherwise leave collaboration disabled while ordinary
immutable versions remain available. Preserve dirty rooms for explicit diff3
review or their fenced 30-day expiry. WebTransport has no Phase 5 deployment
path and cannot be enabled or rolled back independently.

## MCP broker or runner rollback

Disable runner admission first. Cancel active runner invocations and keep the
current controller available until it removes invocation-labeled Pods and
bootstrap Secrets. Then set `mcp.runners.enabled=false`; do not delete arbitrary
Pods or Secrets by name prefix alone. Streamable HTTP mediation may remain
enabled only if the broker, vault, gateway, database policy, and revocation path
are independently healthy.

To disable all MCP, revoke affected registrations/services, wait for active
invocations to reach a terminal state, then set `mcp.enabled=false`. Restore the
recorded previous API/web images and configuration together so the public
contract and SPA do not diverge. Current binaries require configuration version
8 and purpose-tagged version-2 keysets. After any version-8 admission, roll back
only to a previously recorded fixed version-8 image, ConfigMap, and overlapping
same-purpose keyset set; never reintroduce a shared-key verifier. The expanded
PostgreSQL schema and vault ciphertext remain in place.

Never roll a catalog entry back by moving a digest or weakening signature
policy. Select a previously reviewed immutable catalog/root/bundle ConfigMap and
digest-pinned image, or leave runners disabled. Preserve old certificate and
KEK generations through the rollback verification window.

## Mount preview rollback

The supported rollback is to keep every mount protocol disabled. If a test deployment
rendered the preview, stop listener admission, advance the affected gateway epochs,
revoke active credentials as required, close sessions/handles/locks in
PostgreSQL, and scale gateway, VFS, and Headscale-sync workloads to zero before
rolling API or I/O. Retain both gateway RWO tailstate claims for incident
evidence; do not attach them to another gateway identity. The additive
`filebelt_mount` and `filebelt_mount_vault` schemas, mount KEKs, and admitted
`mount-storage` verification keys remain in place until no retained recovery
evidence references them.

For a split NFS cutover failure, retain both the relay tailstate claim and the
backend recovery claim. An older chart may be restored only with NFS disabled;
restoring the co-located Ganesha/bridge/`tailscaled` Pod with NFS enabled would
reopen the DNS and Headscale egress boundary. Relay-only rollback does not
advance the gateway epoch. A backend rollback uses the normal drain/fence path
and only a previously qualified digest within the split topology.

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
