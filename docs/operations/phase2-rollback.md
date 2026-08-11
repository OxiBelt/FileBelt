<!-- SPDX-License-Identifier: Apache-2.0 -->

# Phase 2 Rollback and Recovery Runbook

## Principle

Rollback means returning to a previously compatible binary and configuration
without erasing committed state. SQL migrations are forward-only. Payload and
PostgreSQL state are never reset merely because the project is pre-1.0. If a
contract migration has removed backward compatibility, restore a known
consistent backup and move forward with a repair migration.

## Before changing state

1. Disable public write/login admission at OxiBelt while retaining a bounded
   operator diagnostic path.
2. Record the incident time, source revision, exact image digests,
   `filebelt.toml` checksum, schema version, tenant/backend IDs, current and
   retiring key generations, outbox watermark, active leases, and storage free
   space.
3. Drain active streams for at most the configured 60-second authorization
   recheck bound. Fence operations that do not drain.
4. Stop new job acquisition, allow current fenced transitions either to finish
   or lose their lease, and preserve database/worker logs with secrets redacted.
5. Take quiesced PostgreSQL and payload snapshots before repair. Restore into
   fresh volumes for validation; do not overwrite the only evidence.

## Compatibility decision

Use the migration compatibility declaration and image build identity to choose
one path:

- **Previous binary is schema/config compatible:** deploy it after disabling
  features/routes it does not understand; keep additive schema and persisted
  rows in place.
- **Previous binary cannot parse new configuration:** restore its previous
  configuration while retaining every secret/key generation needed by live
  credentials and data.
- **Contract migration is irreversible:** do not deploy an incompatible older
  binary. Restore the pre-contract snapshot or ship a forward repair migration
  and corrected current binary.
- **Data integrity is uncertain:** keep traffic disabled, restore a copy, run
  reconciliation/scrub, and make a documented forward repair. Do not improvise
  SQL deletion or filesystem cleanup.

## Component procedures

### OIDC, sessions, and ACL

- Disable new callbacks and unsafe mutations, but do not reinterpret existing
  issuer/subject mappings.
- For a suspected identity/session compromise, locally suspend the principal
  or revoke the affected/all sessions. Do not shorten key overlap while an
  unrevoked credential may still require validation.
- For an ACL evaluator defect, stop all affected access paths together. Do not
  leave a worker or future adapter on different semantics. Anonymous sharing is
  unsupported in Phase 2 and must remain disabled.
- For the descendant-share attenuation cutover, rely on the durable tenant gate
  rather than an edge-only route block. It rejects both direct-share and MCP
  data-grant creation even from an older API binary. Retain the gate closed,
  repair all recursive shares and pre-fence grants through the reviewed
  recovery procedure, verify its receipts/generations/outbox, and explicitly
  activate only with the validated tenant-admin actor. Do not delete ACL,
  security, audit, or outbox rows to make a rollback appear complete.
- For the forward ACL replacement fix, temporarily reject the ACL replacement
  endpoint at method-aware ingress: `PUT
  /api/v1/drives/{drive_id}/nodes/{node_id}/acl`. Drain and replace every API
  replica, verify API health and the two-user ACL replacement checks, then
  re-enable it. The checked-in OxiBelt WAF is disabled and must not be enabled
  or edited for this cutover. If method-aware ingress is unavailable, use
  `deployment.quiesced=true` while draining, replacing, and verifying replicas.
- Preserve generation values and audit events. Never decrement a generation or
  delete a deny to make an old binary accept the data.

### Capability or digest keys

- Stop new issuance, make a newly generated key current, distribute verifier
  material first, and revoke/fence affected sessions, links, or operations.
- Retain old capability public keys only through the 60-second maximum token
  lifetime after issuance stops. Retain session and share digest keys for their
  seven- and 30-day validation windows unless all affected credentials have
  been authoritatively revoked.
- A missing retiring key is not repaired by accepting an unsigned or unknown
  generation.

### API, worker, and edge

- Restore OxiBelt and service images/configuration as one reviewed route set.
  Keep backend ports isolated and write retries/content caching disabled.
- Start verification/storage workers before capability issuance, then API,
  then edge admission. Confirm API has no payload mount and workers lack API
  signing/session secrets.
- Keep the reserved public-share route disabled. A future release may enable it
  only with an accepted boundary and proof that no raw fragment token reaches
  logs.

### PostgreSQL migration

- Stop at the last binary/schema pair declared compatible by the migration
  evidence. Do not edit the SQLx ledger, modify a released migration checksum,
  run a down migration, or restore selected tables into a newer schema.
- For an interrupted additive migration/backfill, rerun its idempotent forward
  step under the migration lock and validate invariants before traffic.
- For a bad contract migration, restore the complete pre-contract database and
  matching payload snapshot or create a new forward repair migration.

### Payload commit or deletion

- Run read-only operation/manifest/path diagnostics first. Do not manually
  promote `WRITING`/`FINALIZED` to referenced or delete a finalized orphan.
- Reconciliation uses the durable operation and fencing records to complete or
  quarantine interrupted writes. Preserve the 24-hour orphan and expired-part
  grace periods.
- A missing, short, or checksum-invalid object is quarantined and every
  referencing version is identified. It is never hidden as an empty file or
  silently removed from history.
- Quarantine recovery first persists `quarantining`, then reconciles the
  UUID-addressed source and quarantine destination without overwriting either
  when both exist. A retry completes the database transition after an already
  completed filesystem move.
- Resume deletion only from a committed deletion intent after reference and
  fence rechecks. Quota bytes are released only after successful physical
  deletion.

### Jobs and Iggy

- Iggy may be stopped without rolling back database state. Keep PostgreSQL
  polling enabled, repair the helper, then replay the transactional outbox.
- Never delete the outbox to clear a backlog. Consumers deduplicate and rebuild
  from PostgreSQL when seven-day Iggy retention has elapsed.
- Stop a defective job kind from leasing new work, allow leases to expire, fix
  the worker, and use the explicit operator retry for terminal items. Never
  reuse an old fencing value.

## Restore verification

Before restoring traffic, require all of the following:

- configuration, schema, tenant bootstrap, key overlap, and storage probes pass;
- migrations and repository invariants are clean;
- no unexplained active lease, deletion intent, finalized orphan, or outbox gap
  remains;
- every restored payload manifest has the expected size and BLAKE3 or is
  explicitly quarantined;
- two separate OIDC users demonstrate private-drive isolation, authorized
  share/download, revoke, version restore, trash restore, and session revoke;
- an already open download terminates within the authorization-check bound
  after revocation; and
- audit records cover the incident and operator actions without raw secrets.

Re-enable read traffic before write admission when doing so is compatible with
the incident. Re-enable uploads and maintenance jobs last, monitor operation,
quota, quarantine, lease, and outbox signals, then remove the maintenance
window.

## Evidence and cleanup

Record the reason, scope, decisions, exact commands, revisions/digests,
snapshots, hashes, tests, skipped checks, and remaining risk in an operator
report. Treat snapshots, logs, and browser artifacts as sensitive. Delete only
explicitly identified temporary resources after recovery is accepted; retain
the original evidence according to the incident policy.
