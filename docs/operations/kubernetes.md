<!-- SPDX-License-Identifier: Apache-2.0 -->

# Kubernetes operations

## Support boundary

FileBelt supports Kubernetes 1.34 through 1.36 with Helm 4.2.3. Kubernetes is
the production topology; Compose remains development and integration only.
The chart deploys web, API, I/O, and maintenance Deployments and explicit
administrative Jobs. It does not deploy PostgreSQL, OIDC, Iggy, an egress
gateway, certificate issuer, monitoring stack, controller, StatefulSet, or
persistent volume.

Operators provide:

- PostgreSQL 18 and separate migrator, API, I/O, maintenance, audit-export,
  and recovery login Secrets;
- one standards-compliant OIDC issuer and an in-cluster CONNECT gateway that
  allowlists only that issuer;
- optional Iggy, which never becomes authoritative;
- a pre-existing RWX POSIX claim owned for UID/GID 10001;
- public, backend-server, and distinct API/I/O backend-client certificates in
  existing Secrets;
- a public L4/TCP path to the web ClusterIP Service; and
- optional Prometheus and OTLP endpoints.

The chart always renders default-deny network policy. Configure exact
namespace/pod/IPBlock peers for public ingress, PostgreSQL, DNS, Iggy,
monitoring, and OTLP. Catch-all IPv4 or IPv6 egress is unsupported.

## Preflight

1. Confirm the Kubernetes and Helm versions and enforce the restricted Pod
   Security Standard on the target namespace.
2. Confirm every application image is a lowercase `sha256:` digest and the
   OxiBelt digest is the version accepted by FileBelt's supply-chain policy.
3. Confirm the external PVC advertises RWX and is not owned by this Helm
   release. Provision its root for UID/GID 10001; do not add a chown init Pod.
4. Confirm all Secret names and required keys exist. Record their generation
   values in the release values; the chart never reads or creates them.
5. Confirm NetworkPolicy peer selectors resolve to the intended Pods and ports.
   In particular, the API may reach the OIDC gateway but not the Internet.
6. Confirm the API and I/O server certificates contain their exact Service DNS
   names, and the OxiBelt client certificates contain distinct configured URI
   SANs and `clientAuth` usage.
7. Render with strict lint and server-side dry-run before changing the release.

Keep rendered output and Helm values protected. Secret bytes must not appear in
values, ConfigMaps, command lines, logs, or retained CI artifacts.

## First installation

Use a unique operation UUID for every administrative Job. Enable only one Job
per Helm revision and capture its status/log before disabling it.

1. The database administrator applies the release-matched `roles.sql`, creates
   login roles that inherit exactly one FileBelt group role, and creates the
   existing Kubernetes database URL Secrets.
2. Install the chart with workloads disabled and only the migration Job
   enabled. Wait for a successful, single-completion Job.
3. The database owner applies the release-matched `grants.sql`. FileBelt never
   accepts an owner URL or owner Secret.
4. Disable migration and enable grant verification. It must confirm SQLx
   checksums and the complete reviewed role matrix.
5. Run tenant bootstrap once with the configured exact administrator
   issuer/subject values. The operation is idempotent but is not an upgrade
   hook.
6. Run the storage probe with the configured storage path and PVC mount. Fsync,
   directory fsync, same-filesystem rename, ownership, and no-follow checks must
   all pass.
7. Disable the operation Job and enable workloads. Wait for startup, liveness,
   readiness, endpoints, PDB, and two replicas of web/API/I/O.
8. Exercise login, upload, download, version, direct share, and revoke with two
   users before admitting ordinary traffic.

## Staged upgrade

Never combine a new workload image/config rollout with the migration revision.

1. Back up and record the current chart, five image digests, immutable ConfigMap
   names, Secret generations, database migration ledger, and certificate trust
   overlap.
2. Using current workload values, add only the new release's migration Job.
   Existing Deployment pod templates must remain byte-for-byte unchanged.
3. Wait for migration success. A timeout, checksum error, or lock conflict
   stops the upgrade; preserve the Job and do not apply new workloads.
4. The database owner applies the new `grants.sql`.
5. Replace migration with the grant/schema verification Job. Stop on any
   missing, excessive, or stale privilege.
6. Run the storage probe if storage configuration or the CSI/provider changed.
7. Disable operations and upgrade the chart, image digests, immutable config,
   and explicit Secret generations. Wait for every old ReplicaSet Pod to leave
   endpoints and every replacement to become ready.
8. Repeat the two-user acceptance path and inspect database, outbox, job,
   storage, OIDC, TLS, and error metrics.

The migration ledger is forward-only. Expand-compatible schema changes precede
rollout; contract migrations occur only after the documented compatibility
window.

## Certificate rotation

1. Add the new CA and new client URI SAN to the API/I/O trust configuration
   while retaining the old values. Update Secrets and their chart generations,
   then roll the servers.
2. Put the new client certificates into the two web projections, bump their
   generations, and roll web. Verify both upstreams and direct rejection of the
   old-only/unknown identity.
3. Retain old server/client trust for the rollback window.
4. Remove old identities and roots, bump generations, roll again, and confirm
   TLS-expiry and handshake metrics.

An in-place Secret update without a generation rollout is not a supported
rotation procedure.

## Outages and diagnosis

- PostgreSQL outage: liveness remains healthy, readiness fails, new access
  fails closed, and no payload action proceeds on uncertain generations.
- Iggy outage: commits continue, outbox age grows, and five-second PostgreSQL
  polling remains authoritative. After recovery, verify replay/deduplication.
- OIDC gateway/issuer outage: existing sessions continue within their policy
  bounds; new login and stale metadata fail closed. The API must not bypass the
  gateway.
- Payload failure: I/O and maintenance readiness fail; API and web still have
  no mount. Preserve and quarantine evidence rather than deleting it.
- Worker crash: wait for lease expiry/takeover and verify that stale fencing
  tokens cannot complete work.

Use the private metrics and structured logs described in
[observability.md](observability.md). Do not expose operations ports through the
public L4 path.

## Uninstall

Capture required audit/recovery evidence, disable traffic, drain workloads, and
uninstall only the Helm release's namespaced objects. The existing PVC,
external database, external Iggy, OIDC gateway, certificate Secrets, and
published registry artifacts are never cleanup targets.

For failures during an upgrade, follow
[the Kubernetes rollback runbook](kubernetes-rollback.md). For backups and
restore rehearsals, follow [Kubernetes recovery](kubernetes-recovery.md).
