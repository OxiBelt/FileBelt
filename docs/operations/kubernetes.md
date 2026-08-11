<!-- SPDX-License-Identifier: Apache-2.0 -->

# Kubernetes operations

## Support boundary

FileBelt supports Kubernetes 1.34 through 1.36 with Helm 4.2.3. Kubernetes is
the production topology; Compose remains development and integration only.
The chart deploys web, API, I/O, and maintenance Deployments and explicit
administrative Jobs. MCP broker and runner-controller Deployments are separate
opt-ins and disabled by default; the controller creates bounded one-shot runner
Pods. The chart does not deploy PostgreSQL, OIDC, Iggy, either egress gateway,
certificate issuer, monitoring stack, or persistent volume. The disabled mount
preview renders two gateway StatefulSets only when `mounts.enabled=true`; this
revision is not production-admissible because its copyleft adapter images and
SMB IPC acceptance are incomplete.

Operators provide:

- PostgreSQL 18 and separate migrator, API, I/O, maintenance, audit-export,
  and recovery login Secrets;
- one standards-compliant OIDC issuer and an in-cluster CONNECT gateway that
  allowlists only that issuer;
- optional Iggy, which never becomes authoritative;
- a pre-existing RWX POSIX claim owned for UID/GID 10001;
- public, backend-server, and distinct API/I/O backend-client certificates in
  existing Secrets;
- when MCP is enabled, a dedicated broker database login, MCP vault keyring,
  broker/API/gateway mTLS identities, and an HTTPS egress gateway that enforces
  the configured target trust profile;
- when runners are enabled, controller and runner mTLS identities, a
  digest-pinned runner image, a schema-v1 runner catalog, offline Sigstore
  trusted root/bundles, an exact Kubernetes API NetworkPolicy peer, and a
  pre-created exclusive runner namespace separate from the release namespace;
- before any future mount enablement, external Headscale `0.29.3`, API token and
  CA, VFS/Headscale database logins, a distinct mount-vault keyring,
  `mount-storage` purpose private/public material, VFS/API/I/O
  mTLS identities, gateway tailnet auth, node `/dev/net/tun`, and one distinct
  operator-owned RWO tailstate claim per gateway;
- a public L4/TCP path to the web ClusterIP Service; and
- optional Prometheus and OTLP endpoints.

The chart always renders default-deny network policy. Configure exact
namespace/pod/IPBlock peers for public ingress, PostgreSQL, DNS, Iggy,
monitoring, and OTLP. Catch-all IPv4 or IPv6 egress is unsupported.

## Preflight

1. Confirm the Kubernetes and Helm versions and enforce the restricted Pod
   Security Standard on the target namespace. When runners are enabled, create
   `mcp.runners.namespace` separately, enforce the same standard there, reserve
   it for this FileBelt release, and create the runner broker/gateway TLS
   Secrets in that namespace.
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
7. Confirm `filebelt.toml` uses format 7. If MCP is enabled, validate the
   broker/vault/gateway/trust-profile fields; if runners are enabled, also
   validate controller mTLS, catalog/root/bundles, runner digest, namespace,
   and quotas. The `[mcp.runners] namespace` must equal the Helm
   `mcp.runners.namespace` and must not equal the release namespace.
   Keep `mounts.enabled=false`; a render that enables it is preview evidence,
   not authorization to expose SMB or FTPS.
8. While workloads remain quiesced, run the chart's `keys-audit` operation with
   all configured purpose public keysets projected. Require successful proof
   that every current generation is present and no public key bytes occur in
   two purposes; retain the Job output with the candidate release evidence.
9. Render with strict lint and server-side dry-run before changing the release.
   For runners, inspect the namespaced Role and prove it cannot read or mutate
   resources outside the runner namespace.

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
9. In a later revision, optionally enable the MCP broker without runners.
   Exercise personal registration, transport test, discovery, exact capability
   review, intent-bound approval, version-pinned attachment, activity, revoke,
   OAuth expiry/replay, and cross-user denial.
10. Enable runners only after the broker path is healthy. Verify offline
    catalog admission, controller leadership, one-shot creation/cancellation,
    bootstrap Secret cleanup, cross-namespace RBAC denial in the core
    namespace, no runner DNS egress, per-principal/tenant quotas, and absence
    of secrets in the untrusted server container.
11. Do not enable mount gateways in this revision. Retain the disabled render,
    migration/grant verification, and VFS/Headscale image evidence so a later
    qualified adapter release can stage activation without rewriting schema.

## Staged upgrade

Never combine a new workload image/config rollout with the migration revision.

1. Back up and record the current chart, selected workload image digests,
   immutable ConfigMap names, Secret and MCP KEK generations, database migration
   ledger, runner catalog/root/bundle identities, and certificate trust overlap.
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
   storage, OIDC, TLS, and error metrics. When enabled, repeat the MCP
   approval/data-grant/revocation path before enabling runners in a separate
   revision.

### Descendant-share security cutover

For the descendant-share migration, the migration itself deliberately leaves
direct-share and MCP data-grant admission blocked. After migration and grant
verification, roll compatible API images before running these recovery-credential
Jobs, one per Helm revision. Generate one operation UUID for the tenant cutover
and reuse it for every repair retry, verification, and activation:

1. Render `security-descendant-shares-status` with only `operationId` to record
   the tenant's gate/run state.
2. Render `security-descendant-shares-repair` with `operationId`, exact
   `tenantSlugConfirmation`, and the live tenant-admin `actorPrincipalId`.
   Repeat the same operation UUID until its 1,000-row batches report complete.
3. Render `security-descendant-shares-verify` with the same three values; stop
   on any residual target, receipt/checkpoint, generation, or audit mismatch.
4. After compatible workload rollout and acceptance, render
   `security-descendant-shares-activate` with the verified run UUID, exact
   tenant slug, and tenant-admin actor. Only this action reopens the tenant.

These Jobs mount only the recovery database Secret, have no payload claim or
service-account token, and may reach only DNS/PostgreSQL. Do not use freeform
operation arguments, a database-owner login, a direct SQL update, or an old API
image as a substitute for verification or activation.

For the additive mount migrations, keep mount workloads disabled while the DBA
applies VFS and Headscale grants. Provision the purpose-tagged `mount-storage`
public keyset in I/O before any VFS signer could start. Rollback leaves
migrations `000004` and `000005`, the mount KEK, and every admitted retiring
public key in place; never drop the schemas or remove key material referenced
by recovery evidence.

The migration ledger is forward-only. Expand-compatible schema changes precede
rollout; contract migrations occur only after the documented compatibility
window.

### Phase 8 staged activation

1. Leave `media.enabled`, `mounts.nfs.enabled`, and
   `collaboration.webtransport.enabled` false. Apply migrations 000007 through
   000009 and the reviewed grants.
2. Roll every long-running and administrative role to a configuration-version-6
   compatible image and verify its fresh compatibility advertisement.
3. Quiesce writers and take the coordinated PostgreSQL/payload checkpoint.
4. Run `filebeltctl phase8 activate` once. Retain its audit identifier and
   compatibility inventory with the change evidence.
5. Qualify and enable CPU media, NFS, and WebTransport separately. NFS requires
   the external KDC/keytab, handle keyset, `fs_ng` recovery claim, TCP 2049
   client policy, and single-active fencing. WebTransport requires the
   operator-projected TLS identity and UDP policies. VAAPI remains disabled unless experimental
   use is explicitly accepted.

To roll back, disable new admissions, run `filebeltctl phase8 deactivate`,
advance NFS/job/collaboration fences, drain clients, and restore the previous
compatible image digests. Preserve migrations, current and previous handle and
capability public keys, NFS recovery/conflict rows, and media reconciliation
metadata. A pre-Phase-8 binary requires restoration of the checkpoint into
fresh database and payload targets; never run a down migration in place.

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

Rotate broker, controller, runner, and MCP-gateway certificates by the same
overlap-first procedure, but one connection edge at a time. Rotate the MCP
vault KEK independently: add the new generation, make it current, rewrap or
replace credentials under controlled operation, verify the recovery-v2 key
inventory, and remove an old generation only after no envelope or checkpoint
requires it.

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
- MCP gateway outage: remote and runner-server network operations fail closed;
  core file operations remain available and the broker must not connect
  directly to the target.
- MCP broker outage: MCP readiness and invocations fail, while registrations and
  policy remain in PostgreSQL. Do not bypass the broker or expose its listener.
- Controller outage: existing one-shot Pods remain deadline-bounded; no new
  runner is admitted without exactly one leader. Restore leadership and verify
  orphan Pod/Secret reconciliation before resuming runner traffic.
- Headscale outage: synchronization makes no partial device update; keep mount
  admission disabled and do not extend device freshness or derive authority
  from cached tailnet state.
- VFS or gateway incident: disable gateway admission, advance the affected
  gateway epoch, revoke sessions/handles/locks in PostgreSQL, and preserve
  redacted protocol/request evidence. Never mount payload storage into VFS or
  an adapter as a recovery shortcut.

Use the private metrics and structured logs described in
[observability.md](observability.md). Do not expose operations ports through the
public L4 path.

## MCP broker and runner incidents

On `FileBeltMcpRevocationLag`, stop MCP admission and confirm the authoritative
registration, principal, approval, grant, and invocation generations in
PostgreSQL. Cancel active invocations and disable the affected registration or
service. Do not wait for Iggy and do not extend an approval to compensate for
lag.

On invalid controller leadership or runner reconciliation failure, set
`mcp.runners.enabled=false` in a controlled chart revision, preserve controller
logs and catalog identities, and enumerate only runner-labeled Pods and Secrets
in the configured namespace. Delete a resource only after its invocation ID and
FileBelt labels match authoritative state. Keep the broker enabled only for
Streamable HTTP if that path remains independently healthy.

On quarantine growth, leave registrations disabled, preserve redacted
protocol/error reason codes, and compare the exact capability snapshot,
protocol version, endpoint trust profile, and gateway decision. Never show or
export credential plaintext or the remote response body as incident evidence.

For gateway or catalog compromise, disable runners before the broker, revoke
the affected registration/service/certificate identities, rotate bootstrap and
gateway credentials, and replace the catalog/root/bundle or gateway policy in a
new immutable configuration revision. A corrected image uses a new digest;
never move a catalog digest or release tag.

## Uninstall

Capture required audit/recovery evidence, disable traffic, drain workloads, and
uninstall only the Helm release's namespaced objects. Confirm the controller has
reconciled one-shot runner Pods and bootstrap Secrets first. The existing PVC,
external database, external Iggy, OIDC/MCP gateways, operator Secrets, runner
catalog inputs, gateway tailstate claims, external Headscale, and published
registry artifacts are never cleanup targets.

For failures during an upgrade, follow
[the Kubernetes rollback runbook](kubernetes-rollback.md). For backups and
restore rehearsals, follow [Kubernetes recovery](kubernetes-recovery.md).
For v7, create independent, immutable Secret objects for each purpose-private
and purpose-public keyset. Record every exact Secret generation before rollout;
the chart rolls only workloads that project that material. The API owns enabled
API pairs, I/O receives only API-storage plus enabled storage-purpose public
sets, and no runtime media workload receives media material.
