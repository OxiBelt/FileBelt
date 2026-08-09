<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt Helm chart

This chart deploys the supported Phase 6 FileBelt application boundary on
Kubernetes `1.34` through `1.36`. It deliberately does not install PostgreSQL,
Iggy, an OIDC provider, an OIDC egress gateway, an ingress controller, storage,
cert-manager, an MCP egress gateway, or a monitoring stack. Install it in a
dedicated namespace: its namespace-wide default-deny policy intentionally
isolates every core Pod in that namespace. Curated runners additionally use a
separate, pre-created namespace reserved exclusively for one FileBelt release.

The default chart renders four Deployments:

- web/OxiBelt, API, and I/O each default to two replicas;
- maintenance defaults to one replica;
- `deployment.quiesced=true` retains the workload definitions but sets every
  replica count to zero for an operator-controlled recovery window.

`mcp.enabled=true` adds two broker replicas. The separate
`mcp.runners.enabled=true` opt-in adds two Lease-elected controller replicas,
cross-namespace Pod/Secret/Lease RBAC confined to `mcp.runners.namespace`, and
the service account used by per-invocation runner Pods. Runner Pods are created
dynamically rather than as a Deployment. They use a digest-pinned trusted relay
sidecar, a verified catalog server image, no service-account token, no payload
mount, and a runner-namespace default-deny policy.

`mounts.enabled=true` renders the disabled-preview VFS and Headscale-sync
Deployments plus SMB and explicit-FTPS gateway StatefulSets. Each gateway has a
tailscaled sidecar, its own operator-provided RWO tailstate claim, kernel
networking, and an exact default-deny policy path. VFS and Headscale sync do not
receive tailscaled, TUN, tailstate, or payload mounts. Do not enable this
preview in production from this revision: the copyleft adapter images are not
part of the Apache release and the Samba authentication/session IPC path is
still fail-closed.

It never renders an HPA, Secret, PVC, dependency fixture, media
controller, cluster-scoped RBAC, ClusterRole, or ClusterRoleBinding. The API,
broker, controller, and runners have no payload mount. Only I/O, maintenance,
and explicitly selected storage/recovery Jobs mount the existing payload
claim.

Application resource names are fixed under the `filebelt-*` prefix. This is
intentional: FileBelt supports one tenant/deployment in its dedicated namespace
and the generated edge configuration can use stable Service DNS names.

## Prerequisites

- Kubernetes `1.34`–`1.36` with an enforcing NetworkPolicy implementation.
- External PostgreSQL 18 and, if enabled, Apache Iggy.
- A single HTTPS OIDC issuer reachable only through an operator-managed
  in-cluster CONNECT gateway. The gateway must restrict the configured issuer
  host and port and preserve end-to-end issuer TLS validation.
- A pre-existing RWX POSIX claim, already owned by numeric UID/GID `10001`,
  that passes FileBelt's fsync, directory-fsync, no-follow, and same-filesystem
  atomic-rename probe. The chart never changes or deletes this claim.
- An OxiBelt release with per-upstream client certificate support. Do not
  activate the default backend mTLS configuration against an older image.
- Existing Secrets containing the exact keys listed below. The chart projects
  only named keys with file mode `0440` and never reads or renders their data.
- When curated runners are enabled, a pre-created
  `mcp.runners.namespace` different from the release namespace, reserved for
  this release and labeled for the restricted Pod Security Standard. Provision
  the runner broker/gateway client TLS Secrets in that namespace; all other
  chart inputs remain in the release namespace.

Every production image is selected by a lower-case `sha256:` digest. The
all-zero values are static-validation sentinels, not installable artifacts;
replace all eleven deployable Apache workload digests before live installation.
The adapter all-zero digests are additionally non-published sentinels and
cannot be made production-ready by changing only a value.

## Configuration and credentials

`configuration.filebelt` and `configuration.oxibelt` become separate
content-addressed, immutable ConfigMaps. Any content change produces a new
name and a workload checksum. Never put a password, token, private key, or
certificate in either string: use its absolute projected path.

The default OxiBelt configuration uses exclusive trust for each backend. Its
all-zero `trusted_ca_sha256` entries are static-validation sentinels; replace
each with the lowercase SHA-256 of the corresponding projected
`server-ca.crt` before installation.

The default `filebelt.toml` is version 6 in Kubernetes mode and configures the
private operations listener on `9090`, backend TLS 1.3 mTLS, structured JSON
logs, Prometheus, and the OIDC egress proxy. Replace the example origin,
issuer, tenant, administrator, backend UUID, certificate identities, and edge
host together. The API client URI SAN allowlist contains the web identity. The
I/O allowlist contains the web identity and the exact MCP broker attachment
identity; it may contain one additional retiring identity only during
certificate rotation.

MCP remains disabled in both values and application configuration by default.
Enabling it requires an HTTPS broker URL, projected API-to-broker mTLS files,
database and vault Secrets, an exact egress-gateway peer, an HTTPS internal I/O
URL, projected broker-to-I/O mTLS files, and matching backend TLS identities.
The required `[mcp.attachments]` values use
`https://filebelt-worker-io:8081/` and the three files projected below
`/run/secrets/mcp-backend-tls`; chart validation rejects an enabled broker when
that narrow path is absent. Enabling curated runners additionally requires an
operator-owned catalog ConfigMap, a Sigstore trusted-root ConfigMap, bundle
ConfigMap, exact Kubernetes API NetworkPolicy peers, runner TLS Secrets, and a
runner image string matching the chart's digest. The controller performs
offline certificate, transparency-log, issuer, identity, and artifact-digest
verification before creating any Pod.
The `[mcp.runners] namespace` must exactly match the chart
`mcp.runners.namespace`; chart validation rejects the release namespace. The
controller stays in the release namespace, while its Role, leadership Lease,
runner ServiceAccount, Pods, and bootstrap Secrets exist only in the dedicated
runner namespace.
The projected trust root must contain exactly one bounded Fulcio CA, Rekor key,
and CT key and no TSA authority. Each bundle must contain one Rekor v1 entry
with an inclusion proof and promise; its authenticated integrated time must be
inside all three explicit validity windows. Unbounded, overlapping, or
partially rotated trust material is rejected, so replace the trusted-root and
bundle projections together.
The packaged
[`examples/mcp-runner-catalog.schema.json`](examples/mcp-runner-catalog.schema.json)
is the operator-facing catalog shape; catalog JSON, trusted root, and bundles
remain operator-owned inputs and are never synthesized by the chart.

Secret value objects have `name`, key fields, and a non-secret `generation`.
The Secret must already exist. Increment only the affected generation when its
contents change; the relevant Deployment then performs a controlled rollout.

| Value | Projected keys | Consumer |
|---|---|---|
| `apiDatabase` | `database-url` | API |
| `ioDatabase` | `database-url` | I/O |
| `maintenanceDatabase` | `database-url` | Maintenance and scrub |
| `migratorDatabase` | `database-url` | Migration, grant verification, bootstrap |
| `auditDatabase` | `database-url` | Audit export |
| `recoveryDatabase` | `database-url` | Recovery operations |
| `oidcClient` and `oidcCa` | `client-secret` and `ca.crt` | API |
| capability and digest values | one configured key each | API or I/O as required |
| `publicTls` | `tls.crt`, `tls.key` | Web |
| API/I/O server TLS | `tls.crt`, `tls.key`, `client-ca.crt` | Corresponding backend |
| API/I/O client TLS | `tls.crt`, `tls.key`, `server-ca.crt` | Web |
| `mcpDatabase` and `mcpVaultKeyring` | `database-url` and `keyring.json` | MCP broker |
| broker server and API MCP client TLS | certificate, key, and exact CA keys | Broker and API |
| MCP gateway and backend client TLS | certificate, key, and `server-ca.crt` | Broker |
| controller server/client TLS | certificate, key, and exact CA keys | Controller and broker |
| runner broker/gateway TLS | `tls.crt`, `tls.key`, `ca.crt` | Trusted relay sidecar only; create in `mcp.runners.namespace` |
| `vfsDatabase` and `headscaleSyncDatabase` | `database-url` | VFS and Headscale synchronization |
| `mountVaultKeyring` | `keyring.json` | VFS verifier vault only |
| `mountCapabilityPrivateKey` | `private-key` | VFS generation-3 `fbcap2` signer only |
| VFS server, management, and I/O client TLS | certificate, key, and exact CA keys | Gateways, API, VFS, and I/O |
| `headscaleApiToken` and `headscaleServerCa` | `token` and `ca.crt` | Headscale synchronization only |

Secret names are not rollouts by themselves. Generations make an in-place
Secret rotation explicit and auditable. Rotate backend certificates by first
adding the new exact client URI SAN to the server allowlist, rotating the web
client Secret and generation, verifying convergence, and then removing the old
identity in a second immutable configuration revision.
When MCP is enabled, changing `secrets.apiMcpClientTls.generation` is included
in the API Pod-template checksum and therefore rolls the API client identity.

## Networking and exposure

The web Service is ClusterIP on TCP `8443`. Expose it with operator-owned L4
TCP infrastructure so OxiBelt remains the public TLS endpoint; do not terminate
or reinterpret FileBelt HTTP routes in an ingress resource. Set
`networkPolicy.publicIngress.from` to that infrastructure's exact namespace
and Pod labels.

The chart permits only these application paths:

- ingress peers to web; web to API and I/O;
- monitoring peers to private metrics ports;
- API to DNS, PostgreSQL, the OIDC gateway, and optional OTLP;
- I/O to DNS, PostgreSQL, and optional OTLP;
- maintenance to DNS, PostgreSQL, optional Iggy, and optional OTLP;
- when enabled, API to broker; broker to PostgreSQL, API, I/O, the exact MCP
  gateway, and controller; controller to the exact Kubernetes API peer; and
  runner relay sidecars to broker and the exact MCP gateway, with no DNS
  egress from runner Pods;
- an administrative Job to DNS and PostgreSQL.
- when mount preview is rendered, API to VFS management; gateways to VFS;
  VFS to PostgreSQL and I/O; I/O ingress from VFS; Headscale sync to PostgreSQL
  and the exact Headscale peer; and exact tailnet ingress to gateway ports.

`networkPolicy` peers accept Kubernetes namespace/Pod selectors or bounded
`ipBlock` CIDRs. The chart rejects `0.0.0.0/0` and `::/0`. Set every external
peer and port explicitly; enabling Iggy or OTLP requires at least one peer.
DNS defaults assume CoreDNS with `k8s-app=kube-dns`; override this for
NodeLocal DNS or another cluster design. The trusted controller resolves the
configured broker and gateway names before Pod creation and passes only a
bounded list of numeric socket addresses to the relay. The untrusted server
therefore cannot use cluster DNS, while TLS continues to authenticate the
separately configured server names.

## Installation and staged database changes

Run administrative work as explicit, separately rendered Jobs. Jobs are not
Helm hooks: they have one completion, no retry, no automatic TTL deletion, a
six-hour deadline, a required UUID, deterministic naming, and retained logs.
Only one operation can exist in a release. `operation.type=none` is the normal
workload value.

For a fresh installation:

1. Apply the release-matched `roles.sql` as the database owner and create each
   login outside this chart.
2. Install with `deployment.quiesced=true` and run `migrate`.
3. Apply release-matched `grants.sql` as the database owner.
4. Run `verify-grants`, then the idempotent `bootstrap` operation.
5. Run `storage-probe` and retain its logs.
6. Install a normal revision with `operation.type=none` and
   `deployment.quiesced=false`.

For an upgrade, run `migrate` without changing the existing workload images or
configuration, apply `grants.sql`, and run `verify-grants`. Only after both
steps pass should a separate release roll out new image/config digests. The
chart gives no database-owner credential to a Job, never runs migrations from
an API Pod, and has no down-migration path.

Example operation values:

```yaml
deployment:
  quiesced: true
operation:
  type: migrate
  operationId: 123e4567-e89b-42d3-a456-426614174000
  tenantSlugConfirmation: ""
  payloadId: ""
  args: []
  checkpoint:
    secretName: ""
    key: checkpoint.json
```

Supported types are `migrate`, `bootstrap`, `verify-grants`, `storage-probe`,
`storage-scrub-start`, `storage-scrub-status`, `storage-scrub-verify`,
`recovery-checkpoint`, `recovery-verify`, and `audit-export`. Scrub start is a
full-tenant operation and requires the exact tenant slug in
`tenantSlugConfirmation`. For a targeted start/status/verify, set `payloadId`
and leave the tenant confirmation empty; the chart renders the two modes as
mutually exclusive. `args` appends bounded arguments without invoking a shell,
for example an audit cursor or export limit.

Recovery checkpoint and verification require quiesced workloads. Capture the
checkpoint Job's stdout. To verify it, store that sensitive operational JSON in
an operator-owned Secret and set `operation.checkpoint.secretName`; the chart
projects only its configured key at `/run/input/checkpoint.json`. A recovery is
accepted only after restoring into fresh targets, checkpoint verification, a
full BLAKE3 scrub, and application authorization acceptance. The chart makes
no online-backup, PITR, HA, RPO, or RTO claim.

## Availability, monitoring, and validation

Web, API, I/O, broker, and controller use rolling updates with
`maxUnavailable: 0`, `maxSurge: 1`,
`minAvailable: 1` PDBs, and preferred hostname/zone spreading. Maintenance is
single-replica and has no PDB or leader-election claim. Controller readiness is
held false until the runner-namespace Lease is owned; only the leader accepts
runner create/delete requests, and create/cancel mutations are serialized so a
late create cannot survive cancellation. Resource
requests and limits in `values.yaml` are tested small-system baselines, not
capacity guarantees.

Each role has a private metrics Service. `ServiceMonitor` and `PrometheusRule`
are disabled by default and fail closed if enabled without their CRDs. The
rules are portable starting points; validate metric availability and tune them
against observed capacity before paging. Kubernetes health probes are separate
from mTLS data listeners and expose no dependency detail.

Validate locally with the pinned Helm release:

```sh
tests/scripts/check-helm-chart.sh
```

The check lints and renders Kubernetes `1.34`, `1.35`, and `1.36`, exercises
negative schema/helper cases, proves core and MCP workload/RBAC/mount
boundaries, renders the disabled mount preview and rejects unsafe TUN/tailstate
or peer combinations, validates
quiescing and administrative Jobs, and rejects unexpected resource kinds. A
connected test cluster must additionally run server-side dry-run under the
restricted Pod Security Standard and the Kind/Minikube lifecycle, NetworkPolicy,
outage, rollout, and recovery suites before production use.
