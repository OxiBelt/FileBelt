<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0012: Kubernetes and operational maturity

- Status: Accepted
- Date: 2026-08-07
- Owners: `@PiQuark6046`
- Reviewers: none
- Supersedes: the Phase 3 deferrals in ADR-0009 and ADR-0011
- Affected license regions: Apache-2.0 and the reviewed OxiBelt runtime input

## Context

Phase 2 proved the FileBelt control, payload, edge, and recovery contracts in a
Docker integration topology. The Helm chart remained a non-deploying image
schema, backend HTTP relied on that isolated Docker network, recovery was a
manual procedure, and release workflows deliberately lacked write permission.
Kubernetes production support must preserve the API/payload and
PostgreSQL/Iggy boundaries while adding independently tested workload,
identity, network, recovery, observability, and publication contracts.

## Decision

FileBelt supports Kubernetes 1.34 through 1.36 with Helm 4.2.3. Production
installs use four replaceable Deployments: OxiBelt web, API, I/O worker, and
maintenance worker. The tools image runs bounded administrative Jobs. Static
Helm resources are sufficient, so FileBelt deploys no controller or
StatefulSet. The media-controller and MCP-broker remain probe-only and are not
published as Phase 3 services.

PostgreSQL 18, OIDC, optional Iggy, public L4 exposure, monitoring, certificate
issuance, and the OIDC egress gateway are external operator dependencies. The
chart creates no dependency StatefulSet, persistent volume, or Secret. It
requires an existing RWX POSIX claim that passes the FileBelt fsync,
same-filesystem rename, ownership, and no-follow probe. Only I/O, maintenance,
and explicit storage recovery Jobs mount it; API and web never do.

Web, API, and I/O default to two replicas. Maintenance defaults to one. The
three replicated roles have a PodDisruptionBudget with `minAvailable: 1`.
Every workload has explicit resources, bounded writable storage, immutable
image/config identity, graceful admission drain, topology spreading, and the
restricted non-root security context. No workload receives a Kubernetes API
token or RBAC permission. Horizontal autoscaling is deferred until bounded
queue, database, and storage-capacity signals prove that it is safe.

The namespace is ingress/egress default-deny. Policies admit only the public
L4 peer to OxiBelt, OxiBelt to the two mTLS backends, role-specific PostgreSQL
and optional Iggy paths, DNS, configured monitoring/OTLP peers, and API access
to an operator-managed in-cluster OIDC CONNECT gateway. No FileBelt Pod has
general Internet egress. Calico and Cilium tests qualify the standard
NetworkPolicy graph; Cilium-specific policy is not required in production.

Backend API and I/O traffic uses TLS 1.3 mutual authentication. OxiBelt has a
separate client certificate for each upstream. FileBelt validates the operator
CA, client-authentication purpose, and an exact configured URI SAN; API and I/O
identities are distinct and may overlap with one retiring identity during
rotation. OxiBelt validates each service DNS SAN. Certificates come from
existing Secrets and rotate through an explicit chart generation and Pod
rollout. They do not identify a FileBelt user. Health and metrics use a
separate low-information internal listener because kubelet does not present a
client certificate.

Runtime configuration advances to `filebelt.toml` version 2 and version 1 is
rejected. Kubernetes mode requires backend mTLS, the OIDC gateway, JSON logs,
and Prometheus metrics. Development mode may retain plaintext Compose
backends. Configuration changes remain restart-only and use content-addressed
immutable ConfigMaps; external Secret changes require explicit generation
updates.

Database migration, owner grants, verification, tenant bootstrap, storage
probe, audit export, scrub, and recovery are explicit non-hook Jobs. A release
upgrade first runs SQLx migration under the migrator role while old workloads
remain pinned, then pauses for the database owner to apply the reviewed
`grants.sql`, runs the grant/schema verifier, and only then rolls workloads.
The chart never receives an owner credential. Migrations remain forward-only;
rollback never applies a down migration.

Supported recovery is a coordinated quiesced PostgreSQL and payload snapshot.
The operator drains all FileBelt writers, records a bounded versioned recovery
checkpoint, snapshots both external planes, and restores into a fresh
database, namespace, and PVC. Migration, grant verification, reconciliation,
checkpoint comparison, full physical BLAKE3 scrub, and two-user authorization
acceptance are required before traffic returns. Online backup, PITR, HA, and
numeric RPO/RTO promises remain out of scope.

Each native role emits structured redacted JSON logs, bounded-label Prometheus
metrics, and optional OTLP/HTTP traces. Portable alerts and dashboards ship as
assets. Prometheus Operator resources are optional and disabled by default.
Audit export is a pull-based, cursor-bounded NDJSON CLI operation using a
dedicated read-only database role; FileBelt does not push audit data to an
Internet sink.

Signed SemVer tags activate a tag-only release workflow. It promotes already
validated API, I/O, maintenance, tools, and web archives to GHCR, publishes the
Helm chart as `oci://ghcr.io/oxibelt/charts/filebelt`, attaches GitHub artifact
attestations, reads every digest back, and creates a checksummed release. The
workflow publishes no mutable alias and does not publish the media or MCP
probe images. Write permission exists only on the promotion job and never on a
pull-request or manual publication path.

## Alternatives considered

Bundled PostgreSQL/Iggy subcharts were rejected because production state and
availability belong to external operators. An RWO payload claim was rejected
because independent I/O and maintenance Pods require shared POSIX access.
Co-locating those roles would weaken fault and privilege isolation. A
FileBelt controller was rejected because the desired resources and staged
operations are static. A service mesh or cert-manager requirement was rejected
in favor of native backend identity and operator-owned Secrets. FQDN egress
policy was rejected as a portable NetworkPolicy contract; the explicit OIDC
gateway provides the stable policy target. An owner-credential Helm hook was
rejected because it joins schema and database-owner authority and cannot pause
safely for review. Online backup was rejected until provider and RPO/RTO
contracts are selected.

## Consequences and verification

Kubernetes is the only supported production topology; Compose remains
development/integration. Cluster administrators, nodes, the external database
operator, the storage provider, and certificate issuer remain powerful trusted
parties. A compromised web Pod possesses only the two bounded backend client
identities; it receives no database or payload access. A compromised API still
has no payload mount, and worker SQL roles remain unable to grant namespace
authority.

Pull requests run chart, migration, current-Kind lifecycle, and Calico smoke
coverage. Main, scheduled, and release gates run Kubernetes 1.34-1.36,
Calico/Cilium isolation, immutable rollout/rollback, certificate rotation,
worker crash/fencing, PostgreSQL and Iggy outage, and fresh-target recovery.
Production images must prove that test-only fault controls are absent.

## Rollout and rollback

Admit and publish the OxiBelt client-certificate release before enabling
FileBelt backend mTLS. For a FileBelt release, apply role administration,
migration, reviewed grants, verification, bootstrap/storage probe when needed,
and finally the workload rollout as separate Helm revisions. A failed stage
stops before the next stage and retains Job evidence.

Rollback restores the previous chart, image digests, immutable configuration,
and overlapping certificate trust while retaining the external PVC and the
forward-compatible schema. After an irreversible contract migration, restore
the coordinated backup into fresh targets and migrate forward. Never delete
the operator PVC, apply a down migration, or automatically delete a published
artifact as rollback.

## Open questions

None.
