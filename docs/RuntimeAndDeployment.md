<!-- SPDX-License-Identifier: Apache-2.0 -->

# Runtime and Deployment

This specification defines FileBelt's current package, image, release, and
production-deployment contracts. Kubernetes is the supported production
topology. Docker Compose remains a development and integration topology.

Storage and migration guarantees are defined in
[Storage and Durability](StorageAndDurability.md). License composition and
dependency admission are defined in [License Map](LicenseMap.md) and
[Supply-Chain Policy](SupplyChain.md).

## Repository and naming contract

FileBelt is one public mixed-license monorepo. Root Cargo and pnpm workspaces
contain Apache-2.0 packages only. Copyleft adapters have separate build roots,
lockfiles, processes, images, notices, and corresponding-source evidence. An
adapter may consume a generic Apache protocol contract; Apache packages may
not import, link, or path-depend on adapter implementation code. A container
or Pod boundary alone is not license analysis.

Names are stable and role-oriented:

- directories and Cargo packages use lowercase kebab-case;
- Cargo packages and binaries use `filebelt-*`, with Rust crate identifiers
  using underscores where the language requires them;
- private TypeScript packages use `@filebelt/*`;
- Protobuf packages use `filebelt.<domain>.v1`;
- database and configuration keys use `snake_case`;
- environment variables use the `FILEBELT_` prefix;
- release images use `ghcr.io/oxibelt/filebelt-<role>`; and
- deterministic test resources begin with `filebelt-<suite>-` and include a
  unique run identifier.

First-party packages use coordinated SemVer, currently beginning at `0.1.0`.
They are not published to crates.io or npm. The integrated `source` binary is a
development composition and is never a production image.

## Image and process roles

The current build matrix contains ten Apache-region images on
`linux/amd64`, `linux/arm64`, and `linux/riscv64`:

| Role | Current status and authority |
| --- | --- |
| `filebelt-api` | Active and publishable. Resolves OIDC/sessions, authorizes metadata operations, and issues capabilities. Has API-role PostgreSQL access and signing/digest secrets, but no payload mount. |
| `filebelt-worker-io` | Active and publishable. Performs capability-limited upload, finalization, and Range download using a narrow PostgreSQL role, verification keys, and one payload mount. |
| `filebelt-worker-maintenance` | Active and publishable. Leases durable jobs and reconciles, deletes, and scrubs through a narrow PostgreSQL role and one payload mount. |
| `filebelt-tools` | Active and publishable. Runs bounded, explicit configuration, migration, bootstrap, key, audit, job, storage, and recovery commands with command-specific credentials and mounts. |
| `filebelt-web` | Active and publishable. Combines static SPA/Markdown assets and reviewed route configuration with the pinned OxiBelt TLS edge. Has TLS material and isolated backend access, but no PostgreSQL or payload mount. |
| `filebelt-collaboration` | Dedicated Rust collaboration role for Yrs `0.27.3`. When enabled, admits authenticated Markdown editors, persists fenced CRDT manifests through scoped I/O capabilities, and has narrow PostgreSQL/I/O access but no payload mount, browser session authority, or general Internet egress. |
| `filebelt-media-controller` | Probe-only. Built and validated for identity but not deployed or promoted as a service. |
| `filebelt-mcp-broker` | Active, publishable, and disabled by default. Revalidates MCP policy, owns encrypted MCP-vault access, mediates Streamable HTTP and runner relays, and has no payload mount or direct Internet route. |
| `filebelt-controller` | Active, publishable, and enabled only with stdio runners. Verifies the offline runner catalog, leads reconciliation in the exclusive runner namespace, and creates/deletes only bounded runner Pods, bootstrap Secrets, and its Lease there. |
| `filebelt-mcp-runner` | Active and publishable. Supplies the trusted relay/shim injected into one-shot curated server Pods; it receives no FileBelt database, payload, session, or vault credential. |

Reserved adapter roles are `filebelt-smb-gateway`,
`filebelt-ftp-ftps-gateway`, `filebelt-onlyoffice-adapter`, future
`filebelt-nfs-gateway`, and `filebelt-transcoder`. Each has an independently
truthful platform and license contract. Transcode implementation remains
prohibited until its exact FFmpeg composition has been reviewed and the
license map, supply-chain evidence, and runtime contract are updated together.

Every FileBelt process runs as numeric UID/GID `10001:10001` with a read-only
root filesystem, no-new-privileges, dropped Linux capabilities, bounded
writable temporary storage, and only role-specific ports, networks, secrets,
and mounts. Liveness reports process health separately from dependency and
storage readiness.

The controller is the sole ServiceAccount-token exception. It runs in the core
namespace, but its Role is bound only in the runner namespace and permits
`get/list/create/delete` on Pods, `get/create/delete` on Secrets, and
`get/create/update` on coordination Leases. Broker and runner
ServiceAccounts have token automount disabled. Runner Pods also disable service
links, host networking, host PID/process sharing, privilege escalation, and
restart; the 130-second active deadline and ten-second termination grace bound
their lifetime.

| Listener | Port | Exposure |
| --- | ---: | --- |
| API | 8080 | OxiBelt and internal broker only |
| I/O | 8081 | OxiBelt and internal broker only |
| Collaboration | 8085 | OxiBelt only; WebSocket is the sole Phase 5 browser transport |
| MCP broker request API | 8082 | API only, mTLS in Kubernetes |
| Runner controller | 8083 | MCP broker only, mTLS |
| MCP runner relay | 8084 | one-shot runner relay only, mTLS |
| Native operations | 9090 | kubelet/monitoring only |
| Runner local egress proxy | 7777 | loopback within the one-shot Pod only |

The Rust final stages contain the role executable and required identity,
license, and notice files without a shell or package manager. The web image is
derived from the exact OxiBelt input recorded in the image plan and copies only
FileBelt assets, reviewed configuration, identity metadata, licenses, and
notices. The current pin is OxiBelt `0.7.1-beta.2` at
`sha256:e8556a0103feff47bf6135062e70e980e000176598fd438959ea55d99c844030`.
Changing that prerelease input requires a focused source, route, mTLS,
architecture, vulnerability, license, and notice review.

## Platform and artifact evidence

AMD64 and ARM64 run native behavior suites. RISC-V cross-compiles with the
digest-pinned toolchain in `supply-chain/tooling.toml` and runs bounded
rootless-QEMU configuration, crypto-provider, unavailable-database, identity,
health, non-root, and shutdown checks without host `binfmt_misc` registration.
The official Iggy helper is not substituted on RISC-V; polling fallback is
tested instead.

Stable and prerelease source tags are signed annotated Git tags whose text is
the exact SemVer without a `v` prefix. Development archives use the immutable
form `0.1.0-build.<sha12>`. Image identity records the version, revision,
source ref, dirty state, build kind, and role. Mutable `latest`, major, minor,
branch, and platform aliases are not published.

Release validation imports only the tracked public keys into an empty temporary
keyring, requires exactly one valid signature certified by an allowlisted
primary fingerprint, and requires the annotated tag to peel to the checked-out
revision. Signer rotation is an explicit release-authority change; release
validation never discovers trust through a live network lookup.

Every platform archive has a checksum, machine-readable artifact contract,
build metadata, normalized CycloneDX SBOM, and Trivy `0.73.0` vulnerability
report. Rust SBOMs include the selected Cargo application, linked Rust standard
library and musl runtime, and excluded build-tool evidence. Missing or partial
inventory fails closed even when the static filesystem has no package-manager
records.

An unexcepted `HIGH` or `CRITICAL` finding blocks validation. An exception must
match target, advisory, package, installed version, role, and platform, include
a rationale, and expire no more than 90 days after admission. Missing,
ambiguous, wildcarded, expired, malformed, or version-mismatched evidence fails
closed.

Normalized rebuild comparison covers filesystem paths and contents, modes,
numeric ownership, selected image configuration and labels, embedded identity,
and SBOM subjects/components. It ignores only archive transport properties
such as compression, tar order, and BuildKit bookkeeping.

Build and pull-request jobs are read-only and cannot publish packages, create
releases, or mint attestations. The tag-only release workflow verifies an
authorized signed SemVer tag, consumes already validated archives without
rebuilding, promotes API, I/O, maintenance, collaboration, MCP broker,
controller, runner, tools, and web manifests to GHCR, publishes the versioned Helm chart at
`oci://ghcr.io/oxibelt/charts/filebelt`, attaches GitHub artifact attestations,
reads every digest back, and creates a checksummed immutable GitHub Release.
Publication permission exists only in the promotion job. Published versions
are never moved or automatically deleted for rollback.

## Kubernetes production contract

FileBelt supports Kubernetes 1.34 through 1.36 with Helm 4.2.3. The chart
always creates four replaceable workload definitions: OxiBelt web, API, I/O
worker, and maintenance worker. `collaboration.enabled=true` additionally
creates the collaboration Deployment and Service; it requires the approved
collaboration schema, I/O capability verification path, and exact image
digest. WebSocket is enabled with the public edge route. WebTransport is
reserved until a separately reviewed runtime listener, H3 edge route, UDP
Service, QUIC host-key lifecycle, and browser compatibility evidence land
together; Phase 5 chart values deliberately expose no WebTransport toggle or
UDP route. `mcp.enabled=true` additionally creates the
broker Deployment and Services. The separate `mcp.runners.enabled=true`
opt-in creates the core controller Deployment, a narrow Role/RoleBinding and
runner ServiceAccount in the pre-created runner namespace, and permits one-shot
runner Pods there. The tools image runs
explicit bounded administrative Jobs. FileBelt deploys no StatefulSet or HPA.

PostgreSQL 18, one OIDC issuer and its in-cluster CONNECT egress gateway,
optional Iggy, the MCP HTTPS egress gateway, public L4 exposure, certificate
issuance, monitoring, and OTLP collection are external operator dependencies.
The chart creates none of those services and creates no Secret or persistent
volume. The MCP gateway authenticates broker/runner clients and enforces the
configured target/trust profile; no FileBelt Pod receives general Internet
egress.

The operator supplies one existing RWX POSIX claim owned for UID/GID 10001.
It must pass FileBelt's fsync, directory-fsync, same-filesystem rename,
ownership, and no-follow probe. Only I/O, maintenance, and explicit storage or
recovery Jobs mount the claim; API and web never do. FileBelt never changes or
deletes the claim.

Production chart values select all nine deployable workload images by
lowercase `sha256:` digest: API, I/O, maintenance, tools, web, collaboration,
broker, controller, and runner. Registry mirrors may replace only the registry authority; they do not
change repository, role, digest, authorization, or license semantics. A
catalog server image is separately pinned by digest and admitted only after its
offline Sigstore bundle, expected identity/issuer, license, source, command,
architectures, egress profile, and resource quantities validate.
The controller accepts only FileBelt's curated offline trust profile: exactly
one explicitly bounded Fulcio CA, Rekor key, and CT key, no TSA, and one Rekor
v1 proof-and-promise whose authenticated integrated time is inside all three
windows. Root and bundle rotation is an atomic operator change; overlapping or
unbounded authority projections fail closed.

Web, API, I/O, and collaboration default to two replicas and have `minAvailable: 1`
PodDisruptionBudgets. An enabled broker and controller also default to two
replicas with `minAvailable: 1`; the controller stays in the core namespace but
elects one 15-second Lease holder and receives Pod/Secret/Lease authority only
in the separate, pre-created runner namespace. Maintenance defaults to one
replica and
makes no leader-election or PDB claim. Workloads have explicit resource
requests and limits, bounded writable storage, immutable image and
configuration identity, graceful admission drain, preferred topology
spreading, and the restricted non-root security context.
`deployment.quiesced=true` retains workload definitions but sets every
long-running replica count to zero for a recovery window. It does not authorize
new runner creation; existing runner Pods and bootstrap Secrets must drain or
be reconciled before the checkpoint.

The core namespace and the exclusive runner namespace are ingress- and
egress-default-deny. NetworkPolicy permits only:

- the configured public L4 peer to OxiBelt;
- OxiBelt to the API, I/O, and collaboration backends;
- role-specific PostgreSQL and optional Iggy paths;
- collaboration to PostgreSQL and the I/O capability endpoint only;
- configured DNS, monitoring, and OTLP peers;
- API access to the operator-managed OIDC CONNECT gateway;
- broker access to PostgreSQL, API/I/O, the controller when enabled, and the
  MCP gateway; and
- runner relay access only to the broker relay and the MCP gateway. Runner Pods
  have no DNS egress; the trusted controller resolves both endpoints to a
  bounded numeric address list before Pod creation, while TLS validates their
  separately configured server names.

Catch-all IPv4 or IPv6 egress is rejected. Calico and Cilium acceptance tests
qualify the portable NetworkPolicy graph.

Backend API, I/O, and collaboration traffic uses TLS 1.3 mutual authentication. OxiBelt has a
distinct client certificate for each upstream. FileBelt validates the operator
CA, client-authentication purpose, and exact configured URI SAN; one retiring
identity may overlap during rotation. OxiBelt validates each service DNS SAN.
Health and metrics use a separate low-information internal listener because
kubelet does not present a client certificate.

API-to-broker and broker-to-controller traffic uses the same TLS 1.3 client
identity rules. Runner-to-broker and broker/runner-to-gateway use distinct
projected client credentials. Bootstrap tokens are immutable, invocation-bound,
32--4096 bytes, never mounted into the untrusted server container, and erased
after the relay hello. The server container receives only the runner shim,
memory-backed socket, bounded temporary storage, and loopback proxy variables.

Kubernetes mode uses `filebelt.toml` version 4; earlier versions are rejected. It
requires backend mTLS, HTTPS OIDC through the egress gateway, JSON logs, and
Prometheus metrics. Enabled collaboration additionally requires the
collaboration database URL/TLS identity, the combined API-generation-1 and
collaboration-generation-2 capability verification keyset, distinct
collaboration signing key, internal I/O capability endpoint and TLS identity,
60-second maximum reauthentication interval, 30-day dirty-room retention, and
a day-23 warning threshold. `webtransport_enabled` remains false in the typed
runtime configuration and is not an operator-facing deployment option. Enabled
collaboration filters join-grant verification to API generation 1; the
generation-2 collaboration key remains storage-capability-only even though both
public keys share the restored verification keyset. Enabled
MCP additionally requires the broker database URL,
vault keyring, broker URL/TLS, gateway URL/TLS, the internal I/O URL and
broker-to-I/O client TLS, and at least one named trust profile. The I/O server
allowlist admits the broker's exact attachment identity; the broker uses a
one-shot signed I/O capability and never mounts payload storage. Runners require
Kubernetes mode, controller mTLS, namespace, catalog,
offline trusted root and bundles, digest-pinned runner image, and positive
principal/tenant limits. The configured runner namespace must differ from the
core release namespace and be reserved for that release. Development mode may
use plaintext Compose backends
but never enables the Kubernetes runner controller. Configuration is
restart-only and stored in content-addressed immutable ConfigMaps. Existing
Secret content is projected by named key; an explicit generation change
triggers its controlled rollout.

The Compose edge configuration keeps the exact WebSocket route and the
`core` profile starts the collaboration role with its distinct database and
signing-key mounts. The shared API configuration enables grant issuance and
includes absolute collaboration paths only for typed validation; the API does
not mount the collaboration database or signing key. Operators exercise the
functional path with the `core` profile. Compose never publishes backend ports
or a UDP/WebTransport port.

## Administration, observability, and recovery

Database migration, grants verification, tenant bootstrap, storage probe,
audit export, scrub, recovery checkpoint, and recovery verification are
explicit non-hook Jobs with command-specific credentials and mounts. An
upgrade applies migration under the migrator role while old workloads remain
pinned, pauses for the database owner to apply the reviewed `grants.sql`, runs
grant/schema verification, and only then rolls workloads. The chart never
receives owner credentials and never applies a down migration.

Phase 5 collaboration rollout is staged. First apply its forward room/manifest
migration and reviewed narrow grants while collaboration admission is disabled,
then take a coordinated checkpoint. Enable WebSocket collaboration only after
the I/O finalize/fsync-to-manifest ACK path, 60-second authorization checks,
external-head freeze, reconnect, diff3, and dirty-retention tests pass.
WebTransport is not deployed in Phase 5. Its later admission requires a new
transport review and cannot be enabled by changing a Helm value. On a fault,
stop new grants, drain connections, fence rooms, and preserve dirty manifests
for review; never
acknowledge an update from an event or in-memory replica state.

Phase 4 rollout is staged. First apply the forward MCP migration and reviewed
role grants, provision the broker database/vault/gateway/mTLS inputs, validate
format-3 configuration, and take a coordinated checkpoint. Enable the broker
without runners, test one personal registration, discovery, explicit approval,
version-pinned attachment, revocation, and cross-user denial, then admit normal
MCP traffic. Enable the controller and runner only in a later revision after
catalog/Sigstore verification, namespace RBAC, Kubernetes-API egress, runner
quotas, cleanup, and gateway policy pass. No step combines owner grants,
credential rotation, broker rollout, and runner activation.

Rollback disables runner admission first, cancels active invocations, waits for
the controller to remove one-shot Pods and bootstrap Secrets, and then disables
the broker. Restore the recorded previous image digests, Secret generations,
and version-2 ConfigMap only when that binary is compatible with the expanded
schema. Do not drop `filebelt_mcp` or `filebelt_mcp_vault`, run a down migration,
or remove a KEK generation referenced by a
`filebelt.recovery.checkpoint.v2` document.

When compatibility cannot be proved, remain quiesced and restore the last
coordinated checkpoint into fresh targets before migrating forward.

Each native role emits structured redacted JSON logs and bounded-label
Prometheus metrics, with optional OTLP/HTTP traces. Portable alert and
dashboard assets ship in the repository. Prometheus Operator resources are
optional and disabled by default. Audit export is a pull-based, cursor-bounded
NDJSON command using its dedicated read-only database role; FileBelt does not
push audit records to an Internet sink.

Recovery is a coordinated quiesced PostgreSQL and payload snapshot restored
into fresh targets. The detailed production, recovery, and rollback procedures
are [Kubernetes operations](operations/kubernetes.md),
[Kubernetes recovery](operations/kubernetes-recovery.md), and
[Kubernetes rollback](operations/kubernetes-rollback.md).

## Changing this contract

Creating or activating a role, changing image contents or platforms, changing
the repository or license boundary, admitting a native or external runtime,
changing publication authority, adding a protocol integration, or changing
the production topology or trust graph requires an explicit architecture and
policy review in the same pull request. Record rationale, alternatives,
compatibility, security and license effects, rollout, and rollback. Update
this specification, the license map, supply-chain policy, threat model,
operator documentation, and regression coverage with the implementation.
