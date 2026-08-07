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

The current build matrix contains seven Apache-region images on
`linux/amd64`, `linux/arm64`, and `linux/riscv64`:

| Role | Current status and authority |
| --- | --- |
| `filebelt-api` | Active and publishable. Resolves OIDC/sessions, authorizes metadata operations, and issues capabilities. Has API-role PostgreSQL access and signing/digest secrets, but no payload mount. |
| `filebelt-worker-io` | Active and publishable. Performs capability-limited upload, finalization, and Range download using a narrow PostgreSQL role, verification keys, and one payload mount. |
| `filebelt-worker-maintenance` | Active and publishable. Leases durable jobs and reconciles, deletes, and scrubs through a narrow PostgreSQL role and one payload mount. |
| `filebelt-tools` | Active and publishable. Runs bounded, explicit configuration, migration, bootstrap, key, audit, job, storage, and recovery commands with command-specific credentials and mounts. |
| `filebelt-web` | Active and publishable. Combines static SPA/Markdown assets and reviewed route configuration with the pinned OxiBelt TLS edge. Has TLS material and isolated backend access, but no PostgreSQL or payload mount. |
| `filebelt-media-controller` | Probe-only. Built and validated for identity but not deployed or promoted as a service. |
| `filebelt-mcp-broker` | Probe-only. Built and validated for identity but not deployed or promoted as a service. |

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
rebuilding, promotes only API, I/O, maintenance, tools, and web manifests to
GHCR, publishes the versioned Helm chart at
`oci://ghcr.io/oxibelt/charts/filebelt`, attaches GitHub artifact attestations,
reads every digest back, and creates a checksummed immutable GitHub Release.
Publication permission exists only in the promotion job. Published versions
are never moved or automatically deleted for rollback.

## Kubernetes production contract

FileBelt supports Kubernetes 1.34 through 1.36 with Helm 4.2.3. The chart
creates four replaceable Deployments: OxiBelt web, API, I/O worker, and
maintenance worker. The tools image runs explicit bounded administrative Jobs.
Static resources are sufficient, so FileBelt deploys no controller,
StatefulSet, HPA, Kubernetes RBAC permission, or service-account token.

PostgreSQL 18, one OIDC issuer and its in-cluster CONNECT egress gateway,
optional Iggy, public L4 exposure, certificate issuance, monitoring, and OTLP
collection are external operator dependencies. The chart creates none of
those services and creates no Secret or persistent volume.

The operator supplies one existing RWX POSIX claim owned for UID/GID 10001.
It must pass FileBelt's fsync, directory-fsync, same-filesystem rename,
ownership, and no-follow probe. Only I/O, maintenance, and explicit storage or
recovery Jobs mount the claim; API and web never do. FileBelt never changes or
deletes the claim.

Production chart values select all five workload images by lowercase
`sha256:` digest. Registry mirrors may replace only the registry authority;
they do not change repository, role, digest, authorization, or license
semantics.

Web, API, and I/O default to two replicas and have `minAvailable: 1`
PodDisruptionBudgets. Maintenance defaults to one replica and makes no leader
election or PDB claim. Workloads have explicit resource requests and limits,
bounded writable storage, immutable image and configuration identity,
graceful admission drain, preferred topology spreading, and the restricted
non-root security context. `deployment.quiesced=true` retains workload
definitions but sets every replica count to zero for a recovery window.

The namespace is ingress- and egress-default-deny. NetworkPolicy permits only:

- the configured public L4 peer to OxiBelt;
- OxiBelt to the API and I/O backends;
- role-specific PostgreSQL and optional Iggy paths;
- configured DNS, monitoring, and OTLP peers; and
- API access to the operator-managed OIDC CONNECT gateway.

Catch-all IPv4 or IPv6 egress is rejected. Calico and Cilium acceptance tests
qualify the portable NetworkPolicy graph.

Backend API and I/O traffic uses TLS 1.3 mutual authentication. OxiBelt has a
distinct client certificate for each upstream. FileBelt validates the operator
CA, client-authentication purpose, and exact configured URI SAN; one retiring
identity may overlap during rotation. OxiBelt validates each service DNS SAN.
Health and metrics use a separate low-information internal listener because
kubelet does not present a client certificate.

Kubernetes mode uses `filebelt.toml` version 2; version 1 is rejected. It
requires backend mTLS, HTTPS OIDC through the egress gateway, JSON logs, and
Prometheus metrics. Development mode may use plaintext Compose backends.
Configuration is restart-only and stored in content-addressed immutable
ConfigMaps. Existing Secret content is projected by named key; an explicit
generation change triggers its controlled rollout.

## Administration, observability, and recovery

Database migration, grants verification, tenant bootstrap, storage probe,
audit export, scrub, recovery checkpoint, and recovery verification are
explicit non-hook Jobs with command-specific credentials and mounts. An
upgrade applies migration under the migrator role while old workloads remain
pinned, pauses for the database owner to apply the reviewed `grants.sql`, runs
grant/schema verification, and only then rolls workloads. The chart never
receives owner credentials and never applies a down migration.

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
