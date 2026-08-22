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

The current build matrix contains seventeen Apache-region images on
`linux/amd64`, `linux/arm64`, and `linux/riscv64`:

| Role | Current status and authority |
| --- | --- |
| `filebelt-api` | Active and publishable. Resolves OIDC/sessions, authorizes metadata operations, and issues capabilities. Has API-role PostgreSQL access and signing/digest secrets, but no payload mount. |
| `filebelt-worker-io` | Active and publishable. Performs capability-limited upload, finalization, and Range download using a narrow PostgreSQL role, verification keys, and one payload mount. |
| `filebelt-worker-maintenance` | Active and publishable. Leases durable jobs and reconciles, deletes, and scrubs through a narrow PostgreSQL role and one payload mount. |
| `filebelt-tools` | Active and publishable. Runs bounded, explicit configuration, migration, bootstrap, key, audit, job, storage, and recovery commands with command-specific credentials and mounts. |
| `filebelt-web` | Active and publishable. Combines static SPA/Markdown assets and reviewed route configuration with the pinned OxiBelt TLS edge. Has TLS material and isolated backend access, but no PostgreSQL or payload mount. |
| `filebelt-collaboration` | Dedicated Rust collaboration role for Yrs `0.27.3`. When enabled, admits authenticated Markdown editors, persists fenced CRDT manifests through scoped I/O capabilities, and has narrow PostgreSQL/I/O access but no payload mount, browser session authority, or general Internet egress. |
| `filebelt-document` | Active, publishable, and disabled by default. Coordinates provider-neutral document sessions, revalidates Virtual ACL and API-session generations, signs `document-storage` exact-version/revision I/O capabilities, and reconciles expected-head commits. It has a narrow PostgreSQL role and no payload mount, browser cookie authority, adapter implementation dependency, or Internet egress. |
| `filebelt-revision` | Compatibility-gated and disabled by default. Coordinates PostgreSQL-authoritative text Git revisions, shared-chunk backfill, bounded comparison, activation, and repair holds through purpose-scoped I/O and adapter calls. Comparison admission defaults to two globally and one per authenticated user, with immediate overload rejection. It has a narrow PostgreSQL role and no payload/Git mount, browser session credential, or Internet egress. |
| `filebelt-media-controller` | Probe-only. Built and validated for identity but not deployed or promoted as a service. |
| `filebelt-mcp-broker` | Active, publishable, and disabled by default. Revalidates MCP policy, owns encrypted MCP-vault access, mediates Streamable HTTP and runner relays, and has no payload mount or direct Internet route. |
| `filebelt-controller` | Active, publishable, and enabled only with stdio runners. Verifies the offline runner catalog, leads reconciliation in the exclusive runner namespace, and creates/deletes only bounded runner Pods, bootstrap Secrets, and its Lease there. |
| `filebelt-mcp-runner` | Active and publishable. Supplies the trusted relay/shim injected into one-shot curated server Pods; it receives no FileBelt database, payload, session, or vault credential. |
| `filebelt-private-egress-gateway` | Preview-only and blocked from publication. A role-specific Apache protocol gateway for exact MCP or ONLYOFFICE output requests; it holds only its two mTLS hop identities and target CA and has no tunnel key, database, payload mount, or generic proxy API. |
| `filebelt-tunnel-relay` | Preview-only and blocked from publication. Accepts the fixed private-egress ALPN over mTLS and relays to one configured set of numeric same-port targets, directly through WireGuard or through a loopback userspace-Tailscale SOCKS5 endpoint. It accepts no caller destination. |
| `filebelt-vfs` | Active and publishable, but mount delivery is disabled by default. Resolves generic gateway requests through PostgreSQL-authoritative Virtual ACL/session/handle fences and signs `mount-storage` `fbcap2` reads to I/O. It has no payload mount. |
| `filebelt-headscale-sync` | Active and publishable, but mount delivery is disabled by default. Validates complete Headscale `0.29.3` device snapshots and atomically replaces the narrow PostgreSQL device projection. It has no payload mount or credential authority. |
| `filebelt-nfs-relay` | Active and publishable, but NFS delivery is disabled by default. Opaquely forwards bounded TCP/2049 streams from the tailnet edge to one chart-pinned Ganesha backend. It has no Ganesha keytab, bridge TLS identity, VFS route, payload mount, or authority over NFS identities. |

Format-9 deployment material is purpose-scoped and operator-created. API mounts
only its enabled API private/public pairs; I/O mounts API-storage plus enabled
storage-purpose public keysets; collaboration additionally receives its own
pair and API storage/grant public sets; broker receives API-MCP-delegation
public material only; document and VFS receive their own pairs. No runtime Pod
mounts media signing material; recovery/admin Jobs receive the media public
keyset. Helm values name every Secret separately and exact Secret generations
are included in the relevant immutable-Secret rollout checksum. Independent
typed `capabilityGenerations` values select the numeric signing generation for
each purpose; an opaque Secret rollout generation never substitutes for that
protocol fence. Before any
format-9 admission, the public-only `keys-audit` Job must load the complete
configured inventory and prove that current generations are present and public
key bytes are globally disjoint across purposes.

Copyleft adapter roles `filebelt-smb-gateway` and
`filebelt-ftp-ftps-gateway` remain outside the Apache image plan and release
workflow. Their Helm entries record the expected repository, SPDX expression,
and corresponding-source location, but the all-zero digest is not a published
artifact. The FTPS source has an opt-in read-only VFS bridge; its release image
and end-to-end certificate fixture are not yet qualified. The SMB source
registers exact Samba ABI callbacks but deliberately returns `ENOSYS` until a
reviewed authentication/session IPC bridge replaces every local-filesystem
fallback. Therefore the combined mount chart topology is a disabled preview,
not a production-ready listener, and operators must not enable it from this
revision.

The separately released `filebelt-onlyoffice-adapter` is an
`AGPL-3.0-only` external-integration role. It remains disabled until the
operator supplies an exact ONLYOFFICE Docs Community `9.4.0` instance, callback
secrets, provider configuration, TLS identities, and an exact egress-gateway
target. Adapter image publication remains disabled until complete amd64 and
arm64 source/SBOM/provenance evidence is admitted; RISC-V is compile/probe
evidence because the upstream provider has no qualified RISC-V runtime. The
separately versioned deployment chart does not create or redistribute
DocumentServer, a database, a Secret, a Namespace, or a volume.

The Apache-2.0 `filebelt-git-adapter` wrapper is also a separately released
process and chart. Its scratch image contains exactly the static wrapper, a
separate static GPL-2.0-only Git `2.55.0` executable, required license and
notice files, and the source manifest. It requires a Git-only RWX PVC, a
private TLS-1.3/mTLS listener on 8092, a distinct operations listener, and no
general egress, PostgreSQL credential, payload mount, API route, or browser
identity. The Apache coordinator listens privately on 8091 without either
byte-plane mount. Adapter images remain non-publishable until their exact Git
source, build inputs, license notices, SBOM/provenance, amd64/arm64 behavior,
SHA-256 repository behavior, and restore/fsck matrix are admitted. Git and
Cargo sources are staged from the checksummed corresponding-source bundle;
the Dockerfile has no downloader or package-manager fallback and compiles the
wrapper locked and offline. The chart
does not create its Namespace, Secrets, database, or operator-owned adapter
ConfigMap. It bounds admitted private tasks at eight and concurrent system-Git
processes at two. A raw connection above the private-task limit closes without
dispatch; an admitted comparison that cannot immediately acquire a Git-process
permit returns the typed admission result. Non-comparison maintenance may wait
for a Git-process permit only within its existing bounded request timeout.

Directory Git is a future compatibility-gated extension of this same process
boundary, not a new payload mount or a direct Apache-to-GPL link. Before its
two-release activation, repository creation, Git HTTPS, tailnet SSH, LFS, and
directory projection remain disabled. When admitted, the Apache coordinator
continues to own PostgreSQL authority and speaks only a versioned private
protocol to the Apache wrapper; the wrapper alone invokes the separate
GPL-2.0-only Git executable and owns the Git-only RWX PVC. No API, web, VFS,
SMB, FTPS, NFS, or I/O process mounts that PVC, receives a Git implementation
credential, or infers a FileBelt principal from a Git path or ref.

Directory-Git release evidence must cover the selected receive limits (1 GiB
pack, 32 first-parent commits, 10,000 changed paths/commit, 100,000 tree
entries, 100 MiB ordinary blobs, and configured LFS max-file limit), HTTPS
device-token expiry, tailnet SSH fencing, `main` projection, Git/LFS retention,
fsck/restore, and checkpoint-v5 recovery. This evidence is in addition to
existing Git source/SBOM/provenance/license evidence. It does not qualify
SMBv3, FTPS, or NFS writes; all remain disabled until independent adapter and
live-protocol qualification completes.

Other reserved adapter roles are future `filebelt-nfs-gateway` and
`filebelt-transcoder`. Each has an independently truthful platform and license contract. Transcode implementation remains
prohibited until its exact FFmpeg composition has been reviewed and the
license map, supply-chain evidence, and runtime contract are updated together.

Adapter charts default to `qualification: blocked` with zero sentinel digests.
Helm rendering fails until promotion supplies a qualified state, an exact
nonzero image digest, and the exact source-bundle SHA-256. Core asset packaging
does not publish adapter charts. Each rendered adapter object and workload Pod
template carries the exact SPDX license, corresponding-source URL, and source
SHA-256 as `filebelt.dev/adapter-*` annotations. These non-identifying release
evidence values are never labels or selectors. Once all seven pre-image
prerequisites pass, the bundle-image runner may build OCI archives without
publishing them; only
the signed-tag release owner may later publish roles whose security,
functional, and native-platform states are also qualified. No adapter
subject-map or promotion implementation exists in this revision, so the plan
keeps publication blocked even if those qualification fields are supplied.

Every FileBelt process normally runs as numeric UID/GID `10001:10001`. The NFS
StatefulSet is the narrow exception: its bridge remains `10001:10001`, Ganesha
runs as `10002:10002`, and both receive supplemental IPC group `10003` so exact
peer credentials can distinguish the trusted FSAL from other Pod processes.
All retain a read-only root filesystem, no-new-privileges, dropped Linux
capabilities, bounded writable temporary storage, and only role-specific ports,
networks, secrets, and mounts. Liveness reports process health separately from
dependency and storage readiness.

## Descendant-share security cutover

The descendant-share migration is a fail-closed compatibility boundary. Apply
the forward migration and reviewed grants first; its tenant gate blocks new
direct shares and MCP data grants, including writes from still-running older
API replicas. Roll out the compatible API/database image, then use the
recovery-credential Helm Jobs in order: `security-descendant-shares-repair`
(the command runs bounded batches until complete),
`security-descendant-shares-verify`, and
`security-descendant-shares-activate`. Generate one operation UUID for the
tenant cutover and reuse it across every repair retry, verification, and
activation. Each mutating Job also requires exact tenant-slug confirmation, a
validated tenant-admin actor, and the same compiled source revision. The status
Job is read-only and takes only the operation UUID.

Do not combine activation with migration or normal workload rollout. Retain the
run/checkpoint/audit output and successful two-user direct-share/MCP denial and
post-activation acceptance evidence. Rollback preserves the schema and blocked
gate: an older binary may be restored only if it is schema-compatible, and no
rollback or scale action reopens admission.

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
| VFS gateway protocol | 8087 | enabled SMB, FTP/FTPS, or NFS adapter identities only, exact URI-SAN mTLS; disabled by default |
| VFS credential management | 8088 | API identity only, mTLS; disabled by default |
| Document API control | 8089 | API identity only, mTLS; disabled by default |
| Document adapter control | 8090 | Approved document-adapter identity only, mTLS; disabled by default |
| ONLYOFFICE adapter | 8089 | OxiBelt mTLS identity only in the integration namespace; separately deployed |
| Native operations | 9090 | kubelet/monitoring only |
| Runner local egress proxy | 7777 | loopback within the one-shot Pod only |

The Rust final stages contain the role executable and required identity,
license, and notice files without a shell or package manager. The web image is
derived from the exact OxiBelt input recorded in the image plan and copies only
FileBelt assets, reviewed configuration, identity metadata, licenses, and
notices. The current pin is OxiBelt `0.7.1-beta.2` at
`sha256:e8556a0103feff47bf6135062e70e980e000176598fd438959ea55d99c844030`.
Its admitted AMD64 child is
`sha256:bda2474f0ae5b7413751381009990d0627228aba0658e03549a00b953fddb130`,
and its retained GitHub/Sigstore rebuild predicate binds role `standalone`,
source revision `bf40172e40298325775ca9d708162a9d8d14e6d4`, and target CPU
`x86-64-v3`. The retained raw index and AMD64 manifests provide the exact
attestation subjects. The verifier fixes the retained Sigstore trusted-root
snapshot path and SHA-256 independently of admission schema v2, which contains
no trust-root selector. This permits offline signature, certificate-identity,
OIDC-issuer, transparency-log, source, and GitHub-hosted-runner verification.
The admission validator also binds this index digest directly to the
`ui/web/Dockerfile` base. FileBelt does not rebuild that upstream binary.
Changing that prerelease input requires a focused source, route, mTLS,
architecture, vulnerability, license, and notice review.
Changing the trust root requires one reviewed change to the retained snapshot,
verifier pin, regression tests, and this contract. An older release remains
verifiable only with that release's retained verifier and root; rollback never
weakens the current verifier to accept its legacy admission schema.

## Platform and artifact evidence

Canonical `linux/amd64` images require the `x86-64-v3` ISA baseline and have
no v2 fallback. FileBelt-built Rust uses
`-Ctarget-cpu=x86-64-v3` and FileBelt-built C/C++ uses
`-march=x86-64-v3`; final links use GNU `-z x86-64-v3`. Each in-scope AMD64
ELF must carry the GNU `x86-64-v3` ISA-needed property; a toolchain may also
include its redundant baseline bit.
ARM64 and RISC-V retain their architecture-default compiler settings.
The Docker integration runner derives the local `--build` input from the
Docker server architecture before it creates Compose resources: `amd64` maps
to `x86-64-v3`, while supported `arm64` and `riscv64` servers map to
`architecture-default`. Empty or unsupported server architecture values stop
the source build. Exact-artifact runs do not perform this selection and remain
no-build validation of their archived image metadata.

Core image-plan schema v2 and adapter image-plan schema v3 carry the exact
`amd64IsaBaseline`. Build metadata, validation receipts, OCI label
`io.filebelt.build.target-cpu`, and CycloneDX subject properties bind the
platform value; normalized SBOMs also bind the canonical plan SHA-256. New
validators accept only these schema versions. Rollback of an older release
uses that release's retained tooling and evidence rather than weakening current
validators.

For each platform build, one role-independent Rust stage installs the selected
output-target component, derives the builder-host triple from its pinned
`rustc -vV`, and makes one locked Cargo fetch for the host and output-target
closures with a finite ten-retry budget. This fetch admits only checksum-locked
crates.io inputs; it never resolves a branch, tag, mirror, or newer publication.
All role-specific compilation then runs locked and offline from that stage.
BuildKit layer reuse prevents
ordinary image matrices from reacquiring the same inputs for every role, but
it is not admission or release evidence; a full no-cache rebuild deliberately
reacquires the closures. Exhausted retries, a missing host or target input,
checksum failure, or an incomplete closure stop the build before any role
archive is accepted. BLAKE3 `1.8.7` removes the former yanked `arrayref` edge;
the checksum-bound source review and fail-closed regression policy are
documented in [Supply chain](SupplyChain.md). No registry mirror, unyank, Git
source, or vendored fallback is part of this contract.

AMD64 and ARM64 run native behavior suites. Before an AMD64 build or native
test, the FileBelt host checker verifies every `/proc/cpuinfo` processor and
emits only a bounded compatibility result. This proves the execution host, not
a remote Docker daemon. RISC-V cross-compiles with the
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
build metadata, normalized CycloneDX SBOM, and Trivy `0.74.0` vulnerability
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
rebuilding, promotes API, I/O, maintenance, collaboration, document, MCP broker,
controller, runner, tools, VFS, Headscale-sync, and web manifests to GHCR,
publishes the versioned Helm chart at
`oci://ghcr.io/oxibelt/charts/filebelt`, attaches GitHub artifact attestations,
reads every digest back, and creates a checksummed immutable GitHub Release.
It also publishes and attests the Apache-authored, disabled-by-default
`oci://ghcr.io/oxibelt/charts/filebelt-onlyoffice` deployment chart. That chart
contains no adapter binary or provider asset and its sentinel image digest must
be replaced with independently admitted adapter-image evidence before use.
Publication permission exists only in the promotion job. Published versions
are never moved or automatically deleted for rollback.

The versioned Docker integration catalog contains isolated `core`,
`collaboration`, and `mcp` units. Pull requests, pushes, scheduled validation,
and manual validation run all three. Signed-tag release validation replays all
three independently. Every job downloads only the validated AMD64
artifact, verifies that it binds the current revision and event channel, and
loads it without rebuilding FileBelt. Unique Compose projects, disposable
state, owned fixture tags, volumes, and networks make cleanup deterministic.
Only a secretless, mountless, bounded raw TCP acceptance relay joins the
ordinary publication network; it forwards exclusively to the web edge on the
internal edge network. The runner requires exactly one IPv4 loopback mapping,
while every FileBelt application service remains unpublished.
Failure evidence is limited to bounded scrubbed logs and synthetic screenshots
for 7 days on pull requests and 30 days otherwise; browser traces are disabled.
The catalog and exact operator commands are documented in
[Docker integration units](operations/docker-integration.md).

The manual local development helper at
[`tests/development/README.md`](../tests/development/README.md) creates named,
detached Compose or helper-owned Minikube sessions for diagnosis. Its strict
schema defaults to source images and accepts validated artifact archives only
as an explicit alternative. Minikube source mode builds the core chart images
for local `amd64` or `arm64`; its artifact mode requires the validated AMD64
evidence catalog. The preview uses the repository-pinned Helm `v4.2.4`,
defaults to Kubernetes `v1.36.1`/Calico, and accepts only the current
repository-supported Kubernetes/CNI choices. It installs the chart only with
`deployment.quiesced=true` and `operation.type=none`; it is chart and policy
inspection, not serving-deployment evidence. Every optional chart image,
Secret file, PVC, ConfigMap, values file, and prerequisite manifest remains
caller-qualified. Sessions and Compose port-forwards are loopback-only,
retained diagnostics are failure-only and scrubbed, and session/status JSON is
always `accepted: false`.

The helper does not qualify production, release, provider, Kubernetes/CNI, or
security behavior and is not a CI live deployment lane.

Docker evidence proves the cataloged development topology only. It is not live
Kubernetes, Helm rollout, CNI, NFS/Kerberos/Ganesha, public DNS, provider, or
external MCP TLS qualification. Kubernetes compatibility and Calico/Cilium
jobs remain separate blocking gates and their definitions are unchanged by the
Docker matrix.

Production AMD64 node pools must be homogeneous `x86-64-v3`. Operators run the
digest-pinned DaemonSet preflight described in
[Kubernetes operations](operations/kubernetes.md) before rollout and after a
pool, autoscaler, hypervisor, or VM CPU-model change. FileBelt does not add a
custom ISA label or scheduling affinity. Rollback may select a previously
verified generic-AMD64 digest on the already-qualified v3 pool; it must not use
rollback as evidence that an untested pool supports current images.

## Kubernetes production contract

FileBelt supports Kubernetes 1.34 through 1.36 with Helm 4.2.4. The chart
always creates four replaceable workload definitions: OxiBelt web, API, I/O
worker, and maintenance worker. `collaboration.enabled=true` additionally
creates the collaboration Deployment and Service; it requires the approved
collaboration schema, I/O capability verification path, and exact image
digest. WebSocket is enabled with the public edge route. The separate Phase 8
`collaboration.webtransport.enabled=true` opt-in adds the reviewed TLS 1.3 H3
listener, OxiBelt route, UDP Service/NetworkPolicy path, bounded drain, and the
same one-use first-frame collaboration grant. WebSocket remains the correctness
fallback. `mcp.enabled=true` additionally creates the
broker Deployment and Services. The separate `mcp.runners.enabled=true`
opt-in creates the core controller Deployment, a narrow Role/RoleBinding and
runner ServiceAccount in the pre-created runner namespace, and permits one-shot
runner Pods there. SMB, FTP/FTPS, and NFS are independent disabled-by-default
mount flags. Any enabled protocol renders VFS. SMB or FTP/FTPS also renders
Headscale sync and the selected gateway StatefulSet with an operator-provided
RWO tailstate claim. NFS instead renders two single-active StatefulSets. The
tailnet StatefulSet contains `tailscaled` and the Apache
`filebelt-nfs-relay`; the backend StatefulSet contains only Ganesha and its
authenticated bridge. The tailstate claim and TUN device exist only in the
relay Pod, while recovery state, the keytab, VFS client identity, and Unix IPC
exist only in the backend Pod. A stable ClusterIP Service selects the relay and
a second pinned-ClusterIP Service is private to relay-to-Ganesha TCP 2049.
NFS does not force Headscale sync. Rendering is rejected unless kernel tailnet
networking, exact tailnet-control and ingress peers, pinned VFS/backend Service
addresses, and the selected protocol's fail-closed inputs are present.
Separately licensed adapters remain production-gated on published images and
protocol acceptance evidence. The tools image runs explicit bounded
administrative Jobs. FileBelt deploys no HPA.

The scheduled and manually dispatched validation workflow also runs an
isolated Minikube/Calico acceptance lane against Kubernetes `v1.37.0-rc.0`.
That prerelease lane verifies the exact API-server version, restricted Pod
Security admission, rendered objects, and NetworkPolicy behavior, but is not a
release or support gate. Kubernetes 1.37 must not enter `kubeVersion`, the
supported Kind matrix, or production guidance until a stable release and an
immutable reviewed Kind node image are available.

`documents.enabled=true` additionally renders the Apache document coordinator
Deployment and Service only after migration 000006, grants verification, the
`document-storage` purpose keyset, API/document/I/O mTLS projections, an exact
operator-configured isolated editor launch action, and an exact external
provider HTTPS origin are present. The editor action must be HTTPS at
`/onlyoffice/launch` on a hostname distinct from both the FileBelt public host
and provider host. The existing public TLS Secret must cover both FileBelt DNS
names; OxiBelt serves them as separate virtual hosts with disjoint route sets.
The base chart never renders a
provider adapter or DocumentServer. The separately installed
`filebelt-onlyoffice` chart targets a pre-created integration namespace and
renders only the AGPL adapter, its Service/PDB, and default-deny policies. The
operator supplies the DocumentServer workload and provider database according
to its own edition/license contract; neither receives a FileBelt payload mount
or general FileBelt PostgreSQL credential.

PostgreSQL 18, one OIDC issuer and its in-cluster CONNECT egress gateway,
optional Iggy, the MCP HTTPS egress gateway, public L4 exposure, certificate
issuance, monitoring, and OTLP collection are external operator dependencies.
Mount preview additionally depends on external Headscale `0.29.3`, its API
token/CA, gateway tailnet auth, node `/dev/net/tun`, and distinct RWO tailstate
claims.
The chart creates none of those services and creates no Secret or persistent
volume. The MCP gateway authenticates broker/runner clients and enforces the
configured target/trust profile; no FileBelt Pod receives general Internet
egress.

The operator supplies one existing RWX POSIX claim owned for UID/GID 10001.
It must pass FileBelt's fsync, directory-fsync, same-filesystem rename,
ownership, and no-follow probe. Only I/O, maintenance, and explicit storage or
recovery Jobs mount the claim; API and web never do. FileBelt never changes or
deletes the claim.

Production chart values select all thirteen deployable Apache workload images by
lowercase `sha256:` digest: API, I/O, maintenance, tools, web, collaboration,
broker, controller, runner, VFS, Headscale sync, document coordinator, and NFS
relay. Registry mirrors may
replace only the registry authority; they do not
change repository, role, digest, authorization, or license semantics. A
catalog server image is separately pinned by digest and admitted only after its
offline Sigstore bundle, expected identity/issuer, license, source, command,
architectures, egress profile, and resource quantities validate.
The controller accepts only FileBelt's curated offline trust profile: exactly
one explicitly bounded Fulcio CA, Rekor key, and CT key, no TSA, and one Rekor
v1 proof-and-promise whose authenticated integrated time is inside all three
windows. Root and bundle rotation is an atomic operator change; overlapping or
unbounded authority projections fail closed.

Web, API, I/O, collaboration, and enabled VFS and document roles default to two replicas and have `minAvailable: 1`
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
- document coordinator to its PostgreSQL role only; API may reach its 8089
  mTLS listener and the approved integration-namespace adapter may reach only
  its separate 8090 listener;
- VFS to its PostgreSQL role and the I/O mount-read endpoint only, and I/O
  ingress from the exact VFS identity only when mount preview is enabled;
- Headscale sync to its PostgreSQL role and the exact external Headscale peer;
- tailnet ingress to the SMB, FTP/FTPS, and NFS relay listeners. SMB and
  FTP/FTPS application containers receive VFS-only egress while their
  `tailscaled` sidecars share configured DNS and exact Headscale egress. The
  NFS relay Pod receives DNS, Headscale, and its backend path only; the separate
  NFS backend receives VFS-only egress;
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

The integration namespace has its own ingress/egress default deny. OxiBelt may
reach only the adapter listener; DocumentServer reaches launch input and
callback paths through OxiBelt rather than receiving direct Pod ingress.
The FileBelt public OxiBelt host exposes adapter input, callback, source, and
about paths, while the distinct editor host exposes only launch POST and the
launcher asset GET. OxiBelt strips browser authority headers on both route
sets, disables retries and caching, and preserves the external Host and Origin
values for the adapter's independent enforcement. No editor-host API or API
CORS route exists.
Adapter egress is limited to DNS, the Apache document adapter listener, the
capability-limited I/O listener, the single mTLS provider-output egress gateway,
and optional OTLP. It has no direct Internet/default-route egress and no path
to the FileBelt payload volume or any PostgreSQL role. The gateway allowlists one
DocumentServer origin and rejects redirects, private/link-local/metadata
destinations after every DNS resolution, oversized response metadata, and
responses above 100 MiB.

Backend API, I/O, collaboration, document, adapter, VFS, and VFS-management
traffic uses TLS 1.3 mutual authentication. OxiBelt has a distinct client
certificate for each upstream, including the ONLYOFFICE adapter. FileBelt and
the adapter validate the operator CA, client-authentication purpose, and exact
configured URI SAN; one retiring identity may overlap during rotation.
OxiBelt validates each service DNS SAN.
Health and metrics use a separate low-information internal listener because
kubelet does not present a client certificate.

API-to-broker and broker-to-controller traffic uses the same TLS 1.3 client
identity rules. Runner-to-broker and broker/runner-to-gateway use distinct
projected client credentials. Bootstrap tokens are immutable, invocation-bound,
32--4096 bytes, never mounted into the untrusted server container, and erased
after the relay hello. The server container receives only the runner shim,
memory-backed socket, bounded temporary storage, and loopback proxy variables.

Kubernetes mode uses `filebelt.toml` version 9; earlier versions are rejected. It
requires backend mTLS, HTTPS OIDC through the egress gateway, JSON logs, and
Prometheus metrics. Enabled collaboration additionally requires the
collaboration database URL/TLS identity, purpose-specific API-storage and
collaboration-storage public keysets, the API collaboration-grant public
keyset, a distinct collaboration signer, internal I/O capability endpoint and TLS identity,
60-second maximum reauthentication interval, 30-day dirty-room retention, and
a day-23 warning threshold. `webtransport_enabled` remains false in the typed
runtime configuration and is not an operator-facing deployment option. Enabled
collaboration filters join-grant verification to the API collaboration-grant
purpose; the collaboration-storage key remains storage-capability-only. Enabled document
integration additionally requires the document database URL, fixed provider ID,
isolated editor launch action, and external provider HTTPS origin, API-to-document
and adapter-to-document client identities,
adapter-to-I/O client identity, `document-storage` signing key, its
purpose-specific I/O verification keyset, 20-participant admission limit, 100 MiB
document limit, and a recheck interval no greater than 60 seconds. The document
role accepts no provider callback JSON and the API receives neither the
`document-storage` private key nor document-role database credential. Enabled MCP
additionally requires the broker database URL,
vault keyring, broker URL/TLS, gateway URL/TLS, the internal I/O URL and
broker-to-I/O client TLS, and at least one named trust profile. The I/O server
allowlist admits the broker's exact attachment identity; the broker uses a
one-shot signed I/O capability and never mounts payload storage. Runners require
Kubernetes mode, controller mTLS, namespace, catalog,
offline trusted root and bundles, digest-pinned runner image, and positive
principal/tenant limits. The configured runner namespace must differ from the
core release namespace and be reserved for that release. Enabled mount preview
additionally requires VFS and Headscale database URLs, the distinct
`mount-storage` signing key, its purpose-specific public verification keyset, a
distinct mount-vault keyring, API/VFS/I/O mTLS projections, external Headscale
URL/token/CA and exact OIDC issuer, and kernel tailnet networking for the
gateways. VFS and Headscale sync do not run tailscaled and receive no TUN
device; only tailnet gateway Pods receive `NET_ADMIN`, `/dev/net/tun`, and
separate tailstate claims. Development mode may use plaintext Compose backends
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
or a UDP/WebTransport port. The development-only acceptance relay is the sole
host-published service and does not carry application secrets or storage. It
binds loopback by default and refuses a non-loopback bind unless the operator
sets the exact development-only acknowledgement documented in `deploy/README.md`.
The passwordless OIDC fixture, payload initializer, and relay use independent
image override variables. External development OIDC requires explicit format-9
role configurations, edge routing, client-secret/CA inputs, and the optional
operator-created OIDC egress network; substituting the fixture image alone is
not supported.

## Phase 8 deployment and rollout

Configuration version 9 retains disabled-by-default media, NFS, and collaboration
WebTransport sections. Unknown fields, mutable image tags, missing Secret keys,
unbounded resources, unsupported protocol modes, and incomplete network peers
fail startup or Helm validation. Phase 8 uses one coordinated version, but
Apache, LGPL, and GPL images remain independently built, evidenced, and
published repositories pinned by digest in the chart.

The NFS backend release target is a single-active fenced StatefulSet containing
NFS-Ganesha `6.5-8` from the Ubuntu 26.04 snapshot dated 2026-08-09, a thin
dynamic FileBelt FSAL, and an adapter-local Rust bridge over bounded Unix IPC.
Its separate single-active tailnet StatefulSet contains `tailscaled` and the
purpose-bound Apache TCP relay; the relay does not parse NFS, terminate TLS,
add PROXY framing, or receive NFS/VFS authority Secrets.
The current tree contains the generic schema/state model, opaque keyed handles,
bounded bridge framing, an unqualified candidate FSAL callback/control surface,
and portable C boundary checks. Exact-header syntax evidence is not an ABI/link
result, and the export sentinel still rejects the callback surface by default;
there is no qualified adapter image.

The exact Ganesha source build also applies reviewed LGPL patches that make
always-stacked MDCACHE delegate an overridden lower-FSAL `test_access` and let
the lower FSAL project authoritative owner/group names through GETATTR and
READDIR without host idmapper fallback. These patches are necessary security
contracts, but patch application and header compilation alone do not establish
ABI/link compatibility or live owner/group enforcement.
The chart therefore requires explicit published gateway, relay, and tailscaled
image digests, operator-owned
Ganesha and bridge ConfigMaps, shell-free command/health/preStop argv, a static
keytab, an exact `spiffe://filebelt/nfs-gateway/vfs` bridge identity, a VFS-only
handle keyring, pinned existing VFS and new backend ClusterIPs, and distinct
RWO tailstate/recovery claims before it renders the NFS listener. The backend
maps only the canonical `filebelt-vfs.<namespace>.svc` hostname to the pinned
VFS address; bridge startup rejects any other URL host, and backend policy has
no DNS or Headscale route. Ganesha and the bridge use the same pinned FileBelt image; the
bridge runs as `10001:10001`, Ganesha runs as `10002:10002`, and their exact
`10003`-group Unix sockets authenticate both connection and packet credentials
in each direction. The relay accepts at most 4,096 connections and 64 per
observed source by default, uses five-second connect and five-minute inactivity
timeouts, and drains for at most 180 seconds. Policy provides no backend DNS,
Headscale, KDC, or default egress. Until the adapter image ABI and protocol
evidence are qualified,
operators must leave NFS disabled.

The checked-in NFS qualification scaffold is read-only and deliberately fails
its publication boundary. It rejects emulated builds, an image that retains the
`abi-probe-only` label, incomplete LGPL/source/SBOM/provenance evidence, and an
incomplete Ubuntu/Debian/RHEL 10 `krb5p` client matrix. The repository currently
defines no native RISC-V runner label, immutable client rootfs set, external
KDC fixture, cluster administration driver, evidence assembler, or NFS
promotion job. Those inputs require separate review before the scaffold can
become release evidence; see [NFS release qualification](operations/nfs-qualification.md).

The media release target is one isolated Job per fenced attempt in a
pre-created namespace, with no service-account token, database credential,
payload/cache mount, DNS, or Internet route. The current tree contains closed
AV1/VP9 plus Opus profiles, durable admission/attempt/receipt/manifest fences,
HTTP request/status/cancel control, the GPL local-path-only wrapper, and exact
image/source-offer contracts. The controller remains probe-only until scoped
I/O transfer/callback integration, Job reconciliation, malicious-input tests,
and HTTP playback are qualified; the chart therefore exposes no media enable
toggle. RISC-V remains compile/probe-only and VAAPI remains disabled.

OxiBelt terminates public HTTP/3/WebTransport on UDP 443 with the same
operator-projected TLS identity as HTTPS. The collaboration QUIC listener uses
TLS 1.3 mutual authentication and disables 0-RTT. OxiBelt forwards only the
dedicated H3/WebTransport route over UDP 8086. Drain rejects new sessions,
retains authenticated connections for at most 300 seconds, then requires a
fresh grant. The current OxiBelt `0.7.1-beta.2` source and digest remain pinned
for Phase 8.

Rollout installs migrations and reviewed grants with every feature disabled,
rolls all compatible roles, takes a coordinated checkpoint, and then runs the
audited Phase 8 activation. NFS, media, and WebTransport are separately enabled
only after their qualification evidence passes, although release promotion is
coordinated. Rollback disables admissions first, fences gateways/jobs/sessions,
drains workloads, and restores previous compatible image digests. It preserves
Phase 8 schemas, conflict data, recovery claims, key generations, and cache
metadata. A binary downgrade uses the recorded pre-activation restore.

A role compatibility advertisement is not a version-only operator assertion.
`filebeltctl phase8 advertise` requires schema
`filebelt.phase8.qualification.v2` evidence covering the exact API, I/O,
maintenance, collaboration, media-controller, VFS, and tools role set. A
compatible advertisement binds the requested instance UUID and source revision
to an executed endpoint, a positive latency sample, exact success and failure
assertions, and completed or unnecessary cleanup. Failed and
prerequisite-bearing skipped results may only advertise `--incompatible`.
Activation still requires fresh compatible evidence for every role.

The provider-neutral local harness exercises API, I/O, and maintenance
operations endpoints, real one-use collaboration WebSocket admission, and the
tools executable boundary in an isolated Compose lifecycle. The development
topology has no media-controller or VFS service and cannot qualify native NFS,
media delivery, or the Kubernetes WebTransport route. Those entries remain
explicit non-accepted skips with their prerequisites and no fabricated
measurements. Completing the harness successfully therefore does not qualify a
Phase 8 release while any skip remains.

An existing NFS gateway upgrades only through a quiesced outage. First drain
and fence NFS, set `deployment.quiesced=true`, and wait for the old Pod and RWO
tailstate attachment to terminate. Record the existing VFS Service ClusterIP,
apply the split topology while both StatefulSets remain at zero, verify its
generation-bound selectors and PVC ownership, then unquiesce. Relay-only
restart does not advance the gateway epoch; backend restart retains the
existing drain and epoch behavior. A failed cutover leaves NFS disabled or
quiesced with both PVCs retained. Rolling back to the co-located topology with
NFS enabled is unsupported.

The NFS identity-approval cutover runs only while NFS admission and gateways
are disabled. Apply `000015_nfs_mapping_target_approval.sql` and its reviewed
grants, verify that every formerly active mapping is quarantined and every
dependent credential, policy, and session is fenced, then roll only binaries
that use the approved-active mapping projection. Administrators must create
fresh proposals and targets must approve them through Mount Settings; there is
no grandfathering, override, email, push, or notification-service dependency.
Do not restore an older direct-activation API binary after the migration.

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
Collaboration remains disabled by default. Its `yjs-v1` decoder dependency is
a risk-accepted operator opt-in under the single-target, exact-version fuzz
quarantine tracked by [issue 10](https://github.com/OxiBelt/FileBelt/issues/10).
The quarantine preserves the existing resource ceilings and stable/ASan smoke
coverage while substituting an exact dependency sentinel for this target's
sustained campaign; it is not a protocol change or a claim of remediation. A
dependency identity or quarantined-target change requires review. Clearance
requires the tracker gates, private snapshot/live-update regressions, and the
full sustained campaign against a reviewed later distribution.
WebTransport is not part of the Phase 5 baseline. Its reviewed Phase 8 route is
separately opt-in and falls back to WebSocket. On a fault, stop new grants,
drain connections, fence rooms, and preserve dirty manifests
for review; never
acknowledge an update from an event or in-memory replica state.

Phase 6 mount rollout remains gated. Apply the forward migration series through
`000023` with reviewed VFS, Headscale, and NFS-approval grants first. Keep
credential creation and revocation quiesced until every API replica uses the
transaction-bound credential cancellation fence; an older API can report an
unsafe absence before an in-flight create commits. Provision
`mount-storage` signing and mount-vault secrets, render the chart with all
protocol flags false, and verify that API/I/O have no new payload or database
authority. Verify the NFS legacy-mapping quarantine and approved-active
projection before any gateway rollout. Do not enable the
preview until separately reviewed GPL image builds, corresponding-source
offers, Samba authentication/session IPC, explicit-FTPS listener integration,
two-user Virtual ACL/revocation tests, tailnet device fencing, and live
Calico/Cilium policy tests all pass. NFS additionally requires the qualified
single-active image ABI, target-approval and revocation evidence,
stable-handle/reclaim evidence, automatic preStop drain, recovery-state
restoration, and exact gateway attestation tests.
Rollback disables gateway admission first, advances gateway epochs, closes
sessions/handles/locks, then scales the selected gateways, VFS, and (when
present) Headscale sync to zero. Keep the additive schemas, KEKs, and every admitted
`mount-storage` public key while retained state or recovery evidence references
them. Keep proposal and approval history and the database approval gate;
rollback never restores direct mapping activation.
The additive credential-operation fence and insert trigger also remain in
place. Do not re-enable credential routes on a rolled-back API that cannot
establish a durable missing-credential cancellation barrier.

Phase 7 document rollout is also staged and disabled by default. First apply
migration `000006`, expand built-in ACL presets under the statement-scoped
generation trigger, apply reviewed grants, add the purpose-tagged
`document-storage` public keyset to I/O, and run grant/schema plus
recovery-checkpoint verification
while `documents.enabled=false`. Then deploy the Apache document coordinator,
test exact-version range read, revision finalize/fsync, duplicate callback,
lost-response reconciliation, ACL/session revocation, and concurrent-head
conflict without an adapter. Only after those pass may an operator install the
separate adapter chart with an admitted AGPL adapter-image digest and exact
source link, provider `9.4.0`, outbox/browser secret generations, mTLS
identities, and egress target. For a deployment that ever exposed the former
public-origin launcher, stop document admission and old binaries before the
cutover. Apply forward migration `000010` for every deployment, verify its
receipt and audit counts, and require affected users to authenticate again.
Provision the distinct editor DNS name and one
FileBelt TLS certificate whose SANs cover both FileBelt hosts, then enable the
two disjoint OxiBelt virtual hosts last. Before user traffic, verify a real
digest-pinned ONLYOFFICE Community `9.4.0` DOCX/XLSX/PPTX flow for two users in
Chromium and Firefox, including the exact CSP sandbox and download, print, and
popup behavior. A contract-faithful fixture alone is insufficient.

Rollback removes the OxiBelt adapter route and stops new launches first, then
drains the adapter and fences active document sessions before scaling the
document coordinator to zero. Preserve finalized checkpoints/conflicts and
continue maintenance/recovery with the previous compatible core images. Do not
drop `filebelt_document`, reverse migration 000006, remove a
`document-storage` keyset generation while an unexpired claim or recovery record
references it, or relabel the
AGPL image as Apache. Migration 000010 is forward-only: never restore the old
public-host launch route or a binary that can mint it while documents are
enabled. If provider-script compromise is suspected, keep reauthentication
blocked and rotate the FileBelt public origin under the incident procedure
before admitting users. FileBelt remains fully usable through ordinary Web,
Markdown, MCP, and disabled mount paths throughout this rollback.

Phase 4 rollout is staged. First apply the forward MCP migration and reviewed
role grants, provision the broker database/vault/gateway/mTLS inputs, validate
the current format-9 configuration with its independent API-MCP-delegation
purpose, and take a coordinated recovery-v4 checkpoint. Enable the broker
without runners, test one personal registration, discovery, explicit approval,
version-pinned attachment, revocation, and cross-user denial, then admit normal
MCP traffic. Enable the controller and runner only in a later revision after
catalog/Sigstore verification, namespace RBAC, Kubernetes-API egress, runner
quotas, cleanup, and gateway policy pass. No step combines owner grants,
credential rotation, broker rollout, and runner activation.

Rollback disables runner admission first, cancels active invocations, waits for
the controller to remove one-shot Pods and bootstrap Secrets, and then disables
the broker. After v9 admission, configuration and keyset repair is forward-only:
retain purpose-specific immutable Secret generations and use a compatible v9
ConfigMap revision only. Do not drop `filebelt_mcp` or `filebelt_mcp_vault`, run
a down migration, roll back to a v8 configuration, or remove a KEK generation
referenced by a `filebelt.recovery.checkpoint.v4` document.

When compatibility cannot be proved, remain quiesced and restore the last
coordinated checkpoint into fresh targets before migrating forward.

Revision comparison limits are part of the format-9 deployment contract.
`revisions.limits.globalComparisons` defaults to `2` and accepts `1` through
`32`; `revisions.limits.perUserComparisons` defaults to `1`, accepts `1`
through `8`, and must not exceed the global value. The Git chart values
`limits.maxConcurrentPrivateRequests` and
`limits.maxConcurrentGitProcesses` default to `8` and `2`, accept `1` through
`64` and `1` through `16` respectively, and the Git-process limit must not
exceed the private-request limit. The Git chart projects those values as the
adapter `serve` flags `--max-concurrent-private-requests` and
`--max-concurrent-git-processes`; the Apache chart projects the coordinator
values under `[revisions.limits]` as `global_comparisons` and
`per_user_comparisons`.

Roll out the Apache core and private protocol support before deploying an
adapter that can emit the new admission result. Rollback reverses that order:
restore the compatible adapter before removing core support. A limit-only
rollback restores the preceding validated limits and drains normally; it does
not require a migration or alter PostgreSQL, payload, Git, or event state.
Revision activation remains disabled by default throughout this rollout.

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
