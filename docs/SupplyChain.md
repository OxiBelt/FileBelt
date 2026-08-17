<!-- SPDX-License-Identifier: Apache-2.0 -->

# Supply-Chain Policy

Rust and Node lockfiles are committed. Dependencies use reviewed registries and
exact versions; unpinned Git sources and unexpected lifecycle scripts are
blocked. Apache runtime graphs allow reviewed permissive licenses. MPL, CDDL,
LGPL, GPL, AGPL, native linkage, bundled source, and `*-sys` dependencies need
an explicit dependency, license, and architecture review recorded in the
admitting pull request.

Rust changes run `cargo audit`, `cargo deny`, and `cargo vet`. Node changes use
frozen pnpm installation with scripts disabled, license admission, audit,
linting, typechecking, tests, and build checks. GitHub Actions are pinned by
commit and run with read-only permissions during pull-request validation.
The Node license admission step compares pnpm's resolved report with
`supply-chain/node-policy.toml` and fails closed on every unknown license.
Cargo Vet consumes locked public audit evidence from Google, Mozilla, the
Bytecode Alliance, ISRG, Zcash, Embark Studios, and the OxiBelt upstream
repository; locally asserted audits remain reviewable in
`supply-chain/audits.toml`. Updating imports changes the committed lock and is
a dependency-policy review, not an implicit network trust decision at build
time.

The root Cargo workspace and every independently locked media or adapter
workspace receive weekly Dependabot coverage. CI additionally runs `cargo
audit` and Cargo Deny's advisory, license, ban, and source policy against every
registered adapter lock and manifest. Cargo Vet uses the root Apache audit
store for both the root workspace and the independently locked Apache
media-protocol graph. Media keeps local Cargo Audit and Cargo Deny policies
with no root reachability exceptions. Adapter updates require their own license
and source-offer artifacts, but do not inherit root audit exemptions or receive
blanket Vet exemptions. Docker and Compose directories and the isolated ONLYOFFICE pnpm
lock are likewise discovered by a fail-closed coverage check. The ONLYOFFICE
launcher lock must remain dependency-free; adding a package requires a
separate adapter-local admission review before its frozen install may run.

Repository lint tooling is also lockfile-pinned. The root uses `eslint` 10.8.1,
`@eslint/js` 10.0.1, `typescript-eslint` 8.67.0, and TypeScript 6.0.3.
Formatting uses exact
`oxfmt` 0.63.0 with its registry-integrity-pinned optional native bindings.
Oxfmt and its bindings are MIT-licensed, declare no install-time lifecycle
scripts, run only while developing or validating source, and are not copied
into published browser or OxiBelt images. Every resolved license must remain admitted by
`supply-chain/node-policy.toml`. Rust production-package closures
and first-party features are independently reviewed in
`supply-chain/cargo-boundaries-v1.toml`; registered package and manifest pairs
are resolved against metadata and the locked tree without duplicating versions
in policy. This complements rather than replaces the exact lockfile, Cargo Vet,
Cargo Deny, and advisory checks: those controls admit the resolved dependency
graph, while the boundary policy verifies that first-party identity and license
direction have not been substituted by name.

Peer checks remain strict except for one exact compatibility admission:
`openapi-typescript@7.13.0` declares TypeScript `^5.x`, while FileBelt pins
TypeScript 6.0.3. `pnpm-workspace.yaml` therefore permits only that package and
peer-version pair after deterministic OpenAPI regeneration was verified with
TypeScript 6.0.3. Changing either exact version requires revalidating and
updating or removing the exception.

The browser packages use Vite `8.2.1` with TypeScript remaining at `6.0.3` and
Fluent UI React Components `9.74.6`. Vite reaches Rolldown `1.2.4` and its
optional platform bindings under MIT, plus Lightning CSS `1.33.0` and its
optional platform bindings under MPL-2.0. These registry-integrity-pinned
native packages declare no install-time lifecycle hooks, and FileBelt disables
all dependency script execution. They run only while building or testing the
browser bundle; neither their binaries nor Node modules are copied into the
published SPA or OxiBelt image. The Node policy admits every Lightning CSS
package by exact name and version rather than globally allowing MPL-2.0.
Changing Vite, Rolldown, Lightning CSS, a binding identity, native loading, or
the final-image copy boundary repeats the source, license, architecture,
vulnerability, and notice review.

Vite 8's test server does not add the missing `.js` suffix to one exact
`@fluentui/react-icons` ESM edge. Fluent-consuming Vitest configurations inline
that package and a serve-only resolver maps only `lib/providers.js` importing
`./contexts/index` to the already shipped `contexts/index.js`. It does not
patch dependencies or affect production builds. Remove the workaround when
Fluent ships the suffix or Vite resolves the edge, and keep a regression test
that rejects unrelated importers and specifiers.

The development-only Vite graph pins `postcss>nanoid` to exact
`nanoid@3.3.18`. FileBelt does not import Nano ID, and the resolved PostCSS
path uses `nanoid/non-secure` with a fixed size rather than the React Native
async custom generator affected by `GHSA-2v37-7h3g-55p8`; the patched release
is still required because Node advisory admission fails closed. Version 3.3.18
retains the reviewed MIT license and introduces no dependency, lifecycle
script, native-code, or engine change. The Vite 8.2.1 graph retains
`postcss@8.5.25` and the same non-secure entrypoint. Changing Vite, PostCSS, the
Nano ID entrypoint, or its runtime reachability invalidates this review. Remove
the override only when the exact locked graph remains outside the advisory
range and the frozen install, license, audit, test, and build gates pass.

### Cargo Vet acceptance baseline

`supply-chain/config.toml` contains a generated, minimal baseline for the exact
third-party crate versions in `Cargo.lock`. Each exemption is limited to one
crate version and `safe-to-deploy`; the configuration does not trust publishers
or use wildcard version ranges. These records document acceptance of the
current locked graph. They are not source audits and do not claim that FileBelt
or an imported auditor reviewed every line of each crate.

`cargo vet --locked` fails when a new crate or version lacks imported audit
evidence, a local audit, or a deliberately reviewed exact exemption. Reviewers
must inspect `cargo vet suggest`, the dependency purpose and features, native
or build-script behavior, maintenance, and license and vulnerability results
before updating the baseline. Prefer replacing exemptions with reviewable
audits as that evidence becomes available. `cargo audit`, `cargo deny check`,
the exact Cargo lockfile, and the locked import set remain independent required
controls; an exemption weakens none of those gates.

The fuzz-only graph pins `cargo-fuzz 0.13.2`, `libfuzzer-sys 0.4.13`, and the
transitive `arbitrary 1.4.2`. Complete checksum-matched local audits admit the
two crates only for `safe-to-run`; `filebelt-fuzz` policy does not promote that
criterion to deployment. The bundled native libFuzzer runtime therefore never
enters a FileBelt image or deployed package. `libfuzzer-sys@0.4.13` has one
exact Cargo Deny exception for its NCSA portion; NCSA is not globally admitted.
Changing either version, feature set, build script, bundled C++ source, runner
environment, or deployed-graph reachability invalidates this review. The full
program and private crash-input handling are documented in [Fuzzing](Fuzzing.md).

## Phase 2 dependency admission

Phase 2 retains exact Cargo and pnpm resolution and adds runtime dependencies
only after source, feature, native-link, license, vulnerability, maintenance,
and three-architecture review. OIDC, database, and first-party Rust HTTP TLS
use Rustls with the AWS-LC provider and Ed25519. The exact optional Iggy 0.8.0
client is an explicit upstream exception that also links Ring for its
notification-only transports; Iggy remains outside authorization and
durability correctness. Admission evidence includes every enabled Cargo feature,
`build.rs` output, bundled source, `*-sys` crate, compiler/linker input, final
ELF dependency, license/notice, and RISC-V musl bindgen requirement. Embedded
public WebPKI roots and an optional mounted custom CA bundle are the only trust
root sources.

The optional OTLP trace path uses one coordinated, exact family:
`opentelemetry@0.32.0`, `opentelemetry-http@0.32.0`,
`opentelemetry-otlp@0.32.0`, `opentelemetry-proto@0.32.0`,
`opentelemetry_sdk@0.32.1`, and `tracing-opentelemetry@0.33.0`. The SDK floor
includes the bounded W3C Baggage parser from GHSA-w9wp-h8wv-79jx. OTLP's HTTP
client uses an isolated `reqwest@0.13.4` workspace alias with blocking Rustls
and no default features; OIDC and the other application clients retain the
reviewed `reqwest@0.12.28` API. FileBelt overrides the compiled platform
verifier with an AWS-LC Rustls configuration containing only the embedded
WebPKI roots plus the optional operator CA. FileBelt installs no inbound
OpenTelemetry propagator, so public trace and baggage headers never become
parent context.

The resolved graph admits two non-baseline license families with narrow,
recorded reasons. `webpki-roots` and `webpki-root-certs` carry
`CDLA-Permissive-2.0` certificate data used by Rustls clients. The exact Iggy
client reaches unmodified `option-ext@0.2.0` under `MPL-2.0`; FileBelt does not
copy or modify that crate, and binary distributions retain its license and a
corresponding-source pointer to the exact crates.io archive. These admissions
do not change the Apache-2.0 license of FileBelt source, but final-image labels,
notices, and SBOMs must include the resolved runtime composition.

`RUSTSEC-2023-0071` is ignored only for `rsa@0.9.10` reached through
`openidconnect@4.0.1`: FileBelt verifies public issuer signatures and never
loads or operates on an RSA private key, so the advisory's private-key timing
sink is absent. A change that introduces RSA signing/decryption or swaps the
OIDC library invalidates this reachability exception.

`RUSTSEC-2026-0235` is reached only through Iggy's byte-unit formatting graph.
FileBelt is producer-only and never constructs, accepts, or validates an rkyv
archive, including an archive containing `Rc` or `Arc`; therefore the affected
archive-validation entry point is absent. Enabling an Iggy consumer, using
rkyv serialization, or changing the Iggy client invalidates this exception.

OpenAPI 3.1 and Protobuf schemas are committed inputs. Generated Rust and
TypeScript clients record source, exact generator, regeneration command, and
license, and `check-generated.py` fails a drifted tree. Browser packages use
frozen pnpm installation with lifecycle scripts disabled; a required script is
an explicit, narrowly reviewed exception rather than an install default. The
Node allowlist admits `0BSD` specifically for Fluent UI's resolved
`tslib@2.8.1` runtime helper; that package remains lockfile-pinned and is not a
general exception for unreviewed browser dependencies. It also admits the
exact SPDX choice `(MIT OR CC0-1.0)` for `type-fest@4.41.0`, reached only by the
lockfile-pinned OpenAPI TypeScript generator; FileBelt elects its MIT option and
does not ship that development-only package in the browser image.

The immutable external integration inputs are:

| Input | Accepted version and digest | Distribution role |
| --- | --- | --- |
| OxiBelt | `0.7.1-beta.2`, `ghcr.io/oxibelt/oxibelt@sha256:e8556a0103feff47bf6135062e70e980e000176598fd438959ea55d99c844030` | Base of `filebelt-web`; prerelease exception |
| PostgreSQL | `18.6`, `docker.io/library/postgres@sha256:ae6c78831cbc35fa3a4aaf4d763ddacf6183d6004774cc2dc28b3920410d1d1a` | Docker integration helper only |
| Apache Iggy | `0.8.0`, `docker.io/apache/iggy@sha256:99b42016a898381d4bab3c2d4613456eb04ad06a7a0688314823d798a685636b` | Optional Docker integration helper only |
| Iggy Rust client | exact crate `0.8.0` | Optional notification publisher/consumer |

Changing one of these versions or digests requires a focused dependency
review. OxiBelt review repeats source-revision, prerelease rationale, route
behavior, architecture, SBOM, vulnerability, license, and notice checks.
FileBelt never copies from or builds the local reference checkout. PostgreSQL
and Iggy helpers are not republished as FileBelt images.

The pinned Iggy helper alone receives its documented `SYS_NICE`, unlimited
memlock, and seccomp exception. Image and Compose contract tests fail if that
exception reaches a FileBelt container or another profile service.

## Phase 4 MCP dependency admission

Phase 4 admits `rmcp@3.1.2` with default features disabled for bounded MCP
model decoding and `sigstore-verify@0.11.0` with default features disabled for
offline runner-catalog verification. They are lockfile exact. The broker still
owns HTTP transport, size/deadline enforcement, egress-gateway routing,
authorization, and result validation; the MCP library does not receive a
browser session, payload path, vault keyring, or unrestricted connector. The
controller verifier reads only an operator-projected trusted root, catalog, and
bundle directory. It permits no online trust-root or transparency-log lookup
at admission time.

The catalog format is schema version 1, at most 1 MiB and 128 entries. Its
trusted-root document is at most 2 MiB and each Sigstore bundle at most 4 MiB.
Every entry binds a lowercase allowlisted registry repository, SHA-256 image
digest, HTTPS source, declared license, absolute command and bounded arguments,
supported architecture set, egress profile, resource quantities, and exact
signature identity/issuer. Bundle paths are canonicalized below the configured
directory. Catalog, root, bundle, image, or policy changes are supply-chain and
deployment-authority changes, not runtime user configuration.

FileBelt deliberately accepts a narrower trust-root profile than the generic
Sigstore verifier. The projection must contain exactly one bounded Fulcio CA,
one bounded Rekor key, and one bounded CT key, with explicit start and end
times, and no TSA authority. A bundle must contain exactly one Rekor v1 entry
with both an inclusion proof and promise, a positive integrated time, and the
exact projected Rekor log ID. That authenticated integrated time must fall
inside all three authority windows and must be the verifier-selected time with
no warnings. Rotations atomically replace the root and catalog bundles; they do
not introduce overlapping authority sets. This wrapper is required because the
admitted verifier version does not itself associate every pooled authority
window with the material it selected.

The browser workspace pins `@playwright/test@1.62.1` for Chromium and Firefox
security-flow coverage. It remains development-only and installs browsers only
in the test environment. `openapi-typescript@7.13.0` remains the sole
deterministic public-client generator; Phase 4 regeneration covers all MCP
personal, administrative, intent/approval, OAuth, and data-grant schemas.
Generated output is committed and drift checked.

Phase 5 admits `officeparser@7.6.2` only through its browser `slim` entry point
for the bounded local Office-to-Markdown proposal path. Its transitive
`tesseract.js@7.0.0` postinstall remains disabled by the empty lifecycle-script
allowlist and `pnpm --ignore-scripts`; FileBelt does not enable OCR, download
language data, extract attachments, or fetch remote document assets. The
lockfile-pinned package and its transitive `pdfjs-dist` and Tesseract/WASM
artifacts remain subject to the license, audit, bundle, and browser-boundary
checks. No Node lifecycle exception is admitted.

The Phase 5 Markdown bundle selects DOMPurify's Apache-2.0 branch from its
`(MPL-2.0 OR Apache-2.0)` distribution and admits `robust-predicates@3.0.3`
under the Unlicense. `khroma@2.1.0` ships an MIT license file but omits a
package metadata field, so the policy records an exact package-and-version MIT
correction; an `Unknown` license remains a failure for every other package.

The collaboration image admits Yrs `0.27.3` and the exact CRDT-support graph
through local `safe-to-deploy` audits, not Cargo Vet exemptions. The WebSocket
support graph is audited at its locked `tokio-tungstenite@0.29.0` and
`tungstenite@0.29.0` versions. These audits are evidence for the exact source
and features in `Cargo.lock`; an update requires a new review.

The ten-image plan adds `filebelt-collaboration` to the prior nine roles. Nine
roles are deployable and publishable; the media controller remains probe-only.
Collaboration, broker, and controller use
`Apache-2.0 AND MIT AND CDLA-Permissive-2.0`; runner uses
`Apache-2.0 AND MIT`. SBOM, notices, Cargo Vet, Cargo Deny, advisory, native
linkage, and three-platform evidence apply independently to each role. A
third-party catalog server is never promoted as a FileBelt image and must carry
its own license, notices, source, signature, digest, and vulnerability review.

## OCI evidence

Phase 1 image builds use digest-pinned Dockerfile frontends and bases and create
local Docker image archives only. Each of the ten image roles is checked against an
immutable plan containing its repository, version, source revision and ref,
build kind, license, platform, and canonical `x86-64-v3` AMD64 baseline. The
core plan is schema v2; separately governed adapter plans are schema v3. New
validators reject earlier schemas, whose releases retain their matching old
tooling and evidence. The archive must contain the corresponding
static Rust probe or web assets, the expected license evidence, numeric
user/group `10001:10001`, and the complete OCI label contract from the
[runtime and deployment specification](RuntimeAndDeployment.md).

Native Rust builds install exact binutils, GCC, musl, musl development, and
musl-tools package versions from immutable Debian snapshot
`20260713T000000Z`. RISC-V uses the digest-pinned cross-toolchain recorded in
`supply-chain/tooling.toml`. Its AMD64-hosted builder also installs the exact
CMake, Clang/libclang, and Ninja versions recorded there from the same
snapshot. A tracked Apache-2.0 CMake toolchain file binds AWS-LC compilation
and bindgen to the copied RISC-V musl compiler and sysroot. The build fails
before Cargo unless the compiler version, target triple, linker version, and
compiler digest match the admitted cross-toolchain identity. A live package
mirror or an unversioned toolchain package is not an admitted build input.

Each role/platform archive produces:

- a SHA-256 archive checksum and machine-readable artifact contract;
- a normalized CycloneDX JSON SBOM scoped to that platform;
- a Trivy `0.74.0` JSON vulnerability report and policy decision; and
- extracted image metadata used by static, identity, and smoke checks.

AMD64 source builds are v3-only. Rust receives
`-Ctarget-cpu=x86-64-v3`, C/C++ receives `-march=x86-64-v3`, and final links
receive GNU `-z x86-64-v3`. Static validation parses ELF program notes and
requires the GNU `x86-64-v3` ISA-needed property, with only the optional
redundant baseline bit, for
every FileBelt-built AMD64 executable or shared object in scope. It does not
infer the baseline from disassembly. ARM64 and RISC-V remain
`architecture-default`.

Static Rust SBOMs are augmented from the immutable image plan with the exact
FileBelt Cargo application and per-platform Rust standard-library, musl,
compiler, and linker inventory.
The CycloneDX subject also records `io.filebelt.build.target-cpu` and the
canonical plan SHA-256; the OCI image and versioned build/validation receipts
carry the corresponding exact platform value.
Every entry records its package URL, version, license, relationship, standard
CycloneDX scope, and immutable evidence source. A Rust SBOM must contain both
runtime and build-tool records; an empty or partial inventory fails even when
Trivy reports no package records for the `scratch` filesystem. Runtime records
use `required` scope, while build tools use `excluded` scope and are omitted
from the image subject's dependency edge. RISC-V CMake, Clang/libclang, and
Ninja records are build-only evidence and are never copied into the final
scratch image, so they do not change its license expression or notices. Rust
images use the aggregate license expression `Apache-2.0 AND MIT` and ship
upstream Rust and musl copyright manifests. The Phase 1 static web artifact
remained `Apache-2.0` and excluded those Rust-only notices; the current
OxiBelt-derived composition is defined in the
[license map](LicenseMap.md#runtime-composition).

Unexcepted `HIGH` or `CRITICAL` vulnerabilities fail the gate. Exceptions in
`supply-chain/image-vulnerability-exceptions.json` must match the role,
platform, advisory, package, installed version, and target exactly, include a
rationale, and expire within 90 days. Missing or malformed scanner output fails
closed. The normalizer emits a runtime-only CycloneDX derivative that excludes
build-tool records and identifies the exact executable as a Cargo scan target.
Trivy scans that derivative, while the linked musl and Rust standard-library
records remain explicit SBOM components without treating compilers as shipped
packages. A Rust scan with no target or Cargo package inventory fails closed,
while the static web role may truthfully produce an empty package report.
Normalized rebuild verification compares the root filesystem, modes, numeric
ownership, selected image config and labels, embedded identity, and SBOM
content while excluding archive transport bookkeeping.

For Phase 2, `filebelt-api`, `filebelt-worker-io`,
`filebelt-worker-maintenance`, `filebelt-tools`, and `filebelt-web` replace
their probe contracts with role-specific runtime contracts. Evidence adds:

- the typed configuration-schema identity and public-origin/secret-file checks;
- exposed ports, required networks, mounts, writable paths, and dropped Linux
  capabilities;
- the absence of payload storage from the API and of signing keys from the I/O
  worker;
- the native crypto provider, final ELF linkage, trusted-root inputs, and
  per-platform build provenance;
- role-specific health, configuration failure, non-root startup, and clean
  shutdown; and
- the exact OxiBelt base/source/route relationship for `filebelt-web`.

The OxiBelt relationship is admitted offline through
`supply-chain/oxibelt-admission-v1.json` and the retained index and AMD64-child
GitHub/Sigstore rebuild bundles. Admission verified the public-good signature,
GitHub-hosted runner, `OxiBelt/OxiBelt` release workflow identity, tag, and
source revision. Routine checks use the retained raw OCI manifest subjects and
Sigstore trusted-root snapshot to repeat the signature, certificate identity,
OIDC issuer, transparency-log, source, and runner-policy verification without a
network lookup. They also bind retained bundle and trusted-root hashes, decoded
predicates, the index-to-child digest, child `targetCpu: x86-64-v3`, and the
admitted index directly to the `ui/web/Dockerfile` base.

The media-controller image remains probe-only and its evidence must continue to
say so. Broker, controller, and runner evidence instead proves their active
runtime modes, listeners, database/mount/Secret boundaries, mTLS identities,
gateway-only egress, and restricted one-shot Pod contract. Rust and
OxiBelt-derived images use the role-specific aggregate expressions in the
license map: WebPKI consumers include CDLA, Iggy-client roles also include
MPL-2.0, and the web role includes ISC and 0BSD. Every upstream copyright and
notice discovered from the final image and dependency graph is shipped and
mapped to the SBOM.

AMD64 and ARM64 run native runtime and Docker behavior tests. The AMD64 host
checker evaluates every processor stanza before native image, rebuild, adapter,
and NFS execution and emits a bounded report without raw CPU flags. A separate
digest-pinned Kubernetes DaemonSet check covers every selected schedulable
AMD64 node; neither check qualifies an unobserved remote Docker daemon or
cluster. RISC-V
cross-compiles and runs bounded rootless-QEMU smoke tests, including native
crypto initialization. The official Iggy helper is not required on RISC-V;
that job validates the PostgreSQL polling fallback and must not substitute an
unreviewed Iggy image.

The read-only pull-request matrix validates all roles on native AMD64 and
ARM64. Default-branch, scheduled, and manual checks also validate RISC-V by
cross-compiling the static probes and running the extracted binaries in a
rootless, digest-pinned QEMU helper container. The release dry run covers all
27 role/platform combinations and an AMD64 normalized rebuild.

No Phase 1 or Phase 2 workflow has package, release, or attestation write
permission.
Archives and reports are downloadable CI evidence, not published releases.
Signed release tags are verified in a temporary keyring containing only the
[tracked authorized signers](../supply-chain/release-tag-signers/README.md),
and the tag must peel to the checked-out source revision.
At the Phase 1 and Phase 2 boundary, publication remained deferred to a
separate least-privilege job that would consume already validated artifacts,
attach GitHub artifact attestations, verify the pushed digest, and avoid
rebuilding. The current tag-only promotion contract is described below. Native
smoke tests remove the archive tag they load, and
RISC-V smoke tests remove their temporary helper image, so the matrix leaves no
role or helper tag in the local daemon. At that boundary there was no registry
artifact to revoke.

Database volumes, payloads, backups, test user data, TLS keys, OIDC credentials,
cookies, CSRF tokens, capabilities, and signing/hash keysets never enter build
contexts or retained evidence. Docker and browser logs redact these values.
Fault and restore artifacts are sensitive local test output and use
deterministic cleanup.

Docker integration consumers verify the current-revision AMD64 archive and its
checksum, build/evidence metadata, validation, smoke result, vulnerability
decision, and nonempty build/runtime SBOMs before `docker load`. They may build
only the digest-pinned OIDC and MCP test fixtures; FileBelt subjects are never
rebuilt. Collaboration installs frozen pnpm dependencies without lifecycle
scripts and uses the lockfile-pinned Playwright package with Chromium and
Firefox. Retained failure artifacts contain only bounded scrubbed logs and
synthetic screenshots for 7 days on pull requests and 30 days otherwise.

## Phase 5 Kubernetes and publication evidence

Phase 5 uses a ten-image build and evidence matrix and admits nine
deployable/publishable roles: API, I/O, maintenance, collaboration, MCP broker,
controller, runner, tools, and web. The media controller remains probe-only, has no Helm
workload, and is not promoted to GHCR. MCP broker and controller workloads and
one-shot runner Pods are separately disabled by default. The Helm chart creates
no PostgreSQL, Iggy, OIDC, egress gateway, certificate issuer, monitoring stack,
Secret, or PVC; cluster-test fixtures retain their upstream names, licenses,
and immutable digests and are not FileBelt release artifacts.

The exact OxiBelt prerelease admitted above remains the current immutable input,
and its separate outbound client-certificate behavior for each upstream is
covered by edge and Kubernetes acceptance. Before the FileBelt pin changes,
its source revision, prerelease rationale, route/cache/retry behavior,
server-name validation, client-key handling, architecture set,
license/notices, SBOM, and vulnerability evidence are reviewed again. FileBelt
does not copy from or build the local reference checkout.

Kubernetes acceptance uses digest-pinned Kind node images for the supported
1.34, 1.35, and 1.36 lines; pinned Minikube, kubectl, Helm, CNI, fixture, and
probe inputs; locally loaded validated FileBelt archives; deterministic
namespaces; and ownership-checked cleanup. Test-only fault-injection builds are
never publishable, and production archive validation proves that their control
surface is absent.

A dedicated tag-only release workflow may hold write permission only in its
promotion job. It verifies an authorized signed annotated SemVer tag, consumes
the same-run validated per-platform archives without rebuilding, assembles and
pushes immutable multi-architecture manifests, publishes the versioned Helm OCI
artifact, attaches GitHub build-provenance attestations, and reads every digest
back. It creates no `latest` or other mutable alias. Pull-request, manual, and
ordinary default-branch jobs remain read-only.

The Helm chart is published at `oci://ghcr.io/oxibelt/charts/filebelt`. Its
`version` and `appVersion` match the release tag. The GitHub Release contains
the exact chart package, checksums, admitted SBOM/evidence, and a checksummed
PostgreSQL administrator bundle containing the canonical role/grant scripts.
Registry subjects and release assets contain no database URL, Secret, backup,
payload, test identity, cookie, capability, private key, or unredacted cluster
diagnostic.

Artifact rollback selects a previous verified digest. The project does not
move version tags or automatically delete packages/attestations; a compromised
artifact is withdrawn only through a separately reviewed administrator
incident procedure and replaced by a new SemVer release.

## Phase 7 document and ONLYOFFICE evidence

Phase 7 adds the Apache `filebelt-document` role to the native image matrix.
It follows the same amd64, arm64, and RISC-V build, ELF/native linkage, SBOM,
Trivy, normalized rebuild, identity, notice, signature, and provenance policy
as the other WebPKI-enabled Apache roles. Its runtime contract additionally
proves that the image contains the provider-neutral service executable and
purpose-bound `document-storage` capability logic, exposes only the document listener, and has no
adapter source, browser bundle, provider asset, payload mount, Internet path,
or general API database credential.

`adapters/onlyoffice/` is an independent `AGPL-3.0-only` workspace and image
plan. Apache packages do not link or path-depend on it. Adapter evidence must
include its own Cargo and pnpm locks, license/notices, exact OCI source and
revision labels, immutable corresponding-source URL, build instructions,
source/about HTTP response fixture, SBOM, vulnerability report, signature,
provenance, and normalized amd64/arm64 rebuilds. RISC-V is explicitly
compile-and-probe-only and is not included in the adapter manifest. The image
contains no operator secret, provider database, DocumentServer binary,
provider connector, `api.js`, or other provider asset.

The adapter pins `hmac@0.13.0`, `sha2@0.11.0`, and `zip@8.6.0`. Their resolved
cryptographic and archive-support graph is limited to the exact permissively
licensed crates in `adapters/onlyoffice/Cargo.lock`; it adds no lifecycle
script, native linkage, provider code, or network fetch. The adapter's AGPL
corresponding-source bundle and SBOM include that exact lockfile and every
resolved crate and notice. Changing the digest implementation, archive
features, or extraction behavior repeats the callback-authentication,
malformed-document, license, and source-offer review.

ONLYOFFICE Docs Community `9.4.0` is an operator-supplied external process, not
a FileBelt build input or release subject. An operator records its exact image
digest, upstream source, notices, branding, and vulnerability review outside
the FileBelt adapter SBOM. FileBelt makes no cluster or paid-edition claim and
enforces the documented 20 active-connection ceiling before provider launch.
Release acceptance must exercise a real digest-pinned `9.4.0` Community image,
not only a contract-faithful fixture, in Chromium and Firefox through the
isolated editor hostname. The evidence records the provider digest, platform,
upstream source and notices, verifies the fixed launcher CSP sandbox, and covers
DOCX, XLSX, PPTX, download, print, and popup behavior without adding that
external image to a FileBelt chart, SBOM, or release subject.
Changing provider version or edition, copying provider JavaScript, embedding a
provider image in the chart, or changing the AGPL expression repeats the full
license, source, dependency, browser, threat-model, and release review.

The coordinated tag-only release publishes the Apache core chart and images.
Adapter charts are excluded from the core asset packager while their checked-in
values remain blocked. The release invokes a separate read-only reusable
adapter workflow that produces a schema-v2 six-role plan and pre-image
evidence; the existing release promotion job remains the only write-authorized
GitHub Release owner. It attaches the blocked adapter plan as review evidence
but does not publish adapter images or charts. The schema intentionally keeps
adapter publication blocked until a separately reviewed subject-map and
promotion implementation binds every platform archive, SBOM, provenance
statement, source bundle, registry digest, and readback result. No promotion
job may rebuild an adapter or publish DocumentServer.

Every adapter source archive is named
`filebelt-<role>-source-<version>.tar.gz`, contains one normalized root, and
uses release-commit mtimes, numeric zero ownership, sorted paths, and a
timestamp-free gzip header. The archive contains the complete tracked FileBelt
tree plus `SOURCE-MANIFEST.json`, offline build instructions, license and
notice inventories, upstream source, patches, build inputs, and the complete
Cargo vendor closure. The final archive hash is external evidence and never
self-references from its manifest. Archive validation rejects unsafe paths,
duplicates, mutable source URLs, checksum drift, missing vendor packages, and
image-plan revision or license mismatches.

`supply-chain/license-compatibility-v1.toml` is the directional policy source
of truth. The image gate requires seven independently qualified inputs:
source bundle, dependency compatibility, component policy, licenses/notices,
build inputs, immutable source, and build context. Blocked roles may retain a
source bundle, but they must have no image archive, image SBOM, provenance,
chart digest, promotion subject, or nonzero image digest. Once those seven
inputs qualify, `run-adapter-bundle-image.py` constructs the Docker context
only from the validated bundle and permits an OCI build; publication remains a
separate decision over security, functionality, native platforms, and the
currently unimplemented signed-tag adapter subject map.

## Phase 8 NFS, transcoder, and WebTransport evidence

The coordinated Phase 8 release adds separate NFS and transcoder adapter image
plans without merging their license or source evidence into Apache images. The
NFS image publishes native AMD64, ARM64, and RISC-V artifacts from the pinned
Ubuntu 26.04 snapshot and NFS-Ganesha `6.5-8`. Evidence includes the exact
package snapshot, dynamic FSAL ABI probe, LGPL source/replacement instructions,
bridge lockfile, Kerberos composition, runtime functional probe, normalized
SBOM, vulnerability result, source archive, provenance, and rebuild comparison.
The bridge pins `nix@0.31.3` with only `fs`, `socket`, `uio`, and `user`
features. This MIT-licensed Rust wrapper changes neither the Ganesha ABI nor
the dynamic LGPL relinking boundary; its exact source, lockfile, notice, and
SBOM entry remain part of the NFS corresponding-source evidence.

The transcoder image publishes native AMD64 and ARM64 artifacts. RISC-V is
compile/probe-only and cannot enter the manifest. Evidence locks FFmpeg
`8.1.2`, libaom `3.14.1`, libvpx `1.16.0`, Opus `1.5.2`, every configure flag,
enabled parser/codec/filter, Ubuntu package snapshot, VAAPI package/driver
identity, first-party wrapper lockfile, GPL source offer, notices, SBOM,
vulnerability result, malicious-input corpus result, provenance, and normalized
rebuild. Enabling `version3`, `nonfree`, an additional codec/filter/protocol,
static linkage, NVIDIA support, or a different upstream version repeats the
license and security review.

The Apache collaboration image admits the exact Quinn/h3 versions recorded in
`Cargo.lock` and keeps OxiBelt `0.7.1-beta.2` pinned by public source revision
and image digest. WebTransport evidence includes UDP service and route
identity, QUIC host-key lifecycle, Retry/0-RTT settings, browser parity,
loss/reconnect correctness, drain, CPU/memory comparison, and the required
latency improvement. The read-only local OxiBelt reference is never a build
input or release citation.

Performance evidence uses immutable configuration and output artifacts at
five-minute change smoke, 60-minute nightly, two-hour weekly, and 2.5-hour
pre-release cadences. The release gate rejects NFS/media regression above ten
percent against the accepted same-host baseline, WebTransport improvement below
15 percent against WebSocket in the specified loss/latency scenario, any
acknowledged loss or orphan, sustained memory growth above one percent per hour,
or settled descriptor/task growth above five percent.

Tag-only promotion consumes already validated artifacts, publishes distinct
role repositories and a digest-pinned chart, and never rebuilds in a
write-authorized job. CPU media and NFS are production subjects only after
their required evidence passes. VAAPI remains an explicitly experimental,
disabled value until real Intel/AMD device evidence is reviewed.

## Changing the policy

A dependency, toolchain, base image, feature, native linkage, license,
vulnerability exception, evidence format, or publication-authority change
requires an explicit supply-chain and architecture review in the same pull
request. Record rationale, alternatives, exact graph or artifact effects,
security and license impact, expiry where applicable, rollout, and rollback.
Update this policy, the [license map](LicenseMap.md),
[runtime specification](RuntimeAndDeployment.md), machine-readable admission
files, notices, and regression evidence with the change.
