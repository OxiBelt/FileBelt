<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0007: OCI build and release evidence

- Status: Accepted
- Date: 2026-08-06
- Owners: `@PiQuark6046`
- Reviewers: none
- Supersedes: none
- Affected license regions: Apache-2.0 source and Apache-2.0 AND MIT Rust images

## Context

ADR-0006 reserves seven Apache image roles and requires evidence before an
image may be published. Phase 1 must make that evidence reproducible without
granting a pull request or ordinary build job the ability to write packages,
create releases, or mint attestations. It must also exercise all promised
architectures without registering persistent host emulation.

The Phase 1 applications are buildable identity probes rather than usable
services. PostgreSQL-backed state, authorization enforcement, health endpoints,
and Kubernetes workloads do not exist yet. A successful image build therefore
must not be interpreted as runtime readiness.

## Decision drivers

- Bind every archive and evidence file to one role, source revision, version,
  platform, license, and build kind.
- Exercise the promised platform matrix without giving untrusted changes a
  package-write or host-privilege path.
- Make vulnerability exceptions precise, expiring, and reviewable.
- Detect meaningful rebuild drift while ignoring container-archive transport
  details that do not change the runnable filesystem or declared identity.
- Preserve the Apache-only image boundary and truthful source/license mapping.

## Decision

### Roles, repositories, and contents

Phase 1 builds exactly these Apache image repositories:

| Role | Repository | Contents |
| --- | --- | --- |
| `filebelt-api` | `ghcr.io/oxibelt/filebelt-api` | Static Rust identity probe |
| `filebelt-worker-io` | `ghcr.io/oxibelt/filebelt-worker-io` | Static Rust identity probe |
| `filebelt-worker-maintenance` | `ghcr.io/oxibelt/filebelt-worker-maintenance` | Static Rust identity probe |
| `filebelt-media-controller` | `ghcr.io/oxibelt/filebelt-media-controller` | Static Rust identity probe |
| `filebelt-mcp-broker` | `ghcr.io/oxibelt/filebelt-mcp-broker` | Static Rust identity probe |
| `filebelt-tools` | `ghcr.io/oxibelt/filebelt-tools` | Static `filebeltctl` identity probe |
| `filebelt-web` | `ghcr.io/oxibelt/filebelt-web` | Static web and Markdown package output |

The Rust images use a statically linked musl executable in a `scratch` final
stage. The web image is a static artifact and intentionally has no server or
entrypoint. All seven final image configurations declare numeric user and group
`10001:10001`. They include only the role artifact, required license/notices,
and minimal identity files needed by their probe contract. The controller,
integrated binary, adapters, and transcoder remain outside this matrix.

Native Rust builds resolve musl and binutils only from Debian snapshot
`20260713T000000Z` and install exact admitted package versions. The RISC-V
cross-toolchain is selected by immutable image digest; its build log records
musl `1.2.5`, GCC `14.3.0`, and binutils `2.45`. The admitted builder,
snapshot, package versions, and cross-toolchain digest are recorded in
`supply-chain/tooling.toml`; live distribution mirrors and unversioned package
installation are not build inputs.

All seven roles declare `linux/amd64`, `linux/arm64`, and `linux/riscv64`.
AMD64 and ARM64 validation is native. RISC-V is cross-compiled and its extracted
static executable is invoked by a digest-pinned QEMU helper container without
host `binfmt_misc` registration. The web role is checked as static content and
does not claim an executable smoke probe.

### Version and source identity

Stable and prerelease source tags are signed, annotated Git tags whose text is
the exact SemVer version without a `v` prefix. Dry-run archives use the
immutable development form `0.1.0-build.<sha12>`, where `<sha12>` is the first
12 lowercase hexadecimal characters of the source commit. No mutable
`latest`, major, minor, branch, or platform alias is created.

Release-tag verification uses only the public keys and primary fingerprints in
the tracked release-signer allowlist. CI imports those keys into an empty
temporary keyring, requires exactly one valid signature certified by an
allowlisted primary key, and requires the annotated tag to peel to the exact
checked-out revision. Signer rotation is an explicit release-authority change,
not a network lookup performed during a release job.

Rust probes implement only two successful invocations: `--version` and the
deterministic `--build-info=json`. Unsupported arguments, missing runtime
configuration, and attempted service startup fail nonzero; Phase 1 does not
invent health or long-running behavior. Embedded build information and image
labels use explicit version, revision, source ref, dirty state, and build kind.
A release identity must name an exact signed release tag and a clean tree.

Each image config carries these labels:

- `org.opencontainers.image.title`
- `org.opencontainers.image.description`
- `org.opencontainers.image.source`
- `org.opencontainers.image.url`
- `org.opencontainers.image.version`
- `org.opencontainers.image.revision`
- `org.opencontainers.image.created`
- `org.opencontainers.image.licenses`
- `io.filebelt.image.role`
- `io.filebelt.build.source-ref`
- `io.filebelt.build.dirty`
- `io.filebelt.build.kind`

`org.opencontainers.image.licenses` is `Apache-2.0 AND MIT` for Rust roles,
reflecting Apache FileBelt code and the linked Rust/musl runtime selection. The
web role remains `Apache-2.0` and does not ship Rust-specific notices. Each
Rust image includes the exact Rust 1.97.1 library copyright manifest and the
tracked upstream musl 1.2.5 copyright manifest, plus the Apache-2.0 and MIT
license texts. The source and URL labels point to the public FileBelt
repository, and the role label must agree with the build plan and archive
contents.

### Evidence and failure policy

Every platform archive produces an artifact contract, archive digest, build
metadata, a CycloneDX JSON SBOM, and Trivy vulnerability JSON. SBOMs describe
one platform archive; Phase 1 does not synthesize an index-level SBOM. Trivy
`0.73.0` is the only admitted vulnerability scanner for this gate.

Because package scanning a static `scratch` filesystem can return no package
records, every Rust plan row also carries its exact FileBelt Cargo application
and a per-platform inventory of the linked Rust standard library and musl
runtime plus the compiler and linker toolchain that produced them.
Normalization adds those records to the CycloneDX document with standard
`required` runtime or `excluded` build-tool scope and explicit relationship
evidence. Missing, empty, duplicate,
malformed, or relationship-incomplete Rust inventories fail closed. Build
tools are recorded as evidence but are not declared as runtime dependencies of
the image subject. Normalization also emits a runtime-only CycloneDX derivative
without excluded build tools and adds a structural Cargo scan target for the
exact executable path. Trivy scans that derivative, and a Rust report without
a nonempty target and scanned Cargo package inventory fails closed; an empty
package report is allowed only for the static web role.

An unexcepted `HIGH` or `CRITICAL` result blocks validation. An exception must
match the target, advisory, package, installed version, role, and platform
exactly, give a rationale, and expire no later than 90 days after admission.
Missing, ambiguous, wildcarded, expired, or version-mismatched exceptions fail
closed. A scanner failure or malformed result is a gate failure, not a clean
scan.

Rebuild validation compares normalized root filesystem paths, file contents,
modes, numeric ownership, selected image config and labels, embedded build
identity, and SBOM subjects/components. It deliberately ignores layer
compression, tar member order, and BuildKit transport bookkeeping. Both builds
come from the same declared source and pinned inputs; any normalized difference
fails the gate.

### CI and release separation

Phase 1 is dry-run only. Workflows build Docker archives and evidence for
downloadable CI artifacts but do not push to GHCR, create GitHub releases, or
create attestations. Repository workflows remain read-only and do not request
`packages: write`, `contents: write`, or `id-token: write`.

Pull requests validate all seven roles on native AMD64 and ARM64. The default
branch, schedule, and manual dry run additionally validate RISC-V through the
rootless helper. Release-tag and manual dry runs cover all 21 role/platform
combinations and normalized rebuild checks. Build jobs never publish.

When publication is introduced by a later accepted decision, a separate
least-privilege job will consume already validated artifacts. GitHub artifact
attestations are the selected future attestation mechanism; Cosign and a
second signing identity are not introduced. The first published GHCR
prerelease is made public immediately, but Phase 1 performs no registry write.

### Helm contract

The Phase 1 `filebelt` chart is a values and schema contract only. It lists the
same seven image roles, their immutable tag-or-digest selection, registry mirror
precedence, platform intent, and numeric user/group. It renders no Kubernetes
object. Deployments, Services, probes, storage, credentials, policy, and
authorization semantics require later decisions and implementation.

## Alternatives considered

Multi-architecture indexes were not published because Phase 1 has no registry
write path. A Docker-host QEMU registration step was rejected because it
changes shared host execution state and increases pull-request privilege.
Compile-only RISC-V evidence was rejected because it does not exercise the
static executable.

Cosign was deferred because GitHub attestations provide the selected future
identity and transparency path without introducing a second key lifecycle.
Mutable image aliases were rejected because they weaken the source-to-artifact
mapping. A placeholder Kubernetes Deployment and fake health endpoint were
rejected because both would overstate runtime readiness.

## Consequences

The repository gains deterministic, downloadable image evidence while
remaining unable to publish it. Consumers can independently inspect role,
platform, source, license, build identity, SBOM, vulnerability, and rebuild
results. Native ARM64 capacity and bounded QEMU execution add CI cost. A later
release phase must add registry permissions, artifact consumption, publication,
attestation, and post-push verification without rebuilding the image.

## Security, data, and license analysis

No database, secret, user payload, namespace, or authorization state is added.
Build contexts exclude adapter implementation and local-agent data. Static
images run as a numeric unprivileged identity and contain no shell or package
manager. Image license labels and shipped notices must match each image's
contents. Rust roles carry aggregate Apache-2.0 and MIT evidence with exact
Rust and musl notices; the web artifact remains Apache-2.0-only. Build-tool
licenses are inventoried as excluded build inputs and those tools are not
copied into the final image.

CI artifacts are untrusted build outputs until every evidence gate succeeds.
No archive produced from a pull request is eligible for publication. Registry
mirrors in the Helm values change only the registry authority, not repository,
role, digest, authorization, or license semantics.

## Verification

- Repository contract tests validate the exact role and platform matrix,
  archive contents, OCI labels, numeric user, static executable, and license
  evidence.
- Native and rootless-QEMU smoke tests validate deterministic identity and
  reject unsupported execution.
- Helm strict lint, schema validation, and rendering confirm that the chart
  accepts exactly one of tag or digest and emits no Kubernetes object.
- Trivy, exception-policy, SBOM, checksum, and artifact-contract tests fail
  closed on missing or inconsistent evidence.
- A two-build normalized comparison detects meaningful reproducibility drift.
- Workflow-integrity tests prohibit publish permissions and privileged trigger
  paths.
- Release trust checks validate the tracked public-key fingerprints and bind an
  authorized signed tag to the checked-out source revision.

## Rollout and rollback

Land the evidence contract before the builders and workflows that consume it.
Then enable native archive validation, RISC-V smoke validation, rebuild
comparison, and the release dry run. Phase 1 creates no external artifact to
revoke. Rollback removes the workflow invocations and chart/build assets
together; local and CI archives under `artifacts/` can be discarded. Accepted
repository names, immutable version semantics, and the non-publishing boundary
remain governed by ADR-0006 and this ADR until superseded.

## Open questions

None.
