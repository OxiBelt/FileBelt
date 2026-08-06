<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0011: Phase 2 runtime images and evidence

- Status: Accepted
- Date: 2026-08-06
- Owners: `@PiQuark6046`
- Reviewers: none
- Supersedes: Phase 1 runtime-content and web-artifact portions of ADR-0007
- Affected license regions: Apache-2.0 source and reviewed permissive/MPL runtime composition

## Context

ADR-0007 deliberately made every Phase 1 application an identity probe and the
web image a non-executable static artifact. Phase 2 replaces the API, I/O
worker, maintenance worker, tools, and web probes with usable services and
introduces PostgreSQL, OIDC, OxiBelt, and optional Iggy integration fixtures.
It must preserve truthful role separation, three-architecture claims, and
dry-run-only release permissions while admitting new native and external
inputs.

The media controller and MCP broker remain probes. The conditional Kubernetes
controller, adapters, media processing, and Kubernetes runtime remain outside
Phase 2.

## Decision drivers

- Preserve least-privilege runtime images and explicit mount/network/secret
  boundaries.
- Pin every external image and protocol client to a reviewable version and
  immutable digest where applicable.
- Keep pull requests unable to publish packages or mint release attestations.
- Retain truthful AMD64, ARM64, and RISC-V evidence despite native crypto and
  an unavailable Iggy RISC-V image.

## Decision

### Runtime roles

Phase 2 activates these role contracts:

| Role | Runtime responsibility | Privileged inputs |
| --- | --- | --- |
| `filebelt-api` | OIDC, sessions, metadata API, authorization, capability issuance | PostgreSQL API role and signing/hash secret files; no payload mount |
| `filebelt-worker-io` | Capability-limited upload, finalize, and Range download | Narrow PostgreSQL role, capability public keys, one payload mount |
| `filebelt-worker-maintenance` | Durable job leasing, reconcile, delete, and scrub | Narrow PostgreSQL role and one payload mount |
| `filebelt-tools` | Config validation, migration, bootstrap, key, job, storage, and recovery commands | Only explicitly mounted command-specific credentials/storage |
| `filebelt-web` | Pinned OxiBelt TLS edge, static SPA, and reviewed reverse-proxy routes | TLS/custom-CA files and isolated backend network; no PostgreSQL or payload mount |

Each FileBelt process runs as numeric `10001:10001` with a read-only root,
no-new-privileges, dropped capabilities, bounded writable temporary storage,
and only role-specific secret files, ports, networks, and mounts. Runtime
health distinguishes process liveness from dependency and storage readiness.

`filebelt-media-controller` and `filebelt-mcp-broker` keep their Phase 1
probe-only behavior and cannot be presented as Phase 2 services. The Helm chart
retains compatible image values but continues to render no Kubernetes object.

### Immutable external inputs

Phase 2 admits exactly these integration inputs:

- OxiBelt prerelease `0.7.1-beta.2`,
  `ghcr.io/oxibelt/oxibelt@sha256:e8556a0103feff47bf6135062e70e980e000176598fd438959ea55d99c844030`;
- PostgreSQL 18.4,
  `docker.io/library/postgres@sha256:d129b9577d274bb96cbd44d902bdeb1b935c89247d161241e9154cba64e13df4`;
  and
- Apache Iggy server 0.8.0,
  `docker.io/apache/iggy@sha256:99b42016a898381d4bab3c2d4613456eb04ad06a7a0688314823d798a685636b`,
  with exact Rust client `iggy = 0.8.0`.

The OxiBelt prerelease is an explicit exception selected for the required route
profile. Evidence records the upstream release and source revision. A version
or digest change is a separately reviewed dependency update and repeats route,
source, license, vulnerability, and architecture validation.

The web image derives from the pinned OxiBelt image and copies only generated
FileBelt SPA assets, reviewed route configuration, licenses, notices, and
identity metadata. It must not copy from the read-only reference checkout or
link OxiBelt implementation code into a FileBelt package.

PostgreSQL, Iggy, and the OIDC fixture are development/integration helpers,
not FileBelt release images. Iggy's required `SYS_NICE`, unlimited memlock, and
seccomp exception are scoped only to the digest-pinned Iggy container. No
FileBelt container inherits those settings. Iggy is optional in all profiles
except the explicit real-Iggy test profile.

### Toolchain and architecture evidence

FileBelt's OIDC, database, and first-party HTTP TLS code uses Rustls with the
AWS-LC provider, Ed25519, embedded public WebPKI roots, and an optional mounted
custom CA bundle. The exact Iggy 0.8.0 client is an explicit exception whose
upstream notification-only transport also links Ring; it cannot participate in
authorization or durable commit correctness. Native-source,
`*-sys`, feature, build-script, compiler, assembler, linker, and final ELF
evidence is reviewed and recorded. The RISC-V musl build uses the admitted
bindgen and cross-toolchain pattern established by the OxiBelt reference, not
OxiBelt source code.

Active FileBelt roles continue to support `linux/amd64`, `linux/arm64`, and
`linux/riscv64` under ADR-0006. Native architectures run full behavior suites.
RISC-V runs bounded configuration, crypto-provider, database-unavailable,
identity, health, non-root, and shutdown smoke tests under rootless QEMU. The
optional Iggy helper is absent from RISC-V testing because its official image
does not provide that platform; PostgreSQL polling behavior is tested instead.

Every final image retains the ADR-0007 OCI identity labels and gains evidence
for runtime route/config schema, native crypto inputs, final dynamic/static
linkage, license texts/notices, SBOM, vulnerability results, mount/user
contract, and role-specific smoke behavior. Active images use the truthful
role-specific aggregate expression from `docs/LicenseMap.md`, including CDLA
WebPKI data, the maintenance/tools Iggy MPL helper, and the web bundle's 0BSD
runtime helper where applicable.

### Browser application

`@filebelt/web` is a client-rendered React/Vite SPA and uses one generated
OpenAPI client. `@filebelt/admin` is a lazy `/admin` route in the same web
artifact; API authorization remains authoritative. Phase 2 has no SSR, service
worker, offline payload/content cache, or browser-stored credential. IndexedDB
may retain only expiring non-secret upload-resume metadata and clears it on
logout or expiry.

The UI uses `@fluentui/react-components` primitives with FileBelt-owned themes
and density and Lucide icons at 20 px with 1.75 px strokes. It does not copy
Fluent product branding. It supports system/light/dark themes, forced colors,
reduced motion, bidi-safe user content, externalized English strings, a 320 px
viewport, and WCAG 2.2 AA.

The file table uses the documented desktop selection model: arrows move focus,
Space toggles, Shift extends a range, Control/Command plus Space toggles,
Control/Command+A selects all, and Shift+F10 opens the context menu. Checkbox,
touch, and long-press paths provide equivalent behavior without hover-only
controls. Moving one item to trash offers undo without a modal; permanent
purge, multi-item/group/owner/share-wide destruction require explicit
confirmation, with typed confirmation for at least ten items or an entire
drive.

The initial artifact covers private drives, shared-with-me, upload, download,
immutable versions and restore, direct share and revoke, trash, session state,
and the Phase 2 administrator shell. The pnpm workspace runs component and
accessibility-oriented unit coverage; cross-browser end-to-end coverage remains
future work and is not claimed by this phase.

### Docker and release boundary

Docker profiles cover the core stack, optional real Iggy, and fault injection.
Browser package tests run in the pnpm workspace, and the operator guide records
the quiesced backup/restore procedure. Docker remains development and
integration only and makes no production availability or recovery claim.

Repository workflows remain dry-run only. They may build local archives and
downloadable evidence, but they do not push to GHCR, create releases, request
`packages: write`, `contents: write`, or `id-token: write`, or mint
attestations. Publication still requires a later accepted decision and a
separate least-privilege job that promotes already validated artifacts.

## Alternatives considered

Keeping identity probes, running a combined API/storage image, mounting
payload storage into the API, building OxiBelt from the reference checkout,
using a mutable edge tag, granting Iggy privileges to the whole profile, and
requiring an unofficial RISC-V Iggy image were rejected. Adding Kubernetes
objects in Phase 2 was deferred to avoid claiming an untested production
topology.

## Consequences

Phase 2 image evidence becomes materially more expensive because it includes
real startup, configuration, crypto, database, storage, edge, TLS acceptance
client, and restart-recovery behavior. The role boundary makes compromise
consequences narrower
and keeps external servers replaceable. The selected OxiBelt prerelease needs
explicit review on every update.

## Security, data, and license analysis

Build contexts exclude adapters, local-agent state, developer secrets,
database volumes, payloads, test identities, and backup artifacts. Test logs
and retained artifacts redact cookies, tokens, capabilities, OIDC codes, key
material, and user content. Secret files never become image layers or SBOM
properties.

The activated FileBelt source remains Apache-2.0. Rust/musl and OxiBelt-derived
runtime composition carries the complete corresponding permissive notices and
truthful aggregate labels. PostgreSQL and Iggy helper images retain their
upstream licenses and notices and are not republished as FileBelt roles.

## Verification

- Image contract tests inspect numeric identity, rootfs, mounts, ports,
  capabilities, labels, notices, source mapping, and role artifact.
- Native and RISC-V smoke tests prove config failure, health, provider startup,
  non-root execution, and clean shutdown.
- Edge contract and image tests bind the OxiBelt digest to the production route
  profile, static assets, header stripping, cache denial, and disabled write
  retry.
- Docker tests prove PostgreSQL 18.4, deterministic cleanup, restart
  reconciliation, and the two-user TLS-edge workflow. The Compose contract pins
  optional Iggy and isolates the fault-injection role; browser package tests
  cover the initial UI shell, while restore remains an operator procedure.
- Existing SBOM, Trivy, vulnerability-exception, normalized rebuild,
  workflow-integrity, and Helm contract gates continue to fail closed.

## Rollout and rollback

Land dependency admission and image-contract changes before activating runtime
images. Build and validate all archives without publication. Roll out the
Docker stack in database, workers, API, edge order after migrations/bootstrap;
roll back by quiescing writes, draining capabilities, retaining compatible
keys and schema, and restoring the prior compatible archives/configuration.
Discard local archives and test volumes only after recovery evidence has been
captured. No registry artifact exists to revoke.

## Open questions

None.
