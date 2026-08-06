<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0006: Image roles, versioning, and platforms

- Status: Accepted
- Date: 2026-08-06
- Owners: `@PiQuark6046`
- Reviewers: none
- Supersedes: none
- Affected license regions: mixed

## Context

Production permissions, storage mounts, Internet egress, license labels, and
release architectures differ by role. A combined image would obscure both
security and licensing boundaries.

## Decision

Initial Apache image names are `filebelt-api`, `filebelt-worker-io`,
`filebelt-worker-maintenance`, `filebelt-media-controller`,
`filebelt-mcp-broker`, `filebelt-tools`, and `filebelt-web`. The controller
package exists but gains an image only if static Kubernetes resources prove
insufficient. Markdown initially ships through the web role.

Reserved adapter roles are `filebelt-smb-gateway`,
`filebelt-ftp-ftps-gateway`, `filebelt-onlyoffice-adapter`, future
`filebelt-nfs-gateway`, and `filebelt-transcoder` with its exact eventual
composition. The integrated development binary is never a production image.

Images use coordinated SemVer and immutable role-specific tags under
`ghcr.io/oxibelt/`. Kubernetes is the supported production topology; local
composition is development/test only.

Every Apache role supports `linux/amd64`, `linux/arm64`, and `linux/riscv64`.
AMD64 and ARM64 run native full suites. RISC-V cross-builds and must pass a
bounded QEMU smoke suite covering process startup, build identity, configuration
failure, health behavior when applicable, non-root execution, and clean
shutdown. RISC-V does not duplicate expensive behavior matrices already run on
native architectures. Adapter platform lists are independently truthful and
limited by validated upstream composition.

No image may be published until its final contents pass smoke, SBOM,
vulnerability, provenance, source-map, and license-label checks. Build jobs
cannot publish; package-write jobs consume already validated artifacts.

## Alternatives considered

A production all-in-one image was rejected for privilege and role leakage.
Compile-only RISC-V publication was rejected because compilation does not prove
runtime behavior. Requiring RISC-V for every upstream adapter was rejected
because upstream architecture support must be verified per image.

## Consequences and verification

Phase 1 image plans must carry role, license, source, and platform data.
Repository contracts reserve names but Phase 0 creates no Dockerfile or image.

## Rollback

No image exists in Phase 0. Once published, a platform is removed only through
a documented release compatibility change; stable tags are never overwritten.

## Open questions

None.
