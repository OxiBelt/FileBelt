<!-- SPDX-License-Identifier: Apache-2.0 -->

# Phase 1 Repository and Image-Build Threat Model

- Date: 2026-08-06
- Owner: `@PiQuark6046`
- Scope: repository governance, dependency admission, code generation,
  read-only Docker image archives, OCI labels, image evidence, Helm schema,
  and CI
- Excluded: runtime services and user data, registry publication, release
  attestations, and Kubernetes workloads, which do not yet exist

## Security objectives

- A contribution cannot silently cross the Apache/copyleft boundary.
- An untrusted pull request cannot obtain package-write, release, attestation,
  secret, or elevated runtime permissions.
- Dependencies, generated code, and tool invocations remain traceable to pinned
  inputs.
- Repository checks fail closed when ownership, license, or unsafe-code policy
  is missing.
- Every image archive and evidence file agrees on role, platform, source,
  version, build kind, numeric identity, and license.
- Architecture validation does not register persistent host emulation or grant
  an untrusted build privileged execution.
- A vulnerability exception is exact, justified, and short-lived.
- The Helm configuration contract cannot create a Kubernetes object.

## Threats and controls

| Threat | Control | Evidence |
| --- | --- | --- |
| Apache package imports adapter code | Explicit workspaces and resolved path-dependency contract tests | `dependency_boundaries` tests |
| Package or file has ambiguous license | REUSE/SPDX and machine-readable region map | `license_boundaries` tests |
| Malicious PR obtains privileged token | Read-only workflow permissions; no `pull_request_target` | workflow-integrity tests |
| Action or tool tag is retargeted | Immutable action SHAs and exact tool inventory | source-structure checks |
| Generated client hides schema drift | Committed outputs and clean regeneration | protocol CI job |
| Unsafe/native code bypasses review | Workspace lint and empty exception registry | unsafe-policy tests |
| Dependency substitution or install script | Frozen lockfiles, reviewed registries, scripts disabled | supply-chain jobs |
| Broken governance links hide policy | Local Markdown path/anchor validation | link checker |
| Build context includes adapter or local-agent data | Narrow Docker contexts and explicit exclusions | image archive contract tests |
| Role confusion executes the wrong binary or assets | Exact seven-role plan, embedded identity, OCI role label, and archive inspection | image contract and smoke tests |
| Archive claims a false source, version, platform, or license | Cross-checked build metadata, labels, executable identity, SBOM, notices, and checksums | evidence validation |
| Malicious binary gains root in a later runtime | Numeric `10001:10001`, static `scratch` image, no shell or package manager | image config and rootfs inspection |
| RISC-V smoke mutates shared host execution | Extracted static binary runs through a digest-pinned rootless QEMU helper | RISC-V smoke test |
| Scanner error is treated as no vulnerability | Pinned Trivy result and exception policy fail closed on missing or malformed evidence | vulnerability-policy tests |
| Broad or stale exception hides a severe issue | Exact role/platform/advisory/package/version match and maximum 90-day expiry | vulnerability-policy tests |
| Nondeterministic rebuild changes runnable content | Normalized filesystem, config, identity, and SBOM comparison | rebuild gate |
| Placeholder chart accidentally deploys an unsafe workload | Strict schema and an empty manifest contract | Helm asset tests |

## Residual risk

The single maintainer is a concentration of trust. Branch protection, DCO,
auditable ADRs, minimal workflow permissions, and public review provide the
current compensating controls. A CycloneDX SBOM and Trivy scan reduce known
dependency risk but do not prove the absence of malicious build inputs or an
unknown vulnerability. CI archives are not registry artifacts and receive no
release attestation in Phase 1.

Runtime threat models must be added before any service, database, browser
application, adapter, image, or Kubernetes workload is considered usable. A
later publication design must separately model registry credentials, artifact
promotion, GitHub attestation identity, retention, revocation, and post-push
verification; it may not grant a build job package-write access.
