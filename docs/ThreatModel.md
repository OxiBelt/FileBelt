<!-- SPDX-License-Identifier: Apache-2.0 -->

# Phase 0 Repository Threat Model

- Date: 2026-08-06
- Owner: `@PiQuark6046`
- Scope: repository governance, dependency admission, code generation, and CI
- Excluded: runtime services and user data, which do not yet exist

## Security objectives

- A contribution cannot silently cross the Apache/copyleft boundary.
- An untrusted pull request cannot obtain package-write, release, attestation,
  secret, or elevated runtime permissions.
- Dependencies, generated code, and tool invocations remain traceable to pinned
  inputs.
- Repository checks fail closed when ownership, license, or unsafe-code policy
  is missing.

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

## Residual risk

The single maintainer is a concentration of trust. Branch protection, DCO,
auditable ADRs, minimal workflow permissions, and public review provide the
current compensating controls. Runtime threat models must be added before any
service, database, browser application, adapter, or image is considered usable.
