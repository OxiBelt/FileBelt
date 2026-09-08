<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to FileBelt are documented here. The project uses
[Semantic Versioning](https://semver.org/) with coordinated component versions.

## [Unreleased]

### Security

- OxiBelt admission schema v3 retains the exact release qualification and
  vulnerability-decision archives, all three platform subjects, and four
  Sigstore bundles while keeping the trust anchor verifier-owned.
- Helm-rendered OxiBelt TLS paths are confined below its certificate root and
  use the native nested client-identity schema; native image checks reject
  world-readable, missing, and mismatched outbound credentials.

### Added

- A canonical `x86-64-v3` AMD64 image contract with plan-derived Rust, C/C++,
  and linker flags; GNU ISA-note, OCI label, SBOM, build-evidence, host, and
  Kubernetes-node validation; and retained qualified OxiBelt index, AMD64, ARM64,
  and RISC-V attestation evidence.
- Repository governance, workspace, license, architecture, and CI bootstrap.
- Read-only Docker image archives with OCI labels for seven Apache image roles
  on AMD64, ARM64, and RISC-V, with deterministic build identity and scratch
  final images.
- Per-platform CycloneDX SBOMs, pinned Trivy vulnerability decisions, static
  inspection, smoke probes, and normalized rebuild verification.
- A strict Phase 1 Helm image-values schema that intentionally renders no
  Kubernetes resources.
- Native and cross-platform CI plus a non-publishing release dry run for all 21
  role/platform combinations.
