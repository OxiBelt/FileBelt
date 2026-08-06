<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to FileBelt are documented here. The project uses
[Semantic Versioning](https://semver.org/) with coordinated component versions.

## [Unreleased]

### Added

- Repository governance, workspace, license, ADR, and CI bootstrap.
- Read-only Docker image archives with OCI labels for seven Apache image roles
  on AMD64, ARM64, and RISC-V, with deterministic build identity and scratch
  final images.
- Per-platform CycloneDX SBOMs, pinned Trivy vulnerability decisions, static
  inspection, smoke probes, and normalized rebuild verification.
- A strict Phase 1 Helm image-values schema that intentionally renders no
  Kubernetes resources.
- Native and cross-platform CI plus a non-publishing release dry run for all 21
  role/platform combinations.
