<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0001: Repository naming and topology

- Status: Accepted
- Date: 2026-08-06
- Owners: `@PiQuark6046`
- Reviewers: none
- Supersedes: none
- Affected license regions: mixed

## Context

FileBelt needs Rust services, browser packages, protocol definitions, tests,
deployment tooling, and independently licensed adapters without allowing the
Apache workspace to absorb copyleft implementation code.

## Decision

FileBelt is one public monorepo. The root Rust and pnpm workspaces contain
Apache-2.0 packages only. Copyleft adapters use nested build roots and lockfiles
and communicate through protocol-neutral contracts.

Naming is stable and role-oriented:

- directories and Cargo packages use lowercase kebab-case;
- Cargo packages and binaries use `filebelt-*`, while Rust crate identifiers
  use underscores as required by Rust;
- private TypeScript packages use `@filebelt/*`;
- Protobuf packages use `filebelt.<domain>.v1`;
- database and configuration keys use `snake_case`, environment variables use
  `FILEBELT_`, and OCI roles use `ghcr.io/oxibelt/filebelt-<role>`;
- deterministic test resources begin with `filebelt-<suite>-` and include a
  unique run identifier.

All first-party packages use coordinated SemVer, beginning at `0.1.0`, and are
not published to crates.io or npm without another decision. The integrated
`source` binary is a development composition only; production uses role
binaries.

## Alternatives considered

Separate adapter repositories would strengthen physical separation but make
atomic protocol and policy changes harder. A single unrestricted workspace
would weaken license evidence and is rejected.

## Consequences and verification

Adding a package requires explicit root membership and ownership review.
Repository tests reject adapter membership, reverse path dependencies,
incorrect naming, or publishable placeholder packages.

## Rollback

Before public release, a name may change through a superseding ADR and coherent
workspace update. Published names follow the compatibility policy.

## Open questions

None.
