<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0004: Protobuf IDL and generated code

- Status: Accepted
- Date: 2026-08-06
- Owners: `@PiQuark6046`
- Reviewers: none
- Supersedes: none
- Affected license regions: mixed

## Context

Rust services and C, Rust, or TypeScript adapters need versioned,
language-neutral contracts that do not expose upstream implementation types.

## Decision

Protocol schemas are Apache-2.0 Protobuf `proto3` files below
`protocol/<domain>/v1/`, using packages `filebelt.<domain>.v1`. Buf v2 tooling
provides `STANDARD` lint and file-level breaking-change checks against `main`.

Generated clients are committed. Generators and runtime dependencies are exact
and recorded in `supply-chain/tooling.toml`; CI regenerates into deterministic
package-local `generated/` directories and requires a clean diff. Generated
files identify schema source, generator/version, regeneration command, and
license, and are never hand-edited.

Schemas use FileBelt IDs and stable error enums. They never serialize Samba,
FTP server, ONLYOFFICE, NFS-Ganesha, database-row, or host-path types. Protocol
transport, authentication, and service methods require their own later ADR;
Phase 0 deliberately defines none.

## Alternatives considered

Build-only generation was rejected because adapter toolchains need reviewable
public output. JSON Schema was rejected as the primary binary RPC model because
it provides weaker multi-language service tooling.

## Consequences and verification

Schema changes must update generated output in the same commit and pass lint,
breaking, license, and drift checks. Empty Phase 0 protocol roots are valid;
the checks activate when the first schema is accepted.

## Rollback

Before a schema is released it may be replaced coherently. Released `v1`
contracts follow Buf breaking checks and require a new version for incompatible
changes.

## Open questions

None.
