<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt automated-agent guidance

## Audience and precedence

This file is an overlay for automated coding agents. People and automated
agents share the contributor workflow in [`CONTRIBUTING.md`](CONTRIBUTING.md)
and the current engineering contracts indexed in
[`docs/README.md`](docs/README.md). If this file conflicts with either source,
stop and ask the maintainer which rule should prevail.

Files below `.agents/temp/` are ignored, local planning material. They are not
repository policy, must not override tracked guidance, and must not be cited in
commits or pull requests.

## Project boundaries

FileBelt is a public mixed-license monorepo. PostgreSQL is authoritative for
metadata and policy state, UUID-addressed storage is the payload plane, and
Apache Iggy is notification only. Host filesystem ownership never represents a
FileBelt user. Every access path must resolve an internal principal and enforce
the common Virtual ACL model.

## Mandatory planning and escalation

Enter Plan Mode before creating a service or image, changing persisted data,
authorization or namespace semantics, adding a protocol or external
integration, changing a public contract, or moving code across a license
boundary. Read the applicable component overlay and living specifications
first:

- [`NamespaceAndAuthorization.md`](docs/NamespaceAndAuthorization.md) for
  identity, names, principals, sharing, and Virtual ACL;
- [`InterfacesAndCapabilities.md`](docs/InterfacesAndCapabilities.md) for
  public APIs, protocol schemas, edge behavior, and worker capabilities;
- [`StorageAndDurability.md`](docs/StorageAndDurability.md) for migrations,
  payload state, jobs, recovery, and compatibility; and
- [`RuntimeAndDeployment.md`](docs/RuntimeAndDeployment.md) for images,
  external inputs, Kubernetes, release evidence, and rollback.

Stop and ask the maintainer whenever repository evidence and the requested
change leave a material security, durability, compatibility, public-contract,
or licensing choice unresolved. Do not silently select those semantics, and do
not implement past an unresolved decision.

## Dependency and license direction

- Root Cargo and pnpm workspaces contain Apache-2.0 packages only.
- Apache packages must never import, link, or path-depend on implementation
  code under `adapters/`.
- Adapters may consume Apache protocol schemas or clients through a documented,
  replaceable process boundary.
- Domain and authorization packages remain independent of SQL, HTTP,
  Kubernetes, UI, Iggy, and adapter implementation types.
- Rust packages inherit `unsafe_code = "deny"`; exceptions require explicit
  maintainer approval, a rationale in the same pull request, and an entry in
  `supply-chain/unsafe-exceptions.toml`.

## Change discipline

Follow `CONTRIBUTING.md`, including its same-pull-request design review,
validation, DCO, and Conventional Commit requirements. Update the applicable
living specifications, threat model, operator documentation, license evidence,
and rollback notes whenever their boundary changes. Preserve deterministic
resource naming and cleanup in tests. Never make an event stream the sole
record of committed state.

## Agent commit message guidance

Commit messages must contain portable, repository-relevant context. Do not
include session-specific command aliases, absolute host paths, or local-only
environment data and artifacts. For example, do not cite files under
`.agents/temp`; describe the portable result instead, such as whether the
relevant validation or performance benchmarks were run.

When additional context is useful, prefer stable sources that readers can
access publicly, such as tracked repository files, public GitHub projects,
issues, pull requests, commits, published security advisories, and official
documentation. If no suitable public source exists, explain the necessary
context inline without citing inaccessible local material. Sanitize the
description and do not expose secrets, personal data, or undisclosed
vulnerability details.

Run the shared checks documented in `CONTRIBUTING.md` and `README.md`, plus the
targeted Docker, browser, Kubernetes, release, and integration checks required
by the affected living specification. Never replace a required check with a
false-positive placeholder.
