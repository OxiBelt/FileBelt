<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt

FileBelt is a public, self-hostable web drive built primarily in Rust and
TypeScript. The project is Kubernetes-first, uses PostgreSQL as authoritative
metadata state, and applies one application-level Virtual ACL model across web
and protocol access paths.

This repository implements the Apache core production boundary: a
tenant-scoped PostgreSQL namespace and Virtual ACL, OIDC browser sessions,
immutable file versions, UUID-addressed whole/chunk payload storage,
capability-limited I/O workers, sharing and revocation, durable jobs/outbox,
optional Apache Iggy notifications, a per-principal MCP broker with explicit
capability and data approval, and an accessible React web drive behind
OxiBelt. Reviewed local MCP servers may run only through the separately
opted-in Kubernetes controller and one-shot runner boundary.

Docker remains the development/integration topology. Production uses the
hardened Helm chart on Kubernetes 1.34-1.36 with external PostgreSQL, OIDC,
optional Iggy, operator Secrets, an existing RWX POSIX claim, default-deny
networking, and backend mTLS. MCP additionally requires an operator-managed
egress gateway; the broker and runner controller are disabled by default.
FileBelt makes no HA, online-backup, PITR, numeric RPO, or numeric RTO claim.

The [living engineering specifications](docs/README.md),
[supply-chain policy](docs/SupplyChain.md), and
[runtime and deployment contract](docs/RuntimeAndDeployment.md) describe the
current build, runtime, and release boundary. Pull-request validation remains
read-only; authorized signed SemVer tags may promote the eight active images
and Helm chart with attestations.

## Repository regions

- `source/`, `protocol/`, `ui/`, `devops/`, `deploy/`, and repository tooling
  are Apache-2.0.
- `adapters/smb/` and `adapters/ftp-ftps/` are GPL-3.0-or-later regions.
- `adapters/onlyoffice/` is an AGPL-3.0-only region.
- `adapters/nfs/` is reserved as an LGPL-3.0-or-later region.
- `adapters/transcode/` contains only Apache-2.0 governance material until an
  explicit review updates the license and runtime contracts with the exact
  FFmpeg composition.

See [the license map](docs/LicenseMap.md), [contribution guide](CONTRIBUTING.md),
and [engineering documentation index](docs/README.md) before making changes.

## Bootstrap checks

```sh
python3 tests/scripts/check-source-structure.py --repo-root .
python3 tests/scripts/check-markdown-links.py --repo-root .
python3 tests/scripts/check-generated.py --repo-root .
tests/scripts/check-rust-module-size.sh --warn
tests/scripts/check-cargo-boundaries.sh
reuse lint
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo audit
cargo deny check
cargo vet --locked
corepack pnpm install --frozen-lockfile --ignore-scripts
pnpm licenses list --json | python3 tests/scripts/check-node-licenses.py --policy supply-chain/node-policy.toml
pnpm audit --audit-level high
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

Additional supply-chain checks are described in
[`docs/SupplyChain.md`](docs/SupplyChain.md).

## Core architecture

- PostgreSQL is authoritative for identity, metadata, policy, versions, jobs,
  audit, and outbox state.
- The payload plane uses opaque UUIDv4 locators on one validated POSIX storage
  root; host filesystem ownership never represents a FileBelt user.
- Every access resolves an internal principal and enforces the common Virtual
  ACL. The API issues short-lived operation capabilities but does not mount
  payload storage.
- Apache Iggy accelerates wake-ups and invalidation. The same operations remain
  correct through PostgreSQL polling when Iggy is absent or unavailable.
- MCP server registrations, immutable capability reviews, exact approvals,
  version-pinned data grants, service grants, revocation state, and redacted
  activity are authoritative in PostgreSQL. Credentials use a separate
  envelope-encrypted vault schema and never enter browser storage.
- The MCP broker has no payload mount and reaches remote servers only through
  an allowlisting mTLS egress gateway. Curated stdio servers run in one-shot,
  digest-pinned Kubernetes Pods with no service-account token or direct
  Internet path.
- OxiBelt terminates public TLS and serves/proxies the SPA, REST API, uploads,
  and Range downloads. Kubernetes backends require native mTLS and
  NetworkPolicy isolation.

Read the [namespace and authorization](docs/NamespaceAndAuthorization.md),
[interfaces and capabilities](docs/InterfacesAndCapabilities.md),
[storage and durability](docs/StorageAndDurability.md), and
[runtime and deployment](docs/RuntimeAndDeployment.md) contracts, together with
the [threat model](docs/ThreatModel.md) and
[Kubernetes operator guide](docs/operations/kubernetes.md), before changing
these boundaries.

## Image checks

Build the TypeScript planning tools, create an immutable build plan, and run a
native platform matrix with:

```sh
pnpm --filter @filebelt/devops build
tests/scripts/prepare-image-plan.sh --channel build --output artifacts/phase4/image-plan.json
tests/scripts/run-image-matrix.sh --plan artifacts/phase4/image-plan.json --platform linux/amd64 --output-dir artifacts/phase4/amd64
tests/scripts/check-helm-chart.sh
```

The matrix creates local Docker image archives and evidence under `artifacts/`,
which is ignored by Git and safe to discard. Use a native ARM64 host for
`linux/arm64`. The CI RISC-V job cross-compiles active Rust roles and executes a
bounded smoke suite through the repository's rootless, digest-pinned QEMU
helper; optional Iggy behavior uses the PostgreSQL polling fallback on that
architecture. Smoke tests refuse to replace a pre-existing local tag and
remove every image tag they load or build.

## License

Unless otherwise noted by a more specific file or directory, original
FileBelt work is licensed under Apache-2.0. FileBelt has no premium-only or
source-available feature region.
