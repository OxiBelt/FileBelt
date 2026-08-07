<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt

FileBelt is a public, self-hostable web drive built primarily in Rust and
TypeScript. The project is Kubernetes-first, uses PostgreSQL as authoritative
metadata state, and applies one application-level Virtual ACL model across web
and protocol access paths.

This repository implements the Phase 2 Apache core foundation: a tenant-scoped
PostgreSQL namespace and Virtual ACL, OIDC browser sessions, immutable file
versions, UUID-addressed whole/chunk payload storage, capability-limited I/O
workers, sharing and revocation, durable jobs/outbox, optional Apache Iggy
notifications, and an accessible React web drive behind OxiBelt.

The supported Phase 2 runtime is a Docker development/integration topology.
It includes two-user TLS-edge acceptance and restart reconciliation, plus
fault-injection support and a documented quiesced backup/restore procedure. It
is not a production deployment and makes no HA, PITR, RPO, or RTO claim. The Helm
chart remains a strict image-values contract and intentionally renders no
Kubernetes object until Phase 3.

The Phase 1 image evidence contract remains in
[ADR-0007](docs/adr/0007-oci-build-and-release-evidence.md) and its Phase 2
runtime extension is [ADR-0011](docs/adr/0011-phase-two-runtime-images-and-evidence.md).
Image validation remains dry-run only: repository workflows never push to
GHCR, create releases, or mint attestations.

## Repository regions

- `source/`, `protocol/`, `ui/`, `devops/`, `deploy/`, and repository tooling
  are Apache-2.0.
- `adapters/smb/` and `adapters/ftp-ftps/` are GPL-3.0-or-later regions.
- `adapters/onlyoffice/` is an AGPL-3.0-only region.
- `adapters/nfs/` is reserved as an LGPL-3.0-or-later region.
- `adapters/transcode/` contains only Apache-2.0 governance material until an
  accepted ADR establishes the exact FFmpeg composition.

See [the license map](docs/LicenseMap.md), [contribution guide](CONTRIBUTING.md),
and [accepted ADRs](docs/adr/README.md) before making changes.

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
- OxiBelt terminates public TLS and serves/proxies the SPA, REST API, uploads,
  and Range downloads. Backend services remain on an isolated network.

Read [the ADR index](docs/adr/README.md),
[threat model](docs/ThreatModel.md), and
[Phase 2 operator guide](docs/operations/phase2.md) before changing these
boundaries.

## Image checks

Build the TypeScript planning tools, create an immutable build plan, and run a
native platform matrix with:

```sh
pnpm --filter @filebelt/devops build
tests/scripts/prepare-image-plan.sh --channel build --output artifacts/phase2/image-plan.json
tests/scripts/run-image-matrix.sh --plan artifacts/phase2/image-plan.json --platform linux/amd64 --output-dir artifacts/phase2/amd64
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
