<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt

FileBelt is a public, self-hostable web drive built primarily in Rust and
TypeScript. The project is Kubernetes-first, uses PostgreSQL as authoritative
metadata state, and applies one application-level Virtual ACL model across web
and protocol access paths.

This repository has a Phase 1 build-and-release skeleton. The packages remain
identity probes rather than usable services, but the repository can build and
validate seven read-only Docker image archives with OCI identity labels for
AMD64, ARM64, and RISC-V. No database schema, application API, registry
publication, or production deployment is implemented yet. The Phase 1 Helm
chart is a strict image-values contract and intentionally renders no Kubernetes
object.

The image and evidence contract is defined by
[ADR-0007](docs/adr/0007-oci-build-and-release-evidence.md). Image validation is
dry-run only: repository workflows never push to GHCR, create releases, or mint
attestations.

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

## Phase 1 image checks

Build the TypeScript planning tools, create an immutable build plan, and run a
native platform matrix with:

```sh
pnpm --filter @filebelt/devops build
tests/scripts/prepare-image-plan.sh --channel build --output artifacts/phase1/image-plan.json
tests/scripts/run-image-matrix.sh --plan artifacts/phase1/image-plan.json --platform linux/amd64 --output-dir artifacts/phase1/amd64
tests/scripts/check-helm-chart.sh
```

The matrix creates local Docker image archives and evidence under `artifacts/`,
which is ignored by Git and safe to discard. Use a native ARM64 host for
`linux/arm64`. The CI RISC-V job cross-compiles the static probes and executes
them through the repository's rootless, digest-pinned QEMU helper. Smoke tests
refuse to replace a pre-existing local tag and remove every image tag they load
or build.

## License

Unless otherwise noted by a more specific file or directory, original
FileBelt work is licensed under Apache-2.0. FileBelt has no premium-only or
source-available feature region.
