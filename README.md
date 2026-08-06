<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt

FileBelt is a public, self-hostable web drive built primarily in Rust and
TypeScript. The project is Kubernetes-first, uses PostgreSQL as authoritative
metadata state, and applies one application-level Virtual ACL model across web
and protocol access paths.

This repository is in its governance and workspace-bootstrap phase. The
packages currently compile as placeholders; no service, database schema, API,
container image, or production deployment is implemented yet.

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
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
corepack pnpm install --frozen-lockfile --ignore-scripts
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

Additional supply-chain checks are described in
[`docs/SupplyChain.md`](docs/SupplyChain.md).

## License

Unless otherwise noted by a more specific file or directory, original
FileBelt work is licensed under Apache-2.0. FileBelt has no premium-only or
source-available feature region.
