<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt agent guidance

## Project boundaries

FileBelt is a public mixed-license monorepo. PostgreSQL is authoritative for
metadata and policy state, UUID-addressed storage is the payload plane, and
Apache Iggy is notification only. Host filesystem ownership never represents a
FileBelt user. Every access path must resolve an internal principal and enforce
the common Virtual ACL model.

## Mandatory planning

Enter Plan Mode before creating a service or image, changing persisted data,
authorization or namespace semantics, adding a protocol or external
integration, changing a public contract, or moving code across a license
boundary. Read applicable ADRs and component guidance first. Do not silently
choose security, durability, compatibility, or licensing semantics.

## Dependency and license direction

- Root Cargo and pnpm workspaces contain Apache-2.0 packages only.
- Apache packages must never import, link, or path-depend on implementation
  code under `adapters/`.
- Adapters may consume Apache protocol schemas or clients through a documented,
  replaceable process boundary.
- Domain and authorization packages remain independent of SQL, HTTP,
  Kubernetes, UI, Iggy, and adapter implementation types.
- Rust packages inherit `unsafe_code = "deny"`; exceptions require an accepted
  ADR and an entry in the unsafe-exception registry.

## Change discipline

Use Conventional Commits and add regression coverage at the lowest useful
layer. Update ADRs, threat models, operator documentation, license evidence,
and rollback notes whenever their boundary changes. Preserve deterministic
resource naming and cleanup in tests. Never make an event stream the sole
record of committed state.

## Required bootstrap checks

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

Phase-specific Docker, browser, Kubernetes, release, and integration commands
become mandatory only when those artifacts exist; never replace them with a
false-positive placeholder.
