<!-- SPDX-License-Identifier: Apache-2.0 -->

# Supply-Chain Policy

Rust and Node lockfiles are committed. Dependencies use reviewed registries and
exact versions; unpinned Git sources and unexpected lifecycle scripts are
blocked. Apache runtime graphs allow reviewed permissive licenses. MPL, CDDL,
LGPL, GPL, AGPL, native linkage, bundled source, and `*-sys` dependencies need
an accepted review before admission.

Rust changes run `cargo audit`, `cargo deny`, and `cargo vet`. Node changes use
frozen pnpm installation with scripts disabled, license admission, audit,
linting, typechecking, tests, and build checks. GitHub Actions are pinned by
commit and run with read-only permissions during pull-request validation.
The Node license admission step compares pnpm's resolved report with
`supply-chain/node-policy.toml` and fails closed on every unknown license.

Future images must use digest-pinned bases and produce an SBOM, vulnerability
scan, provenance, truthful license label, and exact public-source mapping before
publication. Build jobs never receive package-write permission.
