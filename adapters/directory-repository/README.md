<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt directory-repository adapter

This is an isolated Apache-2.0 scaffold for the private directory-repository
process. It will invoke an exact, separately distributed GPL-2.0-only Git
executable without linking it. It has no database, payload, browser, or network
egress credential and exposes no public Git transport, listener, image, or
deployment activation.

One bare repository is addressed by an opaque FileBelt directory-root UUID.
The private mTLS identity is fixed to
`spiffe://filebelt/directory-repository-coordinator/git`; a future listener
must accept only that identity, one bounded request, then close. The generated
DTO validator and bounded private framing are available from
`protocol/directory_repository/v1/directory_repository.proto`; the transport
consumer remains deliberately disabled, so this scaffold still starts no
listener or public Git transport.

The scaffold validates the contract's deterministic tree invariants before any
system-Git invocation: algorithm-tagged SHA-1/SHA-256 OIDs, modes `040000` and
`100644`, canonical paths, no case-folded `.git`, zero-byte `.filebeltkeep` as
the only entry in an otherwise empty directory, and bounded blobs, packs,
commits, changed paths, and tree entries. `.gitattributes` remains ordinary
data for the upper layer to validate.

The adapter never permits user configuration, remotes, alternates, replace
refs, worktrees, external filters, protocols, prompts, or hooks other than a
future immutable adapter-owned receive bridge.

This scaffold is not an activation-ready dispatcher. Before any listener or
Git command can be enabled, the adapter must derive inspection data from the
staged Git graph, bind `Verify` to `Promote`, persist and enforce fencing-token
high-water state, preflight repeated-field resource use before Protobuf
allocation, and harden the exact absolute Git executable with bounded
execution and an adapter-owned environment. The PostgreSQL side must also
complete current Virtual ACL/signer admission, canonical snapshot-digest
verification, ruleset serialization, idempotent crash replay, and root-move
integration. Absence of production grants and this binary's unconditional
unavailable exit are the compatibility release's enforcement boundary.

Run local checks:

```sh
cargo fmt --check --manifest-path adapters/directory-repository/Cargo.toml
cargo test --manifest-path adapters/directory-repository/Cargo.toml --locked --offline
cargo deny check --manifest-path adapters/directory-repository/Cargo.toml
```
