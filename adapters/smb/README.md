<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# FileBelt Samba gateway

This is the optional GPL-3.0-or-later Samba 4.24.6 adapter region. It is not
part of the Apache root workspace and does not contain Samba source. The VFS
module is loaded by `smbd`; its local bridge framing is GPL. The future FileBelt
VFS RPC remains protocol-neutral and Apache-2.0.

## Security boundary

`smbd` authenticates SMB and provides session/share-mode semantics. The module
must bind each request to an authenticated FileBelt mount session and observed
device context. The bridge must provide bounded queues, validate the local
frame, and pass only opaque FileBelt IDs/operation bytes to the generic VFS
service. Neither component receives a payload mount, API signing key, or
general PostgreSQL credential. FileBelt evaluates current Virtual ACL and
generation/fencing values for every sensitive operation; Iggy is only an
invalidation hint.

The first real gateway must run only on the approved Headscale tailnet and may
not fall back to a local filesystem. `ops/smb.conf.template` requires SMB 3.1.1,
signing, encryption, and no guest access. The placeholder share path is empty
bootstrap state, not file storage.

`protocol-compat/session-and-locking.md` records the adapter's required mount
session and stale-handle behavior. It deliberately does not choose durable
handle continuity, write-conflict policy, or active-active failover; those
remain core-contract decisions.

## Build and source offer

Do not build or publish from this scaffold yet. The manifest pins Samba 4.24.6
to the verified official archive SHA-256; a release must still include Samba
source, FileBelt adapter source, patches, build/config scripts, notices, base
image digest, SBOM, and exact public source URL, and label the image GPL-3.0-or-later plus
`io.filebelt.corresponding-source`. Never fetch an unverified upstream archive
during Docker build.

A future AMD64 build contract must accept only the adapter-plan-derived
`FILEBELT_AMD64_ISA=x86-64-v3` and apply it to both Samba and the FileBelt VFS
bridge. This is a recorded prerequisite, not a completed image-build or
publication qualification.

Run the adapter-only checks with `cargo test --manifest-path adapters/smb/Cargo.toml` and `tests/run-tests.sh`.
