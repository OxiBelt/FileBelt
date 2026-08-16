<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# FileBelt FTP/FTPS gateway

This is the separate GPL-3.0-or-later FileBelt FTP/FTPS gateway workspace. It
is intentionally excluded from the Apache root Cargo workspace. It consumes a
future versioned, protocol-neutral FileBelt VFS service; it must never receive
a payload mount, a browser session cookie, raw metadata-database credentials,
or FTP-specific structures in the VFS contract.

## Approved security profile

- `libunftp` is pinned to exactly `0.23.0` in this workspace.
- Explicit FTPS is required; TLS 1.3 is the required policy floor.
- `PBSZ 0` then `PROT P` is required before any data connection.
- Plaintext credentials, `PROT C`, `CCC`, active `PORT`/`EPRT`, FXP, `SITE`,
  `APPE`, and `STOU` are rejected.
- Passive ports are bounded. libunftp associates a passive reservation with
  the control connection's source address and rejects active mode; FTPS data
  channels require `PROT P` before `PASV`.
- Every VFS operation is authorized against the common Virtual ACL action set;
  `MOUNT` begins a session and mutations reauthorize their exact action set.
- Gateway sessions carry credential, ACL/object, and gateway generations and
  stop on revalidation mismatch or expired authorization lease.

The gateway has an opt-in, read-only listener for the VFS read slice:

- The VFS FTPS authentication exchange carries the raw FTP `PASS` value only
  over its mutually authenticated transport. Core verifies it against its
  encrypted `HMAC(pepper, password)` verifier; the gateway never receives the
  pepper or a verifier. The exchange is ephemeral, is never logged or
  persisted, and is cleared after every transport attempt. The generated enum
  name still mentions HMAC, but it does not mean the gateway computes one.
- The admitted `libunftp` 0.23.0 parser rejects every `PBSZ` value other than
  literal `0` before the command handler. Its builder enforces TLS 1.3,
  explicit FTPS on both channels, passive-only mode, and the bounded passive
  range.
- VFS supports `LIST`, `STAT`, `OPEN`, `READ`, and `CLOSE`. The adapter resolves
  every FTP path component afresh using VFS `LIST` responses below a configured
  drive/root UUID; it neither uses host paths nor trusts a stale UUID cache.
  Uploads, rename/delete, metadata updates, and directory creation remain
  unavailable and return the framework's not-implemented response.

The executable remains disabled (exit 78) until an operator explicitly sets
`FILEBELT_FTPS_ENABLE_READ_ONLY=true` and provides all VFS mTLS, TLS server,
gateway, passive-range, and fixed virtual-root inputs. It never falls back to
a host-backed store.

Required inputs are `FILEBELT_FTPS_TENANT_ID`, `FILEBELT_FTPS_GATEWAY_ID`,
`FILEBELT_FTPS_SHARD_KEY`, `FILEBELT_FTPS_DRIVE_ID`,
`FILEBELT_FTPS_ROOT_NODE_ID`, `FILEBELT_VFS_URL`,
`FILEBELT_VFS_CA_PEM_FILE`, `FILEBELT_VFS_CLIENT_CERT_PEM_FILE`,
`FILEBELT_VFS_CLIENT_KEY_PEM_FILE`, `FILEBELT_FTPS_CERT_FILE`,
`FILEBELT_FTPS_KEY_FILE`, `FILEBELT_FTPS_BIND_ADDRESS`,
`FILEBELT_FTPS_PASSIVE_HOST`, `FILEBELT_FTPS_PASSIVE_PORT_START`, and
`FILEBELT_FTPS_PASSIVE_PORT_END`.

## Local policy tests

The policy module is dependency-free so it can be tested without fetching
unreviewed upstream code:

```sh
rustc --edition 2024 --test src/lib.rs -o /tmp/filebelt-ftp-ftps-policy-tests
/tmp/filebelt-ftp-ftps-policy-tests
```

The adapter-local lockfile pins the admitted source. Run the normal adapter
workspace checks with no registry access:

```sh
cargo fmt --check --manifest-path Cargo.toml
cargo test --manifest-path Cargo.toml --locked --offline
```

The tests include a compile-bound `libunftp` builder contract for TLS 1.3,
FTPS-required control/data channels, passive-only data mode, and a bounded
passive range. They also validate the VFS zero-epoch hello, ephemeral raw
password exchange clearing, request/response correlation, and existence-hiding
error mapping. A public-listener parser contract test exercises rejection of
`PBSZ 1`; this sandbox cannot create loopback listeners, so that portion is
skipped locally and runs where loopback binds are permitted.

## Image and source distribution

`Dockerfile` is a build recipe skeleton, intentionally blocked on a verified
digest-pinned builder/base image and the release-reviewed cross-workspace VFS
source input. Do not replace those inputs with a mutable image tag or copy a
host payload mount into the build. See [SOURCE_OFFER.md](SOURCE_OFFER.md) for
required published materials.

Any future AMD64 image build must take only the adapter-plan-derived
`FILEBELT_AMD64_ISA=x86-64-v3` and apply it to the gateway and native
dependencies. This preserves the currently blocked image-build and
publication state.
