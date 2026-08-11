<!-- SPDX-License-Identifier: LGPL-3.0-or-later -->

# FileBelt NFSv4 adapter

This independent LGPL-3.0-or-later workspace contains the NFS-Ganesha dynamic
FSAL boundary and a Rust Unix-IPC bridge. It is excluded from the Apache Cargo
workspace. The bridge consumes only the generated Apache VFS protocol over an
HTTPS process boundary; Apache packages do not import or link adapter code.

The target is NFS-Ganesha `6.5-8` and libntirpc `6.3-4` from the approved
Ubuntu 26.04 snapshot. The image builds the FSAL against the exact Ganesha
FSAL 13.0 headers, applies the reviewed RPCSEC_GSS accessor patch, and records
all source digests in `sources.lock.toml`. Neither process receives a
PostgreSQL credential, payload mount, FileBelt capability signing key, browser
session, or raw Kerberos ticket/keytab. The FSAL receives only the verified
canonical principal, `krb5p` status, numeric source address, absolute context
expiry, and a 32-byte opaque binding derived with `gss_pseudo_random` using
`GSS_C_PRF_KEY_FULL` and the fixed label `filebelt-nfs-v1` while the context
lock is held. PRF failure rejects authentication.

The private bridge and FSAL channels are Unix `SOCK_SEQPACKET` sockets with
length-prefixed frames bounded to 1,114,112 bytes. The bridge owns all VFS
envelope authority: tenant and gateway identity, gateway epoch, mapped session
and generation fences, and mutation request digests. FSAL input cannot supply
those fields. The bridge uses TLS 1.3, a private CA, no ambient roots or proxy,
an exact VFS endpoint path, and a client certificate whose leaf has exactly the
URI SAN `spiffe://filebelt/nfs-gateway/vfs`.

## Gateway lifecycle

On startup the bridge creates a fresh boot UUID and sends `GatewayHello` for
the configured tenant slug. It computes the canonical BLAKE3 manifest and root
handle digests, asks the local FSAL control endpoint to install the complete
desired export set atomically, verifies the readback, and sends
`GatewayReconcile`. It does not become ready or forward authentication until
Core acknowledges that exact epoch and manifest. It renews the 30-second lease
after 20 seconds. `bridge-drain` first persists a draining marker, then sends
`GatewayDrain`; readiness remains false even if the network call fails.

Each successful NFS authentication is cached only by the opaque GSS binding
until the earlier of the GSS and VFS expiries. Subsequent callbacks supply the
same binding plus NFSv4.1 client, session, slot, sequence, and operation index.
The bridge injects the authoritative session/generation fence and, for
mutations, a deterministic BLAKE3 request digest. Unknown, expired, wrong-realm,
multi-component, AUTH_SYS, non-privacy, or unbound requests fail closed.

The cross-implementation digest vector uses tenant
`00000000-0000-0000-0000-000000000009`, feature generation 5, export
generation 6, and sorted exports 7 and 11. Their drive UUIDs are respectively
`00000000-0000-0000-0000-00000000006b` and
`00000000-0000-0000-0000-00000000006f`; paths are `/filebelt/{drive_uuid}`;
generations are 3 and 4; both are writable; and root handles are 101 bytes of
`01` and `02`. The manifest digest is
`6149f35f85dd9be45674c927f06e5bba7e34b75e6b96a41318c4c41c3ac29067`.
The first root-handle digest is
`b9c50ac8bcb322617cfb23d529f2bbd8f1403eab600f0bb0ad46eb6104524f83`.

## Container commands

The same image is selected by argv. Kubernetes containers and lifecycle probes
must use these exact commands:

```text
filebelt-nfs ganesha
filebelt-nfs bridge
/contract/ganesha-health
/contract/ganesha-drain
/contract/bridge-health
/contract/bridge-drain
```

The bridge reads only `/etc/filebelt-nfs/bridge.toml`, the VFS client TLS files
under `/run/secrets/nfs-bridge-vfs-client-tls/`, the two fixed Unix sockets,
and its fixed state file. `bridge.example.toml` documents the exact format.

## Qualification status

The current callback translation unit is intentionally incomplete.
`filebelt_export.c` returns `ERR_FSAL_NOTSUPP`, and the local Ganesha control
server and filesystem callback marshalling are not yet implemented. Therefore
the Dockerfile is an ABI/source-build probe only and the image must not be
published, deployed, or advertised as NFS-ready. The OCI label
`filebelt.dev.qualification=abi-probe-only` records this fail-closed state.
Removing that sentinel requires the complete FSAL 13.0 callback set, atomic
control-server implementation, live NFSv4.1/krb5p qualification, generated
SBOM/notices, and release evidence.

Run the local framing and C boundary checks with:

```sh
cargo test --manifest-path Cargo.toml --offline
make -C ganesha-fsal-filebelt check
tests/contract.sh
```

An exact ABI check additionally requires the patched NFS-Ganesha 6.5 source
and configured build trees:

```sh
make -C ganesha-fsal-filebelt abi-check \
  GANESHA_SOURCE=/path/to/nfs-ganesha-6.5 \
  GANESHA_BUILD=/path/to/configured-build
```
