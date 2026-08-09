<!-- SPDX-License-Identifier: LGPL-3.0-or-later -->

# FileBelt NFSv4 adapter

This independent LGPL-3.0-or-later workspace contains the NFS-Ganesha dynamic
FSAL boundary and a Rust Unix-IPC bridge. It is excluded from the Apache Cargo
workspace and may exchange only bounded opaque VFS protobuf frames with Core.

The target is NFS-Ganesha `6.5-8` from the approved Ubuntu 26.04 snapshot. The
adapter image build must compile the ABI-specific callback translation unit
against that exact header/source set, dynamically load the resulting FSAL, and
publish the matching source, patches, notices, SBOM, and replacement/relinking
instructions. Neither the FSAL nor the bridge receives a PostgreSQL credential,
payload mount, FileBelt capability signing key, browser session, or raw Kerberos
ticket/keytab.

`bridge/` owns bounded `SOCK_SEQPACKET` framing only. It intentionally does not
depend on the Apache Core crate, because the generated VFS client is injected by
the image-specific bridge executable after protocol generation is verified.

Run the local framing and C boundary checks with:

```sh
cargo test --manifest-path Cargo.toml --offline
make -C ganesha-fsal-filebelt check
tests/contract.sh
```
