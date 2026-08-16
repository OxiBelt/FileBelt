<!-- SPDX-License-Identifier: LGPL-3.0-or-later -->

# NFS adapter corresponding source and relinking contract

The adapter Dockerfile embeds the following materials under
`/usr/share/filebelt-nfs/corresponding-source/`:

- this adapter source, Cargo lockfile, Dockerfile, build scripts, and notices;
- Ubuntu source artifacts for NFS-Ganesha `6.5-8` and libntirpc `6.3-4`; and
- every FileBelt patch applied to NFS-Ganesha.

`sources.lock.toml` pins the download URLs and SHA-256 digests, the Ubuntu
snapshot and base-image manifest, the upstream Ganesha V6.5 tag/commit, every
FileBelt patch digest, FSAL ABI 13.0, and the Rust toolchains for each supported
architecture. The Dockerfile records the complete CMake flags and rebuild
process.

For `linux/amd64`, that process requires the closed
`FILEBELT_AMD64_ISA=x86-64-v3` and `FILEBELT_TARGET_CPU=x86-64-v3` arguments,
Rust `-Ctarget-cpu=x86-64-v3`, C/C++ `-march=x86-64-v3`, and GNU linker
`-z x86-64-v3` properties for the bridge, Ganesha executable, and dynamic FSAL.
Other architectures retain their architecture-default compiler settings.

For every published image digest, the release must also publish the exact
FileBelt source revision, generated package and Rust dependency inventory,
license texts, SBOM, compiler/linker inputs, and any build-time generated files
not present here. Recipients must be able to rebuild and replace the dynamic
`libfsalfilebelt.so` with a modified compatible module; see `RELINKING.md`.
This repository source alone is not a written offer for an unbuilt image, and
the current ABI-probe-only image is not publication-qualified.
