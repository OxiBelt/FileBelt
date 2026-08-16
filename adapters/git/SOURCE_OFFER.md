<!-- SPDX-License-Identifier: Apache-2.0 -->

# Corresponding source

The FileBelt wrapper source is Apache-2.0. The aggregate image also contains a
separate GPL-2.0-only Git `2.55.0` executable.

Before any network deployment or distribution, publish the immutable source
bundle for the exact FileBelt revision and image. It contains the wrapper,
linked Apache revision-protocol source and generated output, the exact Git and
zlib source archives, the versioned Cargo vendor closure, build recipes and
flags, patches (if any), licenses, and notices. The release manifest and image
label bind that bundle URL and SHA-256 to the image index and platform digests.
For `linux/amd64`, those reproducible inputs include the closed
`FILEBELT_AMD64_ISA=x86-64-v3` and `FILEBELT_TARGET_CPU=x86-64-v3` arguments,
Rust `-Ctarget-cpu=x86-64-v3`, C/C++ `-march=x86-64-v3`, and the GNU linker
`-z x86-64-v3` property requirement. Other architectures retain their
architecture-default compiler settings.

The source/license qualification gate must pass before an image is built.
Image publication additionally requires complete SBOM, vulnerability,
provenance, native-platform, SHA-256 repository, restore, and fsck evidence.
