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

The source/license qualification gate must pass before an image is built.
Image publication additionally requires complete SBOM, vulnerability,
provenance, native-platform, SHA-256 repository, restore, and fsck evidence.
