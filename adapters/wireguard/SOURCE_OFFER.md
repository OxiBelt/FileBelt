<!-- SPDX-License-Identifier: Apache-2.0 -->

# Corresponding source

Each published `filebelt-wireguard-init` image digest is paired with an
immutable FileBelt release asset named
`filebelt-wireguard-init-source-<version>.tar.gz`. It contains the exact
FileBelt revision, unmodified WireGuard tools and iproute2 archives, checksums,
license texts, notices, build instructions, and all other material needed to
reproduce the image. The OCI labels record that asset URL and SHA-256.

The checked-in image plan is fail-closed: no image may be built or published
until the source asset exists and every pre-image and platform gate is
qualified.
