<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Corresponding-source release requirements

Every published `filebelt-ftp-ftps-gateway` image must provide an immutable
source URL in `io.filebelt.corresponding-source` and publish, for the exact
image digest:

- FileBelt adapter source, commit, signed tag, and GPL-3.0-or-later text;
- exact `libunftp` source, version, license notices, and any patches;
- adapter-local `Cargo.lock`, Dockerfile, build arguments, toolchain, and
  digest-pinned base/builder inputs;
- all copied license texts and third-party notices;
- an SBOM, provenance, per-platform digest mapping, and rebuild instructions;
- native linkage evidence, and replacement/relink instructions for every LGPL
  component when the exact dependency composition requires them.

Publication must fail if the image label, source revision, notices, SBOM, or
license expression disagree. An OCI image/Pod boundary alone is not a license
analysis; this gateway remains an independent process communicating only via
the generic FileBelt VFS protocol.
