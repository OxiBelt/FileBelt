<!-- SPDX-License-Identifier: LGPL-3.0-or-later -->

# NFS Adapter Third-Party Notices

This adapter targets these pinned primary components:

- NFS-Ganesha 6.5-8 / upstream V6.5, LGPL-3.0-or-later;
- libntirpc 6.3-4, BSD-style and other file-level terms supplied in its source;
- Ubuntu 26.04 `resolute` packages from the pinned snapshot; and
- Rust 1.97.1 plus the exact adapter-local dependency graph in `Cargo.lock`.

The source URLs, revisions, and SHA-256 digests are recorded in
`sources.lock.toml`. The image carries the Ganesha and libntirpc source archives,
Debian packaging, exact-digest FileBelt patches, and this adapter source. The
patches preserve lower-FSAL authorization through MDCACHE and add an optional
FSAL owner/group-name projection hook to the NFSv4 encoder. The FileBelt bridge
and FSAL sources are licensed LGPL-3.0-or-later; the consumed generated VFS
schema crate remains Apache-2.0 and crosses the documented adapter boundary.

Before publication, release automation must generate and review a complete
file-level/package-level inventory, include every applicable license and
copyright notice, produce an SBOM for the resolved image, and bind all evidence
to the image digest. This human-readable summary does not replace that evidence.
