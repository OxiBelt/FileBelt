<!-- SPDX-License-Identifier: Apache-2.0 -->

# Third-Party Notices

FileBelt Rust role images contain statically linked portions of these runtime
components:

- The Rust Standard Library 1.97.1. Copyrights are retained by The Rust
  Project Developers and the individual contributors identified by the
  upstream library copyright manifest. The library is generally available
  under Apache-2.0 or MIT terms, with the exact notices and exceptions recorded
  in `notices/Rust-COPYRIGHT-library.html` inside each Rust role image.
- musl libc 1.2.5. Copyright 2005-2020 Rich Felker and many other contributors,
  including the architecture and source-specific contributors identified by
  the installed copyright manifest. musl is generally available under MIT
  terms, with applicable source-specific notices recorded in
  `notices/musl-COPYRIGHT` inside each Rust role image.

The complete MIT license text is distributed as `LICENSES/MIT.txt`, and the
Apache-2.0 text is distributed as `LICENSES/Apache-2.0.txt`. Rust role image
labels include those terms. API, I/O worker, collaboration, MCP broker,
controller, VFS, Headscale-sync, and NFS relay images also contain unmodified WebPKI
certificate data under CDLA-Permissive-2.0. Maintenance and tools images
contain the same WebPKI data and add unmodified `option-ext` code under MPL-2.0
through the Apache Iggy client. Those images carry the applicable exact license
text and a versioned source or data pointer under `notices/`. Media controller
and MCP runner images remain `Apache-2.0 AND MIT`.

The web artifact carries Apache-2.0, MIT, ISC, and 0BSD content and ships its
browser and OxiBelt notices separately. It also carries this common notice
file, but the Rust component statements above apply only to Rust role images.

Builder images and build tools are build-time inputs and are not copied into
the final `scratch` images. Dependency admission evidence is maintained under
`supply-chain/`.
