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
labels use the aggregate expression `Apache-2.0 AND MIT`. The Apache-only web
artifact does not ship this Rust-specific notice or the MIT license text.

Builder images and build tools are build-time inputs and are not copied into
the final `scratch` images. Dependency admission evidence is maintained under
`supply-chain/`.
