<!-- SPDX-License-Identifier: LGPL-3.0-or-later -->

# Rebuilding and replacing the FileBelt FSAL

The FileBelt NFS module is a dynamically loaded NFS-Ganesha FSAL. A recipient
may modify the source embedded in the image, rebuild it against the exact
NFS-Ganesha 6.5 / FSAL 13.0 header and library set, and replace
`libfsalfilebelt.so` in a derived image.

1. Extract `/usr/share/filebelt-nfs/corresponding-source/` from the image.
2. Verify all archives against `filebelt-adapter/sources.lock.toml`.
3. Reproduce the `ganesha-builder` stage in `filebelt-adapter/Dockerfile`, or
   use that stage directly after modifying `ganesha-fsal-filebelt/` or patches.
4. Run `abi-check` against the configured Ganesha tree, build the module, and
   replace the installed module under Ganesha's multiarch FSAL directory in a
   derived image. Do not modify the unmodified system libraries merely to load
   a replacement FSAL.
5. Retain the LGPL source, notices, patches, relinking instructions, and the
   exact source/build evidence for the derived image.

A replacement is compatible only when the ABI probe passes against the pinned
FSAL 13.0 header set. FileBelt readiness is intentionally fail closed: the
current source contains an unqualified callback sentinel and cannot serve an
export. Replacing or removing it does not by itself qualify a module; the full
callback and krb5p acceptance suite remains mandatory.
