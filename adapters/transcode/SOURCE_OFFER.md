<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Corresponding-source release requirements

Every published `filebelt-transcoder` image must provide its immutable source
URL in `io.filebelt.corresponding-source` and publish, for that image digest:

- the FileBelt GPL wrapper source, signed tag, GPL text, and adapter-local lockfile;
- FFmpeg `8.1.2`, libaom `3.14.1`, libvpx `1.16.0`, and Opus `1.5.2` source,
  licenses, patches, hashes, and build instructions;
- the complete configure invocation generated from
  `ffmpeg-build/configure-contract.sh`, including every enabled parser,
  decoder, demuxer, encoder, muxer, and filter;
- immutable builder/runtime inputs, dynamic-linkage evidence, notices, SBOM,
  vulnerability result, provenance, and per-platform digest mapping; and
- the malicious-input corpus result and normalized rebuild evidence for native
  AMD64 and ARM64. RISC-V remains compile/probe-only and is not published in a
  transcode manifest.

The image must retain dynamic FFmpeg linkage and must not enable `version3`,
`nonfree`, NVIDIA support, an unreviewed codec/filter/protocol, or static
linkage. The wrapper receives only local `emptyDir` paths and never a database
credential, browser session, payload/cache mount, service-account token, or
network route.
