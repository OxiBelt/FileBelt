#!/usr/bin/env sh
# SPDX-License-Identifier: GPL-3.0-or-later

# The source build must pin these upstream versions in its generated source
# inventory. This file records the approved composition boundary; release
# automation supplies immutable source archives, hashes, patches, and toolchain
# paths before it may execute configure.
set -eu

FFMPEG_VERSION=8.1.2
LIBAOM_VERSION=3.14.1
LIBVPX_VERSION=1.16.0
OPUS_VERSION=1.5.2

printf '%s\n' \
  "--enable-gpl" \
  "--disable-version3" \
  "--disable-nonfree" \
  "--enable-shared" \
  "--disable-static" \
  "--enable-libaom" \
  "--enable-libvpx" \
  "--enable-libopus" \
  "--disable-protocols" \
  "--enable-protocol=file" \
  "--enable-protocol=pipe"
