# SPDX-License-Identifier: GPL-3.0-or-later
# Build context must provide a verified, locally reviewed Samba 4.24.6 source
# archive under vendor/. This Dockerfile intentionally performs no network fetch.
ARG FILEBELT_SAMBA_BUILDER_IMAGE
FROM ${FILEBELT_SAMBA_BUILDER_IMAGE} AS build
ARG SAMBA_VERSION=4.24.6
COPY vendor/samba-4.24.6.tar.gz /src/samba-4.24.6.tar.gz
COPY samba-vfs-filebelt /src/filebelt/samba-vfs-filebelt
RUN test "$SAMBA_VERSION" = 4.24.6 && \
    test -s /src/samba-4.24.6.tar.gz && \
    echo '810cc955acb367e9bde556dccfb50db177a02b7c553aa1629a0b905fa7616267  /src/samba-4.24.6.tar.gz' | sha256sum -c - && \
    echo 'Provide reviewed build dependencies and exact archive checksum in the release build manifest.' >&2 && exit 1

# A release implementation replaces this deliberate fail-closed stage only with
# reviewed package snapshots, a verified archive checksum, and recorded flags.
