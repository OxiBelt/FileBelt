# SPDX-License-Identifier: GPL-3.0-or-later
# Build context must provide a verified, locally reviewed Samba 4.24.4 source
# archive under vendor/. This Dockerfile intentionally performs no network fetch.
ARG FILEBELT_SAMBA_BUILDER_IMAGE
FROM ${FILEBELT_SAMBA_BUILDER_IMAGE} AS build
ARG SAMBA_VERSION=4.24.4
COPY vendor/samba-4.24.4.tar.gz /src/samba-4.24.4.tar.gz
COPY samba-vfs-filebelt /src/filebelt/samba-vfs-filebelt
RUN test "$SAMBA_VERSION" = 4.24.4 && \
    test -s /src/samba-4.24.4.tar.gz && \
    echo 'df2c51ab4361ec626ab9988e5946efcca8465bc7afae834291d5558468265ff8  /src/samba-4.24.4.tar.gz' | sha256sum -c - && \
    echo 'Provide reviewed build dependencies and exact archive checksum in the release build manifest.' >&2 && exit 1

# A release implementation replaces this deliberate fail-closed stage only with
# reviewed package snapshots, a verified archive checksum, and recorded flags.
