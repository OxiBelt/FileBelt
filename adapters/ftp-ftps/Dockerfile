# SPDX-License-Identifier: GPL-3.0-or-later

# This is deliberately not a buildable release Dockerfile yet. The exact
# builder and runtime digest, resolved libunftp source, adapter-local lockfile,
# native linkage, and aggregate license expression have not been admitted.
# Do not replace these required inputs with mutable tags.
ARG FILEBELT_FTP_BUILDER_IMAGE
FROM ${FILEBELT_FTP_BUILDER_IMAGE} AS build

WORKDIR /src/adapters/ftp-ftps
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# A release build must use the full reviewed source context because this
# workspace consumes the Apache filebelt-vfs-protocol path dependency. It may
# run `cargo build --locked --release` only after the image plan provides a
# digest-pinned builder/base and records that exact context in the SBOM.

FROM scratch
ARG SOURCE_URL
ARG SOURCE_REF
ARG SOURCE_REVISION
ARG CREATED
ARG LICENSE_EXPRESSION
LABEL org.opencontainers.image.title="filebelt-ftp-ftps-gateway" \
      org.opencontainers.image.description="FileBelt GPL FTP/FTPS gateway" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.url="${SOURCE_URL}" \
      org.opencontainers.image.version="${SOURCE_REF}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="${LICENSE_EXPRESSION}" \
      io.filebelt.image.role="filebelt-ftp-ftps-gateway" \
      io.filebelt.corresponding-source="${SOURCE_URL}/tree/${SOURCE_REVISION}"
# The release stage may be completed only after the above arguments are made
# fail-closed by adapter image-plan validation and the aggregate expression is
# reviewed. It must run as numeric 10001:10001 with a read-only root filesystem.
