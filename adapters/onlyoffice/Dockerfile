# SPDX-License-Identifier: AGPL-3.0-only

# This source-first recipe cannot produce a release image until a design review
# admits exact digest-pinned builder/runtime images, the provider deployment,
# Core mTLS transport, and the aggregate license/SBOM evidence.
ARG FILEBELT_ONLYOFFICE_BUILDER_IMAGE
FROM ${FILEBELT_ONLYOFFICE_BUILDER_IMAGE} AS build

ARG SOURCE_URL
ARG SOURCE_REF
ARG SOURCE_REVISION
ENV FILEBELT_SOURCE_URL=${SOURCE_URL} \
    FILEBELT_SOURCE_REF=${SOURCE_REF} \
    FILEBELT_SOURCE_REVISION=${SOURCE_REVISION}

WORKDIR /src
# Build from the repository root so the adapter's Apache-2.0 protocol crate,
# generated protobuf source, and workspace metadata are present. The
# Dockerfile-specific ignore file keeps local and unrelated adapter state out.
COPY . .
RUN cargo build --locked --release --manifest-path adapters/onlyoffice/Cargo.toml

FROM scratch
ARG SOURCE_URL
ARG SOURCE_REF
ARG SOURCE_REVISION
ARG CREATED
ARG LICENSE_EXPRESSION
LABEL org.opencontainers.image.title="filebelt-onlyoffice-adapter" \
      org.opencontainers.image.description="FileBelt AGPL ONLYOFFICE adapter" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.url="${SOURCE_URL}" \
      org.opencontainers.image.version="${SOURCE_REF}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="${LICENSE_EXPRESSION}" \
      io.filebelt.image.role="filebelt-onlyoffice-adapter" \
      io.filebelt.corresponding-source="${SOURCE_URL}/tree/${SOURCE_REVISION}"
COPY --from=build /src/adapters/onlyoffice/target/release/filebelt-onlyoffice-adapter /filebelt-onlyoffice-adapter
USER 10001:10001
ENTRYPOINT ["/filebelt-onlyoffice-adapter"]
