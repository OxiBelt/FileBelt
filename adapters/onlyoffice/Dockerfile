# syntax=docker/dockerfile:1.7
# SPDX-License-Identifier: AGPL-3.0-only

# The ordinary build context is the exact tracked FileBelt source tree overlaid
# with qualified inputs under adapter-inputs/onlyoffice/. The source-bundle
# validator must admit that overlay before this image recipe is invoked.
ARG FILEBELT_ONLYOFFICE_BUILDER_IMAGE
FROM ${FILEBELT_ONLYOFFICE_BUILDER_IMAGE} AS build

ARG FILEBELT_ONLYOFFICE_BUILDER_IMAGE
ARG SOURCE_URL
ARG SOURCE_REF
ARG SOURCE_REVISION
ARG CORRESPONDING_SOURCE_URL
ARG CORRESPONDING_SOURCE_SHA256
ARG CHART_VERSION
ARG LICENSE_QUALIFICATION
ARG IMAGE_BUILD_STATE
ARG RUST_TARGET
ENV FILEBELT_SOURCE_URL=${SOURCE_URL} \
    FILEBELT_SOURCE_REF=${SOURCE_REF} \
    FILEBELT_SOURCE_REVISION=${SOURCE_REVISION} \
    FILEBELT_CORRESPONDING_SOURCE_URL=${CORRESPONDING_SOURCE_URL} \
    FILEBELT_CORRESPONDING_SOURCE_SHA256=${CORRESPONDING_SOURCE_SHA256} \
    FILEBELT_CHART_VERSION=${CHART_VERSION}

WORKDIR /src
COPY . .
# The qualified source bundle supplies Cargo's complete versioned vendor
# closure and source-replacement configuration. Network-disabled compilation
# proves that neither registry crates nor provider assets are fetched.
COPY adapter-inputs/onlyoffice/.cargo/config.toml /src/.cargo/config.toml
COPY adapter-inputs/onlyoffice/vendor/cargo/ /src/vendor/cargo/
RUN --network=none set -eu; \
    printf '%s' "${FILEBELT_ONLYOFFICE_BUILDER_IMAGE}" | grep -Eq '^.+@sha256:[0-9a-f]{64}$'; \
    test "${LICENSE_QUALIFICATION}" = qualified; \
    test "${IMAGE_BUILD_STATE}" = eligible; \
    test -n "${RUST_TARGET}"; \
    test -s adapter-inputs/onlyoffice/SOURCE-MANIFEST.json \
    && test -s adapter-inputs/onlyoffice/BUILD.md \
    && test -s adapter-inputs/onlyoffice/LICENSES/AGPL-3.0-only.txt \
    && test -s adapter-inputs/onlyoffice/LICENSES/Apache-2.0.txt \
    && test -s adapter-inputs/onlyoffice/NOTICES/THIRD_PARTY_NOTICES.md \
    && cargo build --locked --offline --release \
      --features qualified-release \
      --target "${RUST_TARGET}" \
      --manifest-path adapters/onlyoffice/Cargo.toml \
    && cp "adapters/onlyoffice/target/${RUST_TARGET}/release/filebelt-onlyoffice-adapter" /filebelt-onlyoffice-adapter \
    && chmod 0555 /filebelt-onlyoffice-adapter \
    && ! readelf -l /filebelt-onlyoffice-adapter | grep -q 'Requesting program interpreter' \
    && ! readelf -d /filebelt-onlyoffice-adapter 2>&1 | grep -q '(NEEDED)'

FROM scratch
ARG SOURCE_URL
ARG SOURCE_REF
ARG SOURCE_REVISION
ARG CORRESPONDING_SOURCE_URL
ARG CORRESPONDING_SOURCE_SHA256
ARG CREATED
ARG LICENSE_EXPRESSION
ARG LICENSE_QUALIFICATION
ARG IMAGE_BUILD_STATE
LABEL org.opencontainers.image.title="filebelt-onlyoffice-adapter" \
      org.opencontainers.image.description="FileBelt AGPL ONLYOFFICE adapter" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.url="${CORRESPONDING_SOURCE_URL}" \
      org.opencontainers.image.version="${SOURCE_REF}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="${LICENSE_EXPRESSION}" \
      io.filebelt.image.role="filebelt-onlyoffice-adapter" \
      io.filebelt.first-party-license="AGPL-3.0-only" \
      io.filebelt.corresponding-source="${CORRESPONDING_SOURCE_URL}" \
      io.filebelt.corresponding-source.sha256="${CORRESPONDING_SOURCE_SHA256}" \
      io.filebelt.qualification.license="${LICENSE_QUALIFICATION}" \
      io.filebelt.qualification.image-build="${IMAGE_BUILD_STATE}"
COPY --from=build /filebelt-onlyoffice-adapter /filebelt-onlyoffice-adapter
COPY --from=build /src/adapter-inputs/onlyoffice/LICENSES/AGPL-3.0-only.txt /licenses/AGPL-3.0-only.txt
COPY --from=build /src/adapter-inputs/onlyoffice/LICENSES/Apache-2.0.txt /licenses/Apache-2.0.txt
COPY --from=build /src/adapter-inputs/onlyoffice/NOTICES/ /licenses/third-party/
COPY --from=build /src/adapter-inputs/onlyoffice/NOTICES/THIRD_PARTY_NOTICES.md /doc/THIRD_PARTY_NOTICES.md
COPY --from=build /src/adapters/onlyoffice/SOURCE_OFFER.md /doc/SOURCE_OFFER.md
COPY --from=build /src/adapter-inputs/onlyoffice/SOURCE-MANIFEST.json /doc/SOURCE-MANIFEST.json
COPY --from=build /src/adapter-inputs/onlyoffice/BUILD.md /doc/BUILD.md
USER 10001:10001
ENTRYPOINT ["/filebelt-onlyoffice-adapter"]
