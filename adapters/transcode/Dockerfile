# SPDX-License-Identifier: GPL-3.0-or-later

# This deliberately cannot build a release image without immutable inputs from
# the independent adapter image plan. Do not replace either input with a tag.
ARG FILEBELT_TRANSCODER_BUILDER_IMAGE
FROM ${FILEBELT_TRANSCODER_BUILDER_IMAGE} AS build

WORKDIR /src/adapters/transcode
COPY Cargo.toml ./
COPY Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

# The approved FFmpeg source build is supplied as a separately verified build
# context. It must use ffmpeg-build/configure-contract.sh and publish its full
# source/patch/configure/SBOM inventory before this stage is promotable.
ARG FILEBELT_TRANSCODER_RUNTIME_IMAGE
FROM ${FILEBELT_TRANSCODER_RUNTIME_IMAGE}
ARG SOURCE_URL
ARG SOURCE_REF
ARG SOURCE_REVISION
ARG CREATED
LABEL org.opencontainers.image.title="filebelt-transcoder" \
      org.opencontainers.image.description="FileBelt GPL FFmpeg transcoder" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.url="${SOURCE_URL}" \
      org.opencontainers.image.version="${SOURCE_REF}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      io.filebelt.image.role="filebelt-transcoder" \
      io.filebelt.corresponding-source="${SOURCE_URL}/tree/${SOURCE_REVISION}"
COPY --from=build /src/adapters/transcode/target/release/filebelt-transcoder /usr/local/bin/filebelt-transcoder
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/filebelt-transcoder"]
