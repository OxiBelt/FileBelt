# syntax=docker/dockerfile:1.7
# SPDX-License-Identifier: GPL-2.0-only

# This is a source-first, non-publishable sentinel. Admission must provide
# exact digest-pinned, ABI-compatible builder and runtime images plus complete
# Git/source/SBOM/provenance evidence before an image is built or published.
ARG FILEBELT_GIT_BUILDER_IMAGE
ARG FILEBELT_GIT_RUNTIME_IMAGE
FROM ${FILEBELT_GIT_BUILDER_IMAGE} AS build

ARG GIT_VERSION=2.55.0
ARG GIT_TARBALL_SHA256=457fdb04dc8728e007d4688695e6912e6f680727920f2a40bf11eacc17505357
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl libcurl4-openssl-dev libexpat1-dev \
      libssl-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*
RUN curl -fsSLo /tmp/git.tar.xz "https://www.kernel.org/pub/software/scm/git/git-${GIT_VERSION}.tar.xz" && \
    echo "${GIT_TARBALL_SHA256}  /tmp/git.tar.xz" | sha256sum -c - && \
    tar -xJf /tmp/git.tar.xz -C /tmp && \
    make -C "/tmp/git-${GIT_VERSION}" prefix=/opt/filebelt-git NO_GETTEXT=YesPlease NO_TCLTK=YesPlease NO_INSTALL_HARDLINKS=YesPlease -j"$(nproc)" all && \
    make -C "/tmp/git-${GIT_VERSION}" prefix=/opt/filebelt-git NO_GETTEXT=YesPlease NO_TCLTK=YesPlease NO_INSTALL_HARDLINKS=YesPlease install && \
    /opt/filebelt-git/bin/git --version | grep -Fx "git version ${GIT_VERSION}"
COPY adapters/git adapters/git
COPY source/crates/filebelt-revision-protocol source/crates/filebelt-revision-protocol
COPY protocol/generated/rust/filebelt/revision/v1/filebelt.revision.v1.rs protocol/generated/rust/filebelt/revision/v1/filebelt.revision.v1.rs
RUN cargo build --locked --release --manifest-path adapters/git/Cargo.toml

FROM ${FILEBELT_GIT_RUNTIME_IMAGE}
ARG SOURCE_URL
ARG SOURCE_REF
ARG SOURCE_REVISION
ARG CREATED
LABEL org.opencontainers.image.title="filebelt-git-adapter" \
      org.opencontainers.image.description="FileBelt GPL system-Git revision adapter" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.version="${SOURCE_REF}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="GPL-2.0-only" \
      io.filebelt.image.role="filebelt-git-adapter" \
      io.filebelt.git.version="2.55.0" \
      io.filebelt.qualification="source-sentinel-only" \
      io.filebelt.corresponding-source="${SOURCE_URL}/tree/${SOURCE_REVISION}"
COPY --from=build /opt/filebelt-git /opt/filebelt-git
COPY --from=build /src/adapters/git/target/release/filebelt-git-adapter /usr/local/bin/filebelt-git-adapter
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/filebelt-git-adapter"]
