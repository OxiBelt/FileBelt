# syntax=docker/dockerfile:1.7
# SPDX-License-Identifier: Apache-2.0

# The shared adapter evidence assembler owns this build context. It must stage
# checksum-verified source and a versioned Cargo vendor closure before setting
# both qualification arguments to their accepted values. There is deliberately
# no downloader or package-manager fallback in this recipe.
ARG FILEBELT_GIT_BUILDER_IMAGE
ARG SOURCE_URL
ARG SOURCE_REF
ARG SOURCE_REVISION
ARG CREATED
ARG IMAGE_LICENSES
ARG CORRESPONDING_SOURCE_URL
ARG CORRESPONDING_SOURCE_SHA256
ARG LICENSE_QUALIFICATION
ARG IMAGE_BUILD_STATE
ARG RUST_TARGET
ARG ZLIB_TARBALL_SHA256
ARG TARGETARCH
ARG FILEBELT_AMD64_ISA
ARG FILEBELT_TARGET_CPU

FROM ${FILEBELT_GIT_BUILDER_IMAGE} AS build

ARG FILEBELT_GIT_BUILDER_IMAGE
ARG SOURCE_URL
ARG SOURCE_REF
ARG SOURCE_REVISION
ARG CREATED
ARG IMAGE_LICENSES
ARG CORRESPONDING_SOURCE_URL
ARG CORRESPONDING_SOURCE_SHA256
ARG LICENSE_QUALIFICATION
ARG IMAGE_BUILD_STATE
ARG RUST_TARGET
ARG ZLIB_TARBALL_SHA256
ARG TARGETARCH
ARG FILEBELT_AMD64_ISA
ARG FILEBELT_TARGET_CPU

ARG GIT_VERSION=2.55.0
ARG GIT_TARBALL_SHA256=457fdb04dc8728e007d4688695e6912e6f680727920f2a40bf11eacc17505357
ARG ZLIB_VERSION=1.3.1

WORKDIR /src

COPY adapter-inputs/git/upstream/git-2.55.0.tar.xz /inputs/git-2.55.0.tar.xz
COPY adapter-inputs/git/upstream/zlib-1.3.1.tar.gz /inputs/zlib-1.3.1.tar.gz
COPY adapter-inputs/git/vendor /inputs/vendor
COPY adapter-inputs/git/SOURCE-MANIFEST.json /evidence/SOURCE-MANIFEST.json
COPY adapter-inputs/git/LICENSES/GPL-2.0-only.txt /evidence/GPL-2.0-only.txt
COPY LICENSES/Apache-2.0.txt /evidence/Apache-2.0.txt
COPY source/ops/runtime/musl-COPYRIGHT /evidence/musl-COPYRIGHT
COPY adapters/git adapters/git
COPY Cargo.toml Cargo.toml
COPY source source
COPY protocol protocol
COPY fuzz fuzz
COPY tests tests

RUN --network=none set -eu; \
    printf '%s' "${FILEBELT_GIT_BUILDER_IMAGE}" | grep -Eq '^.+@sha256:[0-9a-f]{64}$'; \
    test "${LICENSE_QUALIFICATION}" = "qualified"; \
    test "${IMAGE_BUILD_STATE}" = "eligible"; \
    case "${SOURCE_URL}" in https://*) ;; *) exit 1 ;; esac; \
    test -n "${SOURCE_REF}"; \
    case "${SOURCE_REF}" in main|master|latest) exit 1 ;; esac; \
    printf '%s' "${SOURCE_REVISION}" | grep -Eq '^[0-9a-f]{40}$'; \
    printf '%s' "${CREATED}" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'; \
    test -n "${IMAGE_LICENSES}"; \
    for license in Apache-2.0 GPL-2.0-only MIT Zlib; do \
      printf '%s' "${IMAGE_LICENSES}" | grep -Fq "${license}"; \
    done; \
    case "${CORRESPONDING_SOURCE_URL}" in https://*) ;; *) exit 1 ;; esac; \
    case "${CORRESPONDING_SOURCE_URL}" in */tree/main|*/tree/master|*/latest/*) exit 1 ;; esac; \
    printf '%s' "${CORRESPONDING_SOURCE_SHA256}" | grep -Eq '^[0-9a-f]{64}$'; \
    test -n "${RUST_TARGET}"; \
    case "${TARGETARCH}" in \
      amd64) test "${FILEBELT_AMD64_ISA}" = x86-64-v3; test "${FILEBELT_TARGET_CPU}" = x86-64-v3 ;; \
      arm64) test -z "${FILEBELT_AMD64_ISA}"; test "${FILEBELT_TARGET_CPU}" = architecture-default ;; \
      *) exit 1 ;; \
    esac; \
    printf '%s' "${ZLIB_TARBALL_SHA256}" | grep -Eq '^[0-9a-f]{64}$'; \
    printf '%s  %s\n' "${GIT_TARBALL_SHA256}" /inputs/git-2.55.0.tar.xz | sha256sum -c -; \
    printf '%s  %s\n' "${ZLIB_TARBALL_SHA256}" /inputs/zlib-1.3.1.tar.gz | sha256sum -c -; \
    test -s /evidence/SOURCE-MANIFEST.json; \
    test -s /evidence/Apache-2.0.txt; \
    test -s /evidence/GPL-2.0-only.txt; \
    test -s /evidence/musl-COPYRIGHT

RUN --network=none set -eu; \
    case "${TARGETARCH}" in \
      amd64) CFLAGS="-O2 -march=${FILEBELT_AMD64_ISA}"; CXXFLAGS="${CFLAGS}" ;; \
      arm64) CFLAGS="-O2"; CXXFLAGS="${CFLAGS}" ;; \
      *) exit 1 ;; \
    esac; \
    mkdir -p /build/zlib /opt/filebelt-git-deps; \
    tar -xzf /inputs/zlib-1.3.1.tar.gz -C /build/zlib --strip-components=1; \
    cd /build/zlib; \
    test "$(cat zlib.h | sed -n 's/^#define ZLIB_VERSION "\([^"]*\)"/\1/p')" = "${ZLIB_VERSION}"; \
    test -s LICENSE; \
    cp LICENSE /evidence/Zlib.txt; \
    CFLAGS="${CFLAGS}" CXXFLAGS="${CXXFLAGS}" ./configure --static --prefix=/opt/filebelt-git-deps; \
    make -j1; \
    make install

RUN --network=none set -eu; \
    case "${TARGETARCH}" in \
      amd64) CFLAGS="-O2 -march=${FILEBELT_AMD64_ISA} -static -I/opt/filebelt-git-deps/include"; LDFLAGS="-static -Wl,-z,${FILEBELT_AMD64_ISA} -L/opt/filebelt-git-deps/lib" ;; \
      arm64) CFLAGS="-O2 -static -I/opt/filebelt-git-deps/include"; LDFLAGS="-static -L/opt/filebelt-git-deps/lib" ;; \
      *) exit 1 ;; \
    esac; \
    mkdir -p /build/git /opt/filebelt-git/bin; \
    tar -xJf /inputs/git-2.55.0.tar.xz -C /build/git --strip-components=1; \
    make -C /build/git -j1 git \
      prefix=/opt/filebelt-git \
      CFLAGS="${CFLAGS}" \
      LDFLAGS="${LDFLAGS}" \
      NO_CURL=YesPlease \
      NO_EXPAT=YesPlease \
      NO_GETTEXT=YesPlease \
      NO_ICONV=YesPlease \
      NO_OPENSSL=YesPlease \
      NO_PERL=YesPlease \
      NO_PYTHON=YesPlease \
      NO_TCLTK=YesPlease; \
    cp /build/git/git /opt/filebelt-git/bin/git; \
    chmod 0555 /opt/filebelt-git/bin/git; \
    /opt/filebelt-git/bin/git --version | grep -Fx "git version ${GIT_VERSION}"; \
    ! readelf -l /opt/filebelt-git/bin/git | grep -q 'Requesting program interpreter'; \
    ! readelf -d /opt/filebelt-git/bin/git 2>&1 | grep -q '(NEEDED)'; \
    if [ "${TARGETARCH}" = amd64 ]; then \
      readelf -n /opt/filebelt-git/bin/git | grep -Eq 'x86 ISA needed: (x86-64-baseline, )?x86-64-v3$'; \
    fi

RUN --network=none set -eu; \
    case "${TARGETARCH}" in \
      amd64) RUSTFLAGS="-C target-cpu=${FILEBELT_AMD64_ISA} -C link-arg=-Wl,-z,${FILEBELT_AMD64_ISA}"; CFLAGS="-march=${FILEBELT_AMD64_ISA}"; CXXFLAGS="${CFLAGS}" ;; \
      arm64) RUSTFLAGS=; CFLAGS=; CXXFLAGS= ;; \
      *) exit 1 ;; \
    esac; \
    RUSTFLAGS="${RUSTFLAGS}" CFLAGS="${CFLAGS}" CXXFLAGS="${CXXFLAGS}" cargo \
      --config 'source.crates-io.replace-with="vendored-sources"' \
      --config 'source.vendored-sources.directory="/inputs/vendor"' \
      build --locked --offline --release \
      --target "${RUST_TARGET}" \
      --manifest-path adapters/git/Cargo.toml && \
    mkdir -p /out && \
    cp "adapters/git/target/${RUST_TARGET}/release/filebelt-git-adapter" /out/filebelt-git-adapter && \
    chmod 0555 /out/filebelt-git-adapter && \
    ! readelf -l /out/filebelt-git-adapter | grep -q 'Requesting program interpreter' && \
    ! readelf -d /out/filebelt-git-adapter 2>&1 | grep -q '(NEEDED)' && \
    if [ "${TARGETARCH}" = amd64 ]; then \
      readelf -n /out/filebelt-git-adapter | grep -Eq 'x86 ISA needed: (x86-64-baseline, )?x86-64-v3$'; \
    fi && \
    test "$(find /out -maxdepth 1 -type f | wc -l)" -eq 1

FROM scratch

ARG SOURCE_URL
ARG SOURCE_REF
ARG SOURCE_REVISION
ARG CREATED
ARG IMAGE_LICENSES
ARG CORRESPONDING_SOURCE_URL
ARG CORRESPONDING_SOURCE_SHA256
ARG LICENSE_QUALIFICATION
ARG IMAGE_BUILD_STATE
ARG FILEBELT_AMD64_ISA
ARG FILEBELT_TARGET_CPU

LABEL org.opencontainers.image.title="filebelt-git-adapter" \
      org.opencontainers.image.description="FileBelt Apache wrapper with a separate GPL system-Git executable" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.version="${SOURCE_REF}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="${IMAGE_LICENSES}" \
      io.filebelt.image.role="filebelt-git-adapter" \
      io.filebelt.first-party-license="Apache-2.0" \
      io.filebelt.git.version="2.55.0" \
      io.filebelt.build.target-cpu="${FILEBELT_TARGET_CPU}" \
      io.filebelt.corresponding-source="${CORRESPONDING_SOURCE_URL}" \
      io.filebelt.corresponding-source.sha256="${CORRESPONDING_SOURCE_SHA256}" \
      io.filebelt.qualification.license="${LICENSE_QUALIFICATION}" \
      io.filebelt.qualification.image-build="${IMAGE_BUILD_STATE}"

ENV PATH="/opt/filebelt-git/bin"

COPY --from=build /out/filebelt-git-adapter /usr/local/bin/filebelt-git-adapter
COPY --from=build /opt/filebelt-git/bin/git /opt/filebelt-git/bin/git
COPY --from=build /evidence/Apache-2.0.txt /usr/share/licenses/filebelt-git-adapter/Apache-2.0.txt
COPY --from=build /evidence/GPL-2.0-only.txt /usr/share/licenses/git/GPL-2.0-only.txt
COPY --from=build /evidence/Zlib.txt /usr/share/licenses/zlib/Zlib.txt
COPY --from=build /evidence/musl-COPYRIGHT /usr/share/licenses/filebelt-git-adapter/musl-COPYRIGHT
COPY --from=build /src/adapters/git/THIRD_PARTY_NOTICES.md /usr/share/doc/filebelt-git-adapter/THIRD_PARTY_NOTICES.md
COPY --from=build /src/adapters/git/SOURCE_OFFER.md /usr/share/doc/filebelt-git-adapter/SOURCE_OFFER.md
COPY --from=build /evidence/SOURCE-MANIFEST.json /usr/share/doc/filebelt-git-adapter/SOURCE-MANIFEST.json

USER 10001:10001
ENTRYPOINT ["/usr/local/bin/filebelt-git-adapter"]
