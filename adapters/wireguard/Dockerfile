# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# SPDX-License-Identifier: Apache-2.0

# The adapter evidence assembler stages every source archive and Cargo input.
# This recipe has no downloader, package manager, or network-enabled build step.
ARG FILEBELT_WIREGUARD_BUILDER_IMAGE
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
ARG TARGETARCH
ARG FILEBELT_AMD64_ISA
ARG FILEBELT_TARGET_CPU

FROM ${FILEBELT_WIREGUARD_BUILDER_IMAGE} AS build

ARG FILEBELT_WIREGUARD_BUILDER_IMAGE
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
ARG TARGETARCH
ARG FILEBELT_AMD64_ISA
ARG FILEBELT_TARGET_CPU

ARG WIREGUARD_TOOLS_VERSION=1.0.20260223
ARG WIREGUARD_TOOLS_SHA256=af459827b80bfd31b83b08077f4b5843acb7d18ad9a33a2ef532d3090f291fbf
ARG IPROUTE2_VERSION=7.1.0
ARG IPROUTE2_SHA256=fd9fa1b95809417157ca83dd72957e3261bdbce896353cb936f80af0b33a4b5c

WORKDIR /src

COPY adapter-inputs/wireguard/upstream/wireguard-tools-1.0.20260223.tar.xz /inputs/wireguard-tools.tar.xz
COPY adapter-inputs/wireguard/upstream/iproute2-7.1.0.tar.xz /inputs/iproute2.tar.xz
COPY adapter-inputs/wireguard/vendor/cargo /inputs/vendor
COPY adapter-inputs/wireguard/SOURCE-MANIFEST.json /evidence/SOURCE-MANIFEST.json
COPY adapter-inputs/wireguard/LICENSES/GPL-2.0-only.txt /evidence/GPL-2.0-only.txt
COPY LICENSES/Apache-2.0.txt /evidence/Apache-2.0.txt
COPY LICENSES/MIT.txt /evidence/MIT.txt
COPY source/ops/runtime/musl-COPYRIGHT /evidence/musl-COPYRIGHT
COPY adapters/wireguard adapters/wireguard

RUN --network=none set -eu; \
    printf '%s' "${FILEBELT_WIREGUARD_BUILDER_IMAGE}" | grep -Eq '^.+@sha256:[0-9a-f]{64}$'; \
    test "${LICENSE_QUALIFICATION}" = qualified; \
    test "${IMAGE_BUILD_STATE}" = eligible; \
    case "${SOURCE_URL}" in https://*) ;; *) exit 1 ;; esac; \
    test -n "${SOURCE_REF}"; \
    case "${SOURCE_REF}" in main|master|latest) exit 1 ;; esac; \
    printf '%s' "${SOURCE_REVISION}" | grep -Eq '^[0-9a-f]{40}$'; \
    printf '%s' "${CREATED}" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'; \
    for license in Apache-2.0 GPL-2.0-only MIT; do printf '%s' "${IMAGE_LICENSES}" | grep -Fq "${license}"; done; \
    case "${CORRESPONDING_SOURCE_URL}" in https://*) ;; *) exit 1 ;; esac; \
    printf '%s' "${CORRESPONDING_SOURCE_SHA256}" | grep -Eq '^[0-9a-f]{64}$'; \
    case "${TARGETARCH}" in \
      amd64) test "${FILEBELT_AMD64_ISA}" = x86-64-v3; test "${FILEBELT_TARGET_CPU}" = x86-64-v3 ;; \
      arm64|riscv64) test -z "${FILEBELT_AMD64_ISA}"; test "${FILEBELT_TARGET_CPU}" = architecture-default ;; \
      *) exit 1 ;; \
    esac; \
    printf '%s  %s\n' "${WIREGUARD_TOOLS_SHA256}" /inputs/wireguard-tools.tar.xz | sha256sum -c -; \
    printf '%s  %s\n' "${IPROUTE2_SHA256}" /inputs/iproute2.tar.xz | sha256sum -c -; \
    test -s /evidence/SOURCE-MANIFEST.json; \
    test -s /evidence/GPL-2.0-only.txt; \
    test -s /evidence/Apache-2.0.txt; \
    test -s /evidence/MIT.txt; \
    test -s /evidence/musl-COPYRIGHT

RUN --network=none set -eu; \
    case "${TARGETARCH}" in \
      amd64) cc=musl-gcc; cflags="-O2 -static -march=${FILEBELT_AMD64_ISA}" ;; \
      arm64) cc=musl-gcc; cflags="-O2 -static" ;; \
      riscv64) cc=riscv64-unknown-linux-musl-gcc; cflags="-O2 -static" ;; \
      *) exit 1 ;; \
    esac; \
    command -v "${cc}"; \
    mkdir -p /build/wireguard-tools /build/iproute2 /out; \
    tar -xJf /inputs/wireguard-tools.tar.xz -C /build/wireguard-tools --strip-components=1; \
    tar -xJf /inputs/iproute2.tar.xz -C /build/iproute2 --strip-components=1; \
    make -C /build/wireguard-tools/src -j1 \
      CC="${cc}" \
      CFLAGS="${cflags}" \
      LDFLAGS=-static \
      WITH_BASHCOMPLETION=no \
      WITH_WGQUICK=no \
      WITH_SYSTEMDUNITS=no \
      wg; \
    (cd /build/iproute2 && ./configure --libbpf_force off); \
    make -C /build/iproute2 -j1 \
      CC="${cc}" \
      SHARED_LIBS=n \
      CFLAGS="${cflags}" \
      LDFLAGS=-static \
      ip/ip; \
    install -m 0555 /build/wireguard-tools/src/wg /out/wg; \
    install -m 0555 /build/iproute2/ip/ip /out/ip; \
    for binary in /out/wg /out/ip; do \
      ! readelf -l "${binary}" | grep -q 'Requesting program interpreter'; \
      ! readelf -d "${binary}" 2>&1 | grep -q '(NEEDED)'; \
    done

RUN --network=none set -eu; \
    case "${TARGETARCH}" in \
      amd64) rustflags="-C target-cpu=${FILEBELT_AMD64_ISA} -C link-arg=-Wl,-z,${FILEBELT_AMD64_ISA}" ;; \
      arm64|riscv64) rustflags='-C target-feature=+crt-static' ;; \
      *) exit 1 ;; \
    esac; \
    RUSTFLAGS="${rustflags}" cargo \
      --config 'source.crates-io.replace-with="vendored-sources"' \
      --config 'source.vendored-sources.directory="/inputs/vendor"' \
      build --locked --offline --release \
      --target "${RUST_TARGET}" \
      --manifest-path adapters/wireguard/Cargo.toml; \
    install -m 0555 "adapters/wireguard/target/${RUST_TARGET}/release/filebelt-wireguard-init" /out/filebelt-wireguard-init; \
    ! readelf -l /out/filebelt-wireguard-init | grep -q 'Requesting program interpreter'; \
    ! readelf -d /out/filebelt-wireguard-init 2>&1 | grep -q '(NEEDED)'; \
    test "$(find /out -maxdepth 1 -type f | wc -l)" -eq 3

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
ARG FILEBELT_TARGET_CPU

LABEL org.opencontainers.image.title="filebelt-wireguard-init" \
      org.opencontainers.image.description="Fixed-route WireGuard Pod initializer" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.version="${SOURCE_REF}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="${IMAGE_LICENSES}" \
      io.filebelt.image.role="filebelt-wireguard-init" \
      io.filebelt.first-party-license="Apache-2.0" \
      io.filebelt.wireguard-tools.version="1.0.20260223" \
      io.filebelt.iproute2.version="7.1.0" \
      io.filebelt.build.target-cpu="${FILEBELT_TARGET_CPU}" \
      io.filebelt.corresponding-source="${CORRESPONDING_SOURCE_URL}" \
      io.filebelt.corresponding-source.sha256="${CORRESPONDING_SOURCE_SHA256}" \
      io.filebelt.qualification.license="${LICENSE_QUALIFICATION}" \
      io.filebelt.qualification.image-build="${IMAGE_BUILD_STATE}"

COPY --from=build /out/filebelt-wireguard-init /usr/local/bin/filebelt-wireguard-init
COPY --from=build /out/wg /usr/local/bin/wg
COPY --from=build /out/ip /usr/local/bin/ip
COPY --from=build /evidence/Apache-2.0.txt /usr/share/licenses/filebelt-wireguard-init/Apache-2.0.txt
COPY --from=build /evidence/GPL-2.0-only.txt /usr/share/licenses/wireguard-tools/GPL-2.0-only.txt
COPY --from=build /evidence/GPL-2.0-only.txt /usr/share/licenses/iproute2/GPL-2.0-only.txt
COPY --from=build /evidence/MIT.txt /usr/share/licenses/musl/MIT.txt
COPY --from=build /evidence/musl-COPYRIGHT /usr/share/licenses/musl/COPYRIGHT
COPY --from=build /src/adapters/wireguard/THIRD_PARTY_NOTICES.md /usr/share/doc/filebelt-wireguard-init/THIRD_PARTY_NOTICES.md
COPY --from=build /src/adapters/wireguard/SOURCE_OFFER.md /usr/share/doc/filebelt-wireguard-init/SOURCE_OFFER.md
COPY --from=build /evidence/SOURCE-MANIFEST.json /usr/share/doc/filebelt-wireguard-init/SOURCE-MANIFEST.json

USER 0:0
ENTRYPOINT ["/usr/local/bin/filebelt-wireguard-init"]
