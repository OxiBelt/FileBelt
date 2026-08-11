# syntax=docker/dockerfile:1.7
# SPDX-License-Identifier: LGPL-3.0-or-later

ARG UBUNTU_IMAGE=docker.io/library/ubuntu:26.04@sha256:678c6550cc43645e08669028bc177f50be4e7c5b8cca677067b1914d4afc7a03

FROM ${UBUNTU_IMAGE} AS bridge-builder
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive
COPY adapters/nfs/container/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources
RUN rm -f /etc/apt/sources.list && \
    apt-get update -o Acquire::Check-Valid-Until=false && \
    apt-get install -y --no-install-recommends build-essential ca-certificates cmake curl pkg-config xz-utils && \
    rm -rf /var/lib/apt/lists/*
RUN case "${TARGETARCH}" in \
      amd64) target=x86_64-unknown-linux-gnu; checksum=88f28fa9af20594179f85d6df67078dfd6fa93e2f6da5e1e9b0ac4997988ca4f ;; \
      arm64) target=aarch64-unknown-linux-gnu; checksum=9a7a2c336b4787f1b72f6bab7c35d5b7af2fd03cbd39b4fc721466a70d402a7d ;; \
      riscv64) target=riscv64gc-unknown-linux-gnu; checksum=2982687edabf8582b21a5497fed8dd5287a24afdb836a64b206959cea81ab947 ;; \
      *) echo "unsupported TARGETARCH ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    curl -fsSLo /tmp/rust.tar.xz "https://static.rust-lang.org/dist/rust-1.97.1-${target}.tar.xz" && \
    echo "${checksum}  /tmp/rust.tar.xz" | sha256sum -c - && \
    tar -xJf /tmp/rust.tar.xz -C /tmp && \
    "/tmp/rust-1.97.1-${target}/install.sh" --prefix=/usr/local --without=rust-docs && \
    rm -rf /tmp/rust.tar.xz "/tmp/rust-1.97.1-${target}"
WORKDIR /src
COPY adapters/nfs adapters/nfs
COPY source/crates/filebelt-vfs-protocol source/crates/filebelt-vfs-protocol
COPY protocol/generated/rust/filebelt/vfs/v1/filebelt.vfs.v1.rs protocol/generated/rust/filebelt/vfs/v1/filebelt.vfs.v1.rs
RUN cargo build --locked --release --manifest-path adapters/nfs/Cargo.toml && \
    install -D -m 0755 adapters/nfs/target/release/filebelt-nfs-bridge /out/usr/local/bin/filebelt-nfs-bridge

FROM ${UBUNTU_IMAGE} AS ganesha-builder
ENV DEBIAN_FRONTEND=noninteractive
COPY adapters/nfs/container/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources
RUN rm -f /etc/apt/sources.list && \
    apt-get update -o Acquire::Check-Valid-Until=false && \
    apt-get install -y --no-install-recommends \
      build-essential ca-certificates cmake curl dpkg-dev libkrb5-dev \
      libnsl-dev libntirpc-dev liburcu-dev patch pkg-config xz-utils && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /build/source
RUN curl -fsSLO 'https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/nfs-ganesha/6.5-8/nfs-ganesha_6.5-8.dsc' && \
    curl -fsSLO 'https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/nfs-ganesha/6.5-8/nfs-ganesha_6.5.orig.tar.gz' && \
    curl -fsSLO 'https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/nfs-ganesha/6.5-8/nfs-ganesha_6.5-8.debian.tar.xz' && \
    echo 'b8ad87e17e4052a523b1eb220ce30d605a9304ee4db39affeb9c1754a8024da6  nfs-ganesha_6.5-8.dsc' | sha256sum -c - && \
    echo 'ece6cf138dd8602f33294eee75233051229867ea7fd1b3f7d6545e989303bfd9  nfs-ganesha_6.5.orig.tar.gz' | sha256sum -c - && \
    echo '265ffa464b51819e8ab323230870937349acbdffedbf740a5f9520272cad4e18  nfs-ganesha_6.5-8.debian.tar.xz' | sha256sum -c - && \
    dpkg-source -x nfs-ganesha_6.5-8.dsc /build/nfs-ganesha-6.5
COPY adapters/nfs/patches /build/filebelt-patches
RUN echo '8ecc34f8b9e50d0e062f23c5d93045f13634b89265278a14e16b6dc8f0bf2aff  /build/filebelt-patches/0001-expose-minimal-filebelt-rpcsec-gss-identity.patch' | sha256sum -c - && \
    echo 'e199f4bfdee75180b40df1637b3315b88aa36c0b584c94669e4da76417570bd1  /build/filebelt-patches/0002-build-filebelt-dynamic-fsal.patch' | sha256sum -c - && \
    echo '40bd37bb49dceeb173c879a77a1ccd82300d9683228c86150c10edb3e779588d  /build/filebelt-patches/0003-delegate-mdcache-test-access.patch' | sha256sum -c - && \
    echo 'c5d71d0623045b6ce2be66fc68637730f5ba82b3e328d8b7ac045d2d90c2aed6  /build/filebelt-patches/0004-project-authoritative-owner-group-names.patch' | sha256sum -c - && \
    patch -d /build/nfs-ganesha-6.5 -p1 < /build/filebelt-patches/0001-expose-minimal-filebelt-rpcsec-gss-identity.patch && \
    patch -d /build/nfs-ganesha-6.5 -p1 < /build/filebelt-patches/0002-build-filebelt-dynamic-fsal.patch && \
    patch -d /build/nfs-ganesha-6.5 -p1 < /build/filebelt-patches/0003-delegate-mdcache-test-access.patch && \
    patch -d /build/nfs-ganesha-6.5 -p1 < /build/filebelt-patches/0004-project-authoritative-owner-group-names.patch
COPY adapters/nfs/ganesha-fsal-filebelt /build/nfs-ganesha-6.5/src/FSAL/FSAL_FILEBELT
RUN cmake -S /build/nfs-ganesha-6.5/src -B /build/ganesha \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_INSTALL_PREFIX=/usr \
      -DLIB_INSTALL_DIR=/usr/lib/ganesha \
      -DFSAL_DESTINATION=/usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)/ganesha \
      -DUSE_SYSTEM_NTIRPC=ON -DUSE_GSS=ON -DUSE_NFS3=OFF \
      -DUSE_NFS_RDMA=OFF -DUSE_9P=OFF -DUSE_9P_RDMA=OFF \
      -DUSE_DBUS=OFF -DUSE_NFSIDMAP=OFF -DUSE_RQUOTA=OFF \
      -DUSE_FSAL_PROXY_V4=OFF -DUSE_FSAL_PROXY_V3=OFF \
      -DUSE_FSAL_VFS=OFF -DUSE_FSAL_LUSTRE=OFF -DUSE_FSAL_XFS=OFF \
      -DUSE_FSAL_LIZARDFS=OFF -DUSE_FSAL_KVSFS=OFF \
      -DUSE_FSAL_CEPH=OFF -DUSE_FSAL_GPFS=OFF -DUSE_FSAL_GLUSTER=OFF \
      -DUSE_FSAL_NULL=OFF -DUSE_FSAL_RGW=OFF -DUSE_FSAL_MEM=OFF \
      -DUSE_FSAL_SAUNAFS=OFF -DUSE_LTTNG=OFF -DUSE_CAPS=OFF \
      -DUSE_UNWIND=OFF -DUSE_ADMIN_TOOLS=OFF -DUSE_GUI_ADMIN_TOOLS=OFF \
      -DUSE_MAN_PAGE=OFF -DDISTNAME_HAS_GIT_DATA=OFF && \
    make -C /build/nfs-ganesha-6.5/src/FSAL/FSAL_FILEBELT abi-check \
      GANESHA_SOURCE=/build/nfs-ganesha-6.5 GANESHA_BUILD=/build/ganesha && \
    cmake --build /build/ganesha --parallel && \
    DESTDIR=/out cmake --install /build/ganesha
RUN curl -fsSLO 'https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/ntirpc/6.3-4/ntirpc_6.3-4.dsc' && \
    curl -fsSLO 'https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/ntirpc/6.3-4/ntirpc_6.3.orig.tar.gz' && \
    curl -fsSLO 'https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/ntirpc/6.3-4/ntirpc_6.3-4.debian.tar.xz' && \
    echo '02b95b00a6e26ba0ec43c3225d83186107e7e386ef9c1e216420bfb5c95e9bba  ntirpc_6.3-4.dsc' | sha256sum -c - && \
    echo '4caf7de4a6bd2de85b3f538a7f137852dcdcdea0b841e44fb3f73293cd7bf5b4  ntirpc_6.3.orig.tar.gz' | sha256sum -c - && \
    echo 'b11737fbf02d7a5b700fe317b7a6ebabf4666442bd943d5dba6530bd8942c91f  ntirpc_6.3-4.debian.tar.xz' | sha256sum -c - && \
    install -d /out/usr/share/filebelt-nfs/corresponding-source && \
    cp nfs-ganesha_6.5-8.dsc nfs-ganesha_6.5.orig.tar.gz nfs-ganesha_6.5-8.debian.tar.xz \
       ntirpc_6.3-4.dsc ntirpc_6.3.orig.tar.gz ntirpc_6.3-4.debian.tar.xz \
       /out/usr/share/filebelt-nfs/corresponding-source/ && \
    cp /build/filebelt-patches/*.patch /out/usr/share/filebelt-nfs/corresponding-source/

FROM ${UBUNTU_IMAGE}
ARG RELEASE_REVISION=unreleased
ENV DEBIAN_FRONTEND=noninteractive
COPY adapters/nfs/container/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources
RUN rm -f /etc/apt/sources.list && \
    apt-get update -o Acquire::Check-Valid-Until=false && \
    apt-get install -y --no-install-recommends \
      ca-certificates libgssapi-krb5-2 libkrb5-3 libnsl2 libntirpc6.3 liburcu8t64 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=bridge-builder /out/ /
COPY --from=ganesha-builder /out/ /
COPY --chmod=0755 adapters/nfs/container/filebelt-nfs /usr/local/bin/filebelt-nfs
COPY adapters/nfs /usr/share/filebelt-nfs/corresponding-source/filebelt-adapter
RUN install -d -m 0755 /contract && \
    ln -s /usr/local/bin/filebelt-nfs /contract/bridge-health && \
    ln -s /usr/local/bin/filebelt-nfs /contract/bridge-drain && \
    ln -s /usr/local/bin/filebelt-nfs /contract/ganesha-health && \
    ln -s /usr/local/bin/filebelt-nfs /contract/ganesha-drain
LABEL org.opencontainers.image.source="https://github.com/OxiBelt/FileBelt" \
      org.opencontainers.image.revision="${RELEASE_REVISION}" \
      org.opencontainers.image.licenses="LGPL-3.0-or-later" \
      filebelt.dev.nfs-ganesha="6.5-8" \
      filebelt.dev.ntirpc="6.3-4" \
      filebelt.dev.fsal-api="13.0" \
      filebelt.dev.qualification="abi-probe-only"
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/filebelt-nfs"]
