# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# SPDX-License-Identifier: Apache-2.0

ARG NODE_BUILDER_IMAGE=node:24-alpine3.24@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43

FROM --platform=$BUILDPLATFORM ${NODE_BUILDER_IMAGE} AS builder

WORKDIR /repo
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.json ./
COPY devops/package.json devops/package.json
COPY ui/admin/package.json ui/admin/package.json
COPY ui/design-system/package.json ui/design-system/package.json
COPY ui/markdown/package.json ui/markdown/package.json
COPY ui/mcp-settings/package.json ui/mcp-settings/package.json
COPY ui/web/package.json ui/web/package.json
RUN corepack enable && \
    corepack prepare pnpm@11.20.0 --activate && \
    pnpm install --frozen-lockfile --ignore-scripts

COPY ui/markdown ui/markdown
COPY ui/web ui/web
RUN --network=none pnpm --filter @filebelt/markdown build && \
    pnpm --filter @filebelt/web build && \
    mkdir -p /out/web /out/markdown && \
    cp -R ui/web/dist/. /out/web/ && \
    cp -R ui/markdown/dist/. /out/markdown/ && \
    find /out -type d -exec chmod 0755 {} + && \
    find /out -type f -exec chmod 0644 {} +

FROM scratch AS filebelt-web

ARG FILEBELT_BUILD_VERSION
ARG FILEBELT_BUILD_REVISION
ARG FILEBELT_BUILD_SOURCE_REF
ARG FILEBELT_BUILD_DIRTY
ARG FILEBELT_BUILD_KIND
ARG FILEBELT_CREATED

COPY --chmod=0644 source/ops/runtime/passwd /etc/passwd
COPY --chmod=0644 source/ops/runtime/group /etc/group
COPY --chmod=0644 LICENSE /usr/share/licenses/FileBelt/LICENSE
COPY --chmod=0644 LICENSES/Apache-2.0.txt /usr/share/licenses/FileBelt/LICENSES/Apache-2.0.txt
COPY --from=builder /out/web /srv/filebelt/web
COPY --from=builder /out/markdown /srv/filebelt/markdown

LABEL org.opencontainers.image.title="filebelt-web" \
      org.opencontainers.image.description="FileBelt static web application" \
      org.opencontainers.image.source="https://github.com/OxiBelt/FileBelt" \
      org.opencontainers.image.url="https://github.com/OxiBelt/FileBelt" \
      org.opencontainers.image.version="${FILEBELT_BUILD_VERSION}" \
      org.opencontainers.image.revision="${FILEBELT_BUILD_REVISION}" \
      org.opencontainers.image.created="${FILEBELT_CREATED}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.filebelt.image.role="filebelt-web" \
      io.filebelt.build.source-ref="${FILEBELT_BUILD_SOURCE_REF}" \
      io.filebelt.build.dirty="${FILEBELT_BUILD_DIRTY}" \
      io.filebelt.build.kind="${FILEBELT_BUILD_KIND}"
USER 10001:10001
