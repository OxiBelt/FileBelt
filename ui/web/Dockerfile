# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# SPDX-License-Identifier: Apache-2.0

ARG NODE_BUILDER_IMAGE=node:24-alpine3.24@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43
ARG OXIBELT_IMAGE=ghcr.io/oxibelt/oxibelt@sha256:e8556a0103feff47bf6135062e70e980e000176598fd438959ea55d99c844030

FROM --platform=$BUILDPLATFORM ${NODE_BUILDER_IMAGE} AS builder

ARG TARGETARCH
ARG FILEBELT_TARGET_CPU=architecture-default

WORKDIR /repo
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.json ./
COPY devops/package.json devops/package.json
COPY ui/admin/package.json ui/admin/package.json
COPY ui/design-system/package.json ui/design-system/package.json
COPY ui/markdown/package.json ui/markdown/package.json
COPY ui/mcp-settings/package.json ui/mcp-settings/package.json
COPY ui/web/package.json ui/web/package.json
RUN if [ "${TARGETARCH}" = amd64 ]; then \
      test "${FILEBELT_TARGET_CPU}" = x86-64-v3; \
    else \
      test "${FILEBELT_TARGET_CPU}" = architecture-default; \
    fi && \
    corepack enable && \
    corepack prepare pnpm@11.21.0 --activate && \
    pnpm install --frozen-lockfile --ignore-scripts

COPY ui/admin ui/admin
COPY ui/design-assets ui/design-assets
COPY ui/design-system ui/design-system
COPY ui/markdown ui/markdown
COPY ui/mcp-settings ui/mcp-settings
COPY ui/web ui/web
COPY ui/vitest-fluent-icons-resolver.ts ui/vitest-fluent-icons-resolver.ts
RUN --network=none pnpm --filter @filebelt/design-system build && \
    pnpm --filter @filebelt/admin build && \
    pnpm --filter @filebelt/markdown build && \
    pnpm --filter @filebelt/web build && \
    mkdir -p /out/web /out/markdown-preview /out/notices && \
    cp -R ui/web/dist/. /out/web/ && \
    cp -R ui/markdown/dist/preview/. /out/markdown-preview/ && \
    pnpm licenses list --prod --json --filter @filebelt/web... > /out/notices/web-production-licenses.json && \
    cp ui/design-system/node_modules/lucide-react/LICENSE /out/notices/lucide-ISC.txt && \
    tslib_license=$(find node_modules/.pnpm -path '*/tslib@*/node_modules/tslib/LICENSE.txt') && \
    test "$(printf '%s\n' "${tslib_license}" | wc -l)" -eq 1 && \
    cp "${tslib_license}" /out/notices/tslib-0BSD.txt && \
    find /out -type d -exec chmod 0755 {} + && \
    find /out -type f -exec chmod 0644 {} +

FROM ${OXIBELT_IMAGE} AS filebelt-web

ARG FILEBELT_BUILD_VERSION
ARG FILEBELT_BUILD_REVISION
ARG FILEBELT_BUILD_SOURCE_REF
ARG FILEBELT_BUILD_DIRTY
ARG FILEBELT_BUILD_KIND
ARG FILEBELT_CREATED
ARG FILEBELT_TARGET_CPU

COPY --chmod=0644 LICENSE /usr/share/licenses/FileBelt/LICENSE
COPY --chmod=0644 LICENSES/Apache-2.0.txt /usr/share/licenses/FileBelt/LICENSES/Apache-2.0.txt
COPY --chmod=0644 LICENSES/MIT.txt /usr/share/licenses/FileBelt/LICENSES/MIT.txt
COPY --chmod=0644 THIRD_PARTY_NOTICES.md /usr/share/licenses/FileBelt/THIRD_PARTY_NOTICES.md
COPY --chmod=0644 ui/web/OXIBELT_NOTICE.md /usr/share/licenses/FileBelt/notices/OXIBELT_NOTICE.md
COPY --from=builder --chmod=0644 /out/notices /usr/share/licenses/FileBelt/notices/web
COPY --chmod=0644 ui/web/edge/oxibelt.toml /etc/oxibelt/config/oxibelt.toml
COPY --from=builder /out/web /srv/filebelt/web
COPY --from=builder /out/markdown-preview /srv/filebelt/markdown-preview

LABEL org.opencontainers.image.title="filebelt-web" \
      org.opencontainers.image.description="FileBelt OxiBelt TLS edge and web application" \
      org.opencontainers.image.source="https://github.com/OxiBelt/FileBelt" \
      org.opencontainers.image.url="https://github.com/OxiBelt/FileBelt" \
      org.opencontainers.image.base.name="ghcr.io/oxibelt/oxibelt@sha256:e8556a0103feff47bf6135062e70e980e000176598fd438959ea55d99c844030" \
      org.opencontainers.image.base.digest="sha256:e8556a0103feff47bf6135062e70e980e000176598fd438959ea55d99c844030" \
      org.opencontainers.image.version="${FILEBELT_BUILD_VERSION}" \
      org.opencontainers.image.revision="${FILEBELT_BUILD_REVISION}" \
      org.opencontainers.image.created="${FILEBELT_CREATED}" \
      org.opencontainers.image.licenses="Apache-2.0 AND MIT AND ISC AND 0BSD" \
      io.filebelt.image.role="filebelt-web" \
      io.filebelt.upstream.oxibelt.version="0.7.1-beta.2" \
      io.filebelt.upstream.oxibelt.revision="bf40172e40298325775ca9d708162a9d8d14e6d4" \
      io.filebelt.build.source-ref="${FILEBELT_BUILD_SOURCE_REF}" \
      io.filebelt.build.dirty="${FILEBELT_BUILD_DIRTY}" \
      io.filebelt.build.kind="${FILEBELT_BUILD_KIND}" \
      io.filebelt.build.target-cpu="${FILEBELT_TARGET_CPU}"
USER 10001:10001
EXPOSE 8443/tcp
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/local/bin/oxibelt", "--config", "/etc/oxibelt/config/oxibelt.toml"]
