# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# SPDX-License-Identifier: Apache-2.0

FROM node:24-alpine3.24@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1

RUN install -d -o 10001 -g 10001 -m 0700 /var/lib/filebelt/payloads
COPY --chmod=0555 server.mjs /opt/filebelt-oidc/server.mjs
COPY --chmod=0555 relay.mjs /opt/filebelt-oidc/relay.mjs

USER 10001:10001
EXPOSE 8083/tcp
ENTRYPOINT ["node", "/opt/filebelt-oidc/server.mjs"]
