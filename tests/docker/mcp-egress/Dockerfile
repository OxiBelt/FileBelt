# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# SPDX-License-Identifier: Apache-2.0

FROM node:24-alpine3.24@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43

COPY --chmod=0444 policy.mjs /opt/filebelt-mcp-egress/policy.mjs
COPY --chmod=0555 server.mjs /opt/filebelt-mcp-egress/server.mjs

USER 10001:10001
EXPOSE 8443/tcp
ENTRYPOINT ["node", "/opt/filebelt-mcp-egress/server.mjs"]
