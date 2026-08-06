# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# SPDX-License-Identifier: Apache-2.0

ARG QEMU_IMAGE=docker.io/tonistiigi/binfmt:qemu-v10.2.3-68@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0
FROM ${QEMU_IMAGE}

COPY --chmod=0755 probe /probe

USER 65534:65534
# The pinned helper is built for binfmt_misc's preserve-argv0 mode, so the
# guest path and its argv[0] are both explicit before probe arguments.
ENTRYPOINT ["/usr/bin/qemu-riscv64", "/probe", "/probe"]
