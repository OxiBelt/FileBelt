#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: verify-static-elf.sh <binary> <target>" >&2
  exit 2
fi

binary=$1
target=$2

test -x "${binary}"
if readelf -l "${binary}" | grep -Fq 'Requesting program interpreter'; then
  echo "${binary} is dynamically linked" >&2
  exit 1
fi

machine=$(readelf -h "${binary}" | awk -F: '/Machine:/ { sub(/^[[:space:]]+/, "", $2); print $2 }')
case "${target}:${machine}" in
  x86_64-unknown-linux-musl:X86-64|\
  x86_64-unknown-linux-musl:Advanced\ Micro\ Devices\ X86-64) ;;
  aarch64-unknown-linux-musl:AArch64) ;;
  riscv64gc-unknown-linux-musl:RISC-V) ;;
  *)
    echo "unexpected ELF machine ${machine} for ${target}" >&2
    exit 1
    ;;
esac
