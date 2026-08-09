#!/usr/bin/env sh
# SPDX-License-Identifier: LGPL-3.0-or-later

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test -f "$root/ganesha-fsal-filebelt/fsal_filebelt.c"
test -f "$root/bridge/src/lib.rs"
! rg -q 'filebelt_database|filebelt_storage|postgres|payload mount' "$root/bridge/src"
rg -q 'SOCK_SEQPACKET' "$root/README.md"
rg -q 'NFS-Ganesha `6.5-8`' "$root/README.md"
