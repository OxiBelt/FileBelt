#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cargo test --manifest-path "$ROOT/Cargo.toml" --workspace --locked
grep -Fq 'server min protocol = SMB3_11' "$ROOT/ops/smb.conf.template"
grep -Fq 'smb encrypt = required' "$ROOT/ops/smb.conf.template"
grep -Fq 'map to guest = Never' "$ROOT/ops/smb.conf.template"
grep -Fq 'SMB_VFS_INTERFACE_VERSION' "$ROOT/samba-vfs-filebelt/source/vfs_filebelt.c"
