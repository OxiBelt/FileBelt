#!/usr/bin/env sh
# SPDX-License-Identifier: LGPL-3.0-or-later

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test -f "$root/ganesha-fsal-filebelt/fsal_filebelt.c"
test -f "$root/ganesha-fsal-filebelt/abi_probe.c"
test -f "$root/patches/0001-expose-minimal-filebelt-rpcsec-gss-identity.patch"
test -f "$root/bridge/src/lib.rs"
test -f "$root/RELINKING.md"
test -f "$root/Dockerfile.dockerignore"
! rg -q 'use (filebelt_database|filebelt_storage|sqlx|tokio_postgres)|postgres[[:space:]]*=' \
  "$root/bridge/src" "$root/Cargo.toml"
rg -q 'SOCK_SEQPACKET' "$root/README.md"
rg -q 'NFS-Ganesha `6.5-8`' "$root/README.md"
rg -q 'libntirpc `6.3-4`' "$root/README.md"
rg -q 'filebelt.dev.qualification="abi-probe-only"' "$root/Dockerfile"
rg -q 'ERR_FSAL_NOTSUPP' "$root/ganesha-fsal-filebelt/filebelt_export.c"
rg -q 'GSS_C_PRF_KEY_FULL' "$root/patches/0001-expose-minimal-filebelt-rpcsec-gss-identity.patch"
rg -Fq 'gd->sec.mech == GSS_C_NO_OID' \
  "$root/patches/0001-expose-minimal-filebelt-rpcsec-gss-identity.patch"
rg -Fq '!g_OID_equal(gd->sec.mech, &krb5oid)' \
  "$root/patches/0001-expose-minimal-filebelt-rpcsec-gss-identity.patch"
rg -q 'filebelt-nfs-v1' "$root/patches/0001-expose-minimal-filebelt-rpcsec-gss-identity.patch"
rg -q '6149f35f85dd9be45674c927f06e5bba7e34b75e6b96a41318c4c41c3ac29067' \
  "$root/README.md" || {
    echo "canonical manifest digest vector is missing" >&2
    exit 1
  }
rg -q 'b9c50ac8bcb322617cfb23d529f2bbd8f1403eab600f0bb0ad46eb6104524f83' \
  "$root/README.md" || {
    echo "canonical root-handle digest vector is missing" >&2
    exit 1
  }

if [ -n "${GANESHA_SOURCE:-}" ]; then
  test -d "$GANESHA_SOURCE"
  git -C "$GANESHA_SOURCE" apply --check \
    "$root/patches/0001-expose-minimal-filebelt-rpcsec-gss-identity.patch"
  git -C "$GANESHA_SOURCE" apply --check \
    "$root/patches/0002-build-filebelt-dynamic-fsal.patch"
fi
