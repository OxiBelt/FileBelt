#!/usr/bin/env sh
# SPDX-License-Identifier: LGPL-3.0-or-later

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test -f "$root/ganesha-fsal-filebelt/fsal_filebelt.c"
test -f "$root/ganesha-fsal-filebelt/abi_probe.c"
test -f "$root/ganesha-fsal-filebelt/filebelt_projection.c"
test -f "$root/ganesha-fsal-filebelt/projection_test.c"
test -f "$root/patches/0001-expose-minimal-filebelt-rpcsec-gss-identity.patch"
test -f "$root/patches/0003-delegate-mdcache-test-access.patch"
test -f "$root/patches/0004-project-authoritative-owner-group-names.patch"
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
echo '40bd37bb49dceeb173c879a77a1ccd82300d9683228c86150c10edb3e779588d  '"$root"'/patches/0003-delegate-mdcache-test-access.patch' | sha256sum -c -
echo 'c5d71d0623045b6ce2be66fc68637730f5ba82b3e328d8b7ac045d2d90c2aed6  '"$root"'/patches/0004-project-authoritative-owner-group-names.patch' | sha256sum -c -
rg -Fq 'entry->sub_handle->obj_ops->test_access != fsal_test_access' \
  "$root/patches/0003-delegate-mdcache-test-access.patch"
rg -Fq 'entry->sub_handle->obj_ops->test_access(' \
  "$root/patches/0003-delegate-mdcache-test-access.patch"
rg -Fq 'get_owner_group_names' \
  "$root/patches/0004-project-authoritative-owner-group-names.patch"
rg -Fq 'args.obj = obj;' \
  "$root/patches/0004-project-authoritative-owner-group-names.patch"
rg -Fq '.obj = data->current_obj,' \
  "$root/patches/0004-project-authoritative-owner-group-names.patch"
rg -Fq 'filebelt_projection_initialize(' \
	"$root/ganesha-fsal-filebelt/filebelt_handle.c"
rg -Fq 'filebelt_projection_matches(' \
	"$root/ganesha-fsal-filebelt/filebelt_handle.c"
rg -Fq 'projection->owner_length' \
	"$root/ganesha-fsal-filebelt/filebelt_handle.c"
test "$(rg -c 'filebelt_projection_initialize\(' \
	"$root/ganesha-fsal-filebelt/filebelt_handle.c")" -eq 1
projection_init_line=$(rg -n 'filebelt_projection_initialize\(' \
	"$root/ganesha-fsal-filebelt/filebelt_handle.c" | cut -d: -f1)
object_publish_line=$(rg -n 'fsal_obj_handle_init\(&object->obj' \
	"$root/ganesha-fsal-filebelt/filebelt_handle.c" | cut -d: -f1)
test "$projection_init_line" -lt "$object_publish_line"
rg -Fq 'ERR_FSAL_SERVERFAULT, EPROTO' \
  "$root/ganesha-fsal-filebelt/filebelt_handle.c"
rg -Fq 'FILEBELT_OP_TEST_LOCK = 61' \
  "$root/ganesha-fsal-filebelt/filebelt_handle.c"
rg -Fq 'FSAL_OP_LOCKT' "$root/ganesha-fsal-filebelt/filebelt_handle.c"
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
  if [ -f "$GANESHA_SOURCE/debian/changelog" ]; then
    test "$(dpkg-parsechangelog -l"$GANESHA_SOURCE/debian/changelog" -SVersion)" = \
      6.5-8
  else
    test "$(git -C "$GANESHA_SOURCE" rev-parse HEAD)" = \
      952fb93373a6f9f9e187bf9bc35c41a9fc25efa6
  fi
  git -C "$GANESHA_SOURCE" apply --check \
    "$root/patches/0001-expose-minimal-filebelt-rpcsec-gss-identity.patch" \
    "$root/patches/0002-build-filebelt-dynamic-fsal.patch" \
    "$root/patches/0003-delegate-mdcache-test-access.patch" \
    "$root/patches/0004-project-authoritative-owner-group-names.patch"
fi
