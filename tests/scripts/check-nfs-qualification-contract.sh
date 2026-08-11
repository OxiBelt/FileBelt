#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/../.." && pwd)
workflow="${repo_root}/.github/workflows/nfs-qualification.yml"
native="${repo_root}/tests/scripts/run-nfs-native-build.sh"
client="${repo_root}/tests/scripts/run-nfs-client-qualification.py"
validator="${repo_root}/tests/scripts/validate-nfs-qualification.py"
release="${repo_root}/.github/workflows/release.yml"

die() {
  echo "NFS qualification contract: $*" >&2
  exit 1
}

assert_contains() {
  grep -F -- "$2" "$1" >/dev/null || die "$(basename -- "$1") is missing: $2"
}

for executable in "${native}" "${client}" "${validator}"; do
  [[ -x "${executable}" ]] || die "script is not executable: ${executable}"
done
bash -n "${native}"
python3 -m py_compile "${client}" "${validator}"

assert_contains "${workflow}" "permissions:"
assert_contains "${workflow}" "contents: read"
if grep -Eq 'packages: write|contents: write|id-token: write|attestations: write' "${workflow}"; then
  die "read-only qualification workflow requests publication authority"
fi
assert_contains "${workflow}" "runner: ubuntu-26.04"
assert_contains "${workflow}" "runner: ubuntu-26.04-arm"
assert_contains "${workflow}" "runner: \${{ inputs.native_riscv64_runner }}"
assert_contains "${native}" 'expected_machine=riscv64'
assert_contains "${native}" 'QEMU binfmt registration is forbidden'
assert_contains "${native}" "[[ \"\${qualification}\" == qualified ]]"
if grep -Eqi 'qemu|binfmt' "${workflow}" && ! grep -F 'QEMU is forbidden' "${workflow}" >/dev/null; then
  die "workflow must not configure emulation"
fi

for runner in \
  ubuntu_amd64_runner ubuntu_arm64_runner \
  debian_amd64_runner debian_arm64_runner \
  rhel10_amd64_runner rhel10_arm64_runner; do
  assert_contains "${workflow}" "${runner}:"
  assert_contains "${workflow}" "runner: \${{ inputs.${runner} }}"
done
for case_name in \
  authenticate_krb5p list read write commit rename xattr acl sparse \
  restart_reclaim drain fence stale_handle reject_auth_sys \
  reject_root_principal reject_cross_realm_principal; do
  assert_contains "${repo_root}/tests/nfs/qualification/required-cases.json" "\"${case_name}\""
done

assert_contains "${native}" 'filebelt.dev.nfs-ganesha'
assert_contains "${native}" 'filebelt.dev.fsal-api'
assert_contains "${native}" 'ganesha_nfsd'
assert_contains "${native}" 'RELINKING.md'
assert_contains "${native}" 'SOURCE_OFFER.md'
assert_contains "${native}" 'THIRD_PARTY_NOTICES.md'
assert_contains "${workflow}" "Refuse publication without an assembled immutable evidence package"
if grep -F 'filebelt-nfs-gateway' "${release}" >/dev/null; then
  die "core release workflow must not promote NFS before its independent gate is admitted"
fi

echo "NFS qualification contract passed"
