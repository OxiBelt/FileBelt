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

if grep -Eq '^permissions:' "${workflow}"; then
  die "qualification workflow must scope permissions at the job level"
fi
[[ "$(grep -Fc 'permissions: { contents: read }' "${workflow}")" -eq 3 ]] || \
  die "qualification workflow must grant checkout jobs only contents: read"
[[ "$(grep -Fc 'permissions: {}' "${workflow}")" -eq 1 ]] || \
  die "qualification workflow must deny permissions to the fan-in gate"
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
  relay_restart_active relay_restart_idle relay_restart_session_fence \
  relay_restart_epoch_stable two_clients_shared_relay_peer \
  backend_restart_reclaim backend_restart_epoch_advance split_claims_retained \
  drain fence stale_handle reject_auth_sys \
  reject_root_principal reject_cross_realm_principal \
  replay_session_revocation replay_credential_revocation \
  replay_mapping_revocation replay_policy_revocation \
  replay_resource_acl_revocation replay_feature_export_revocation \
  replay_gateway_revocation replay_closed_handle_read \
  replay_changed_list_child_acl replay_open_close_idempotency \
  replay_end_session_narrow_ack; do
  assert_contains "${repo_root}/tests/nfs/qualification/required-cases.json" "\"${case_name}\""
done

for operation in relay-restart backend-restart; do
  assert_contains "${client}" "\"${operation}\""
done
for cni in calico cilium; do
  assert_contains "${validator}" "\"${cni}\""
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
