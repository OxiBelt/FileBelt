#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

usage() {
  echo "usage: verify-release-tag.sh <tag> | --check-trust" >&2
}

if [ "$#" -ne 1 ]; then
  usage
  exit 2
fi

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
allowlist="${repo_root}/supply-chain/release-tag-signers.txt"
signer_dir="${repo_root}/supply-chain/release-tag-signers"

for command in git gpg awk grep mktemp; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "missing required command: ${command}" >&2
    exit 1
  }
done
if [ ! -f "${allowlist}" ] || [ ! -d "${signer_dir}" ]; then
  echo "release-tag signer trust material is missing" >&2
  exit 1
fi

keyring=$(mktemp -d)
cleanup() {
  rm -rf "${keyring}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 0700 "${keyring}"
seen="${keyring}/seen-fingerprints"
: >"${seen}"
trusted_count=0

while IFS= read -r fingerprint; do
  case "${fingerprint}" in
    ""|\#*) continue ;;
  esac
  if ! printf '%s\n' "${fingerprint}" | grep -Eq '^[0-9A-F]{40}$'; then
    echo "invalid release-tag signer fingerprint: ${fingerprint}" >&2
    exit 1
  fi
  if grep -Fxq "${fingerprint}" "${seen}"; then
    echo "duplicate release-tag signer fingerprint: ${fingerprint}" >&2
    exit 1
  fi
  printf '%s\n' "${fingerprint}" >>"${seen}"

  key_file="${signer_dir}/${fingerprint}.asc"
  if [ ! -f "${key_file}" ]; then
    echo "missing public key for release-tag signer ${fingerprint}" >&2
    exit 1
  fi
  actual_fingerprint=$(
    gpg --batch --no-autostart --homedir "${keyring}" --with-colons \
      --import-options show-only --import "${key_file}" 2>/dev/null |
      awk -F: '$1 == "fpr" { print $10; exit }'
  )
  if [ "${actual_fingerprint}" != "${fingerprint}" ]; then
    echo "public key fingerprint mismatch for ${key_file}" >&2
    exit 1
  fi
  gpg --batch --no-autostart --homedir "${keyring}" --quiet --import "${key_file}" \
    >/dev/null 2>&1
  trusted_count=$((trusted_count + 1))
done <"${allowlist}"

if [ "${trusted_count}" -eq 0 ]; then
  echo "release-tag signer allowlist is empty" >&2
  exit 1
fi

for key_file in "${signer_dir}"/*.asc; do
  if [ ! -f "${key_file}" ]; then
    echo "release-tag signer directory contains no public keys" >&2
    exit 1
  fi
  actual_fingerprint=$(
    gpg --batch --no-autostart --homedir "${keyring}" --with-colons \
      --import-options show-only --import "${key_file}" 2>/dev/null |
      awk -F: '$1 == "fpr" { print $10; exit }'
  )
  if ! grep -Fxq "${actual_fingerprint}" "${seen}"; then
    echo "unallowlisted release-tag signer key: ${key_file}" >&2
    exit 1
  fi
done

if [ "$1" = --check-trust ]; then
  echo "Release-tag signer trust passed"
  exit 0
fi

tag=$1
tag_revision=$(git -C "${repo_root}" rev-parse --verify "refs/tags/${tag}^{commit}")
head_revision=$(git -C "${repo_root}" rev-parse --verify 'HEAD^{commit}')
if [ "${tag_revision}" != "${head_revision}" ]; then
  echo "release tag ${tag} does not peel to checked-out HEAD ${head_revision}" >&2
  exit 1
fi
verification="${keyring}/verification.status"
gpg_program="${keyring}/gpg-no-autostart"
printf '%s\n' '#!/bin/sh' 'exec gpg --batch --no-autostart "$@"' >"${gpg_program}"
chmod 0700 "${gpg_program}"
if ! GNUPGHOME="${keyring}" git -C "${repo_root}" \
  -c gpg.format=openpgp -c gpg.program="${gpg_program}" verify-tag --raw -- "${tag}" \
  >/dev/null 2>"${verification}"; then
  echo "release tag ${tag} does not have a valid authorized signature" >&2
  exit 1
fi

valid_count=$(awk '$2 == "VALIDSIG" { count += 1 } END { print count + 0 }' "${verification}")
primary_fingerprint=$(awk '$2 == "VALIDSIG" { print $NF }' "${verification}")
if [ "${valid_count}" -ne 1 ] || ! grep -Fxq "${primary_fingerprint}" "${seen}"; then
  echo "release tag ${tag} was not signed by exactly one authorized primary key" >&2
  exit 1
fi

echo "Release tag ${tag} signature passed"
