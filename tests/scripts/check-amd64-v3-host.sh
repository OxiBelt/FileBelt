#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Check whether this Linux execution host can run the FileBelt x86-64-v3 ABI.
#
# This intentionally reports only the bounded compatibility result, never the
# complete CPU feature inventory.  --cpuinfo is a test/diagnostic input; normal
# callers use the kernel-provided /proc/cpuinfo.

set -euo pipefail

usage() {
  echo "usage: $0 [--format json] [--cpuinfo PATH]" >&2
}

format=json
cpuinfo=/proc/cpuinfo
while (($# > 0)); do
  case "$1" in
    --format)
      if (($# < 2)); then
        usage
        exit 2
      fi
      format=$2
      shift 2
      ;;
    --cpuinfo)
      if (($# < 2)); then
        usage
        exit 2
      fi
      cpuinfo=$2
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ "${format}" != json ]] || [[ ! -f "${cpuinfo}" ]] || [[ ! -r "${cpuinfo}" ]]; then
  usage
  exit 2
fi

if [[ "$(wc -c <"${cpuinfo}")" -gt 16777216 ]]; then
  echo "cpuinfo input exceeds the 16 MiB limit" >&2
  exit 2
fi

architecture=$(uname -m 2>/dev/null || true)
if [[ -z "${architecture}" ]]; then
  echo "cannot determine host architecture" >&2
  exit 2
fi

emit_result() {
  local supported="$1"
  local cpu_count="$2"
  shift 2
  local -a missing=("$@")
  local encoded_missing
  encoded_missing=$(printf '%s\n' "${missing[@]}" | sed '/^$/d' | LC_ALL=C sort -u | \
    awk 'BEGIN { first=1; printf "[" } { if (!first) printf ","; printf "\"%s\"", $0; first=0 } END { printf "]" }')
  printf '{"schemaVersion":1,"architecture":"%s","cpuCount":%s,"baseline":"x86-64-v3","supported":%s,"missingFeatures":%s}\n' \
    "${architecture}" "${cpu_count}" "${supported}" "${encoded_missing}"
}

if [[ "${architecture}" != x86_64 ]]; then
  emit_result false 0 "architecture:x86_64"
  exit 1
fi

if ! cpu_lines=$(awk '
  function emit() {
    if (!seen || !have_flags) exit 42
    print flags
  }
  /^[[:space:]]*processor[[:space:]]*:/ {
    if (seen) emit()
    seen = 1
    have_flags = 0
    flags = ""
    next
  }
  /^[[:space:]]*flags[[:space:]]*:/ {
    if (!seen || have_flags) exit 43
    sub(/^[^:]*:[[:space:]]*/, "")
    flags = $0
    have_flags = 1
    next
  }
  END {
    if (!seen || !have_flags) exit 44
    print flags
  }
' "${cpuinfo}"); then
  echo "cpuinfo does not contain one flags record for every processor" >&2
  exit 2
fi

has_feature() {
  local flags="$1"
  local feature="$2"
  [[ " ${flags} " == *" ${feature} "* ]]
}

has_any_feature() {
  local flags="$1"
  shift
  local feature
  for feature in "$@"; do
    if has_feature "${flags}" "${feature}"; then
      return 0
    fi
  done
  return 1
}

declare -a missing=()
cpu_count=0
while IFS= read -r flags; do
  ((cpu_count += 1))
  has_feature "${flags}" cx16 || missing+=(cx16)
  has_feature "${flags}" lahf_lm || missing+=(lahf_lm)
  has_feature "${flags}" popcnt || missing+=(popcnt)
  has_any_feature "${flags}" sse3 pni || missing+=(sse3)
  has_feature "${flags}" ssse3 || missing+=(ssse3)
  has_feature "${flags}" sse4_1 || missing+=(sse4_1)
  has_feature "${flags}" sse4_2 || missing+=(sse4_2)
  has_feature "${flags}" avx || missing+=(avx)
  has_feature "${flags}" avx2 || missing+=(avx2)
  has_feature "${flags}" bmi1 || missing+=(bmi1)
  has_feature "${flags}" bmi2 || missing+=(bmi2)
  has_feature "${flags}" f16c || missing+=(f16c)
  has_feature "${flags}" fma || missing+=(fma)
  has_any_feature "${flags}" lzcnt abm || missing+=(lzcnt)
  has_feature "${flags}" movbe || missing+=(movbe)
  has_feature "${flags}" xsave || missing+=(xsave)
done <<<"${cpu_lines}"

if ((cpu_count == 0)); then
  echo "cpuinfo did not expose any processors" >&2
  exit 2
fi

if ((${#missing[@]} == 0)); then
  emit_result true "${cpu_count}"
  exit 0
fi

emit_result false "${cpu_count}" "${missing[@]}"
exit 1
