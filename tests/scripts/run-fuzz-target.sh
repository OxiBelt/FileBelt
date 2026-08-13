#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
  echo "usage: $0 --target NAME --profile stable|asan --mode smoke|campaign [--runs COUNT] [--seconds COUNT]" >&2
  exit 2
}

target=''
profile=''
mode=''
runs=''
seconds=''
while (($#)); do
  case "$1" in
    --target) target=${2-}; shift 2 ;;
    --profile) profile=${2-}; shift 2 ;;
    --mode) mode=${2-}; shift 2 ;;
    --runs) runs=${2-}; shift 2 ;;
    --seconds) seconds=${2-}; shift 2 ;;
    *) usage ;;
  esac
done

[[ ${target} =~ ^[a-z][a-z0-9_]*$ ]] || usage
[[ ${profile} == stable || ${profile} == asan ]] || usage
[[ ${mode} == smoke || ${mode} == campaign ]] || usage
[[ -z ${runs} || ${runs} =~ ^[1-9][0-9]*$ ]] || usage
[[ -z ${seconds} || ${seconds} =~ ^[1-9][0-9]*$ ]] || usage
[[ ${mode} == smoke && -z ${seconds} ]] || [[ ${mode} == campaign && -z ${runs} ]] || usage

repo_root=$(git rev-parse --show-toplevel)
catalog=${repo_root}/fuzz/targets.toml
readarray -t settings < <(python3 - "${catalog}" "${target}" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as handle:
    catalog = tomllib.load(handle)
matches = [item for item in catalog["target"] if item["name"] == sys.argv[2]]
if len(matches) != 1:
    raise SystemExit(f"unknown or duplicate fuzz target: {sys.argv[2]}")
target = matches[0]
for value in (
    catalog["cargo_fuzz_version"],
    catalog["stable_toolchain"],
    catalog["asan_toolchain"],
    catalog["timeout_seconds"],
    catalog["rss_limit_mib"],
    catalog["malloc_limit_mib"],
    catalog["smoke_runs"],
    target["max_input_bytes"],
    target["seed_directory"],
    target.get("dictionary", ""),
):
    print(value)
PY
)

expected_cargo_fuzz=${settings[0]}
stable_toolchain=${settings[1]}
asan_toolchain=${settings[2]}
timeout_seconds=${settings[3]}
rss_limit_mib=${settings[4]}
malloc_limit_mib=${settings[5]}
default_runs=${settings[6]}
max_input_bytes=${settings[7]}
seed_directory=${repo_root}/${settings[8]}
dictionary=${settings[9]}

actual_cargo_fuzz=$(cargo fuzz --version)
[[ ${actual_cargo_fuzz} == "cargo-fuzz ${expected_cargo_fuzz}" ]] || {
  echo "expected cargo-fuzz ${expected_cargo_fuzz}, found ${actual_cargo_fuzz}" >&2
  exit 1
}

mkdir -p "${repo_root}/fuzz/corpus" "${repo_root}/fuzz/artifacts"
corpus=$(mktemp -d "${repo_root}/fuzz/corpus/${target}.XXXXXX")
trap 'rm -rf -- "${corpus}"' EXIT
cp -- "${seed_directory}"/* "${corpus}/"

output_root=${FILEBELT_FUZZ_OUTPUT_DIR:-${repo_root}/fuzz/artifacts}
mkdir -p "${output_root}/${target}"
artifact_directory=$(mktemp -d "${output_root}/${target}/${profile}.XXXXXX")
artifact_prefix=${artifact_directory}/

toolchain=${stable_toolchain}
sanitizer=none
detect_leaks=0
if [[ ${profile} == asan ]]; then
  toolchain=${asan_toolchain}
  sanitizer=address
  [[ ${mode} == smoke ]] || detect_leaks=1
fi

engine=(
  "-timeout=${timeout_seconds}"
  "-rss_limit_mb=${rss_limit_mib}"
  "-malloc_limit_mb=${malloc_limit_mib}"
  "-max_len=${max_input_bytes}"
  "-detect_leaks=${detect_leaks}"
  "-artifact_prefix=${artifact_prefix}"
)
if [[ ${mode} == smoke ]]; then
  engine+=("-runs=${runs:-${default_runs}}")
else
  engine+=("-max_total_time=${seconds:-900}")
fi

cargo_args=("+${toolchain}" fuzz run "${target}" "${corpus}" --sanitizer "${sanitizer}" --no-default-features --features fuzz-target)
if [[ -n ${dictionary} ]]; then
  cargo_args+=(-- "-dict=${repo_root}/${dictionary}")
else
  cargo_args+=(--)
fi
cargo_args+=("${engine[@]}")

set +e
log=$(mktemp "${repo_root}/fuzz/artifacts/${target}.${profile}.log.XXXXXX")
trap 'rm -rf -- "${corpus}" "${artifact_directory}"; rm -f -- "${log}"' EXIT
env -u CUSTOM_LIBFUZZER_PATH -u CUSTOM_LIBFUZZER_STD_CXX -u RUST_LIBFUZZER_DEBUG_PATH \
  cargo "${cargo_args[@]}" >"${log}" 2>&1
status=$?
set -e
if ((status != 0)); then
  grep -E '^(==[0-9]+==|SUMMARY:|ERROR:|AddressSanitizer:|LeakSanitizer:|libFuzzer:)' "${log}" \
    | sed -E 's#(/[^[:space:]]+)+#<path>#g' \
    | tail -80 || true
  find "${artifact_prefix}" -maxdepth 1 -type f -print0 \
    | sort -z \
    | xargs -0 -r sha256sum \
    | awk '{print "crash-sha256 " $1}'
fi
exit "${status}"
