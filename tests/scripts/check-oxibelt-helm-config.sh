#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly HELM_VERSION='v4.2.4'

usage() {
  echo 'usage: check-oxibelt-helm-config.sh --archive <web-image.tar>' >&2
}

archive=''
temporary=''
loaded_ref=''
container=''

cleanup() {
  local status="$?"
  set +e
  if [[ -n "${container}" ]]; then
    docker rm --force "${container}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${loaded_ref}" ]]; then
    docker image rm --force "${loaded_ref}" >/dev/null 2>&1 || true
  fi
  case "${temporary}" in
    "${TMPDIR:-/tmp}"/filebelt-oxibelt-helm.*) rm -rf -- "${temporary}" ;;
    '') ;;
    *) echo "refusing to remove unexpected test directory: ${temporary}" >&2 ;;
  esac
  exit "${status}"
}
trap cleanup EXIT HUP INT TERM

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --archive) archive="${2-}"; shift 2 ;;
    --help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

[[ -n "${archive}" && -f "${archive}" ]] || { usage; exit 2; }
for command in docker helm jq openssl python3 tar; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "missing required command: ${command}" >&2
    exit 1
  }
done
[[ "$(helm version --template '{{ .Version }}')" == "${HELM_VERSION}" ]] || {
  echo "requires Helm ${HELM_VERSION}" >&2
  exit 1
}

repo_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
chart="${repo_root}/deploy/helm/filebelt"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/filebelt-oxibelt-helm.XXXXXX")"

archive_ref="$(tar -xOf "${archive}" manifest.json | jq -er '
  if length == 1 and (.[0].RepoTags | length) == 1 then .[0].RepoTags[0]
  else error("expected one image tag") end')"
if docker image inspect "${archive_ref}" >/dev/null 2>&1; then
  echo "refusing to replace existing local image tag: ${archive_ref}" >&2
  exit 1
fi
loaded_ref="${archive_ref}"
load_output="$(docker load --input "${archive}")"
local_ref="$(printf '%s\n' "${load_output}" | awk -F': ' '/Loaded image:/ { print $2 }' | tail -n 1)"
[[ "${local_ref}" == "${archive_ref}" ]] || {
  echo 'loaded image reference does not match archive contract' >&2
  exit 1
}

openssl req -x509 -newkey ed25519 -nodes -days 1 \
  -keyout "${temporary}/ca.key" -out "${temporary}/ca.crt" \
  -subj '/CN=FileBelt OxiBelt chart test CA' >/dev/null 2>&1
openssl req -newkey ed25519 -nodes \
  -keyout "${temporary}/public.key" -out "${temporary}/public.csr" \
  -subj '/CN=filebelt.example.invalid' \
  -addext 'subjectAltName=DNS:filebelt.example.invalid,DNS:filebelt-editor.example.invalid,DNS:editor.example.test' >/dev/null 2>&1
openssl x509 -req -days 1 -in "${temporary}/public.csr" \
  -CA "${temporary}/ca.crt" -CAkey "${temporary}/ca.key" -CAcreateserial \
  -out "${temporary}/public.crt" \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:filebelt.example.invalid,DNS:filebelt-editor.example.invalid,DNS:editor.example.test\n') \
  >/dev/null 2>&1
openssl req -newkey ed25519 -nodes \
  -keyout "${temporary}/client.key" -out "${temporary}/client.csr" \
  -subj '/CN=filebelt-web' >/dev/null 2>&1
openssl x509 -req -days 1 -in "${temporary}/client.csr" \
  -CA "${temporary}/ca.crt" -CAkey "${temporary}/ca.key" -CAcreateserial \
  -out "${temporary}/client.crt" \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n') \
  >/dev/null 2>&1
openssl genpkey -algorithm ED25519 -out "${temporary}/mismatched-client.key" >/dev/null 2>&1

render_variant() {
  local name="$1"
  shift
  helm template "filebelt-oxibelt-${name}" "${chart}" --kube-version 1.36.0 "$@" \
    >"${temporary}/${name}.yaml"
  python3 - "${temporary}/${name}.yaml" "${temporary}/${name}.toml" "${temporary}/ca.crt" <<'PY'
import hashlib
import sys

manifest_path, output_path, ca_path = sys.argv[1:]
for document in open(manifest_path, encoding="utf-8").read().split("\n---\n"):
    lines = document.splitlines()
    if "kind: ConfigMap" not in lines or "  oxibelt.toml: |" not in lines:
        continue
    start = lines.index("  oxibelt.toml: |") + 1
    rendered = []
    for line in lines[start:]:
        if line.startswith("    "):
            rendered.append(line[4:])
        elif not line:
            rendered.append("")
        else:
            break
    sentinel = "0" * 64
    trusted_ca_sha256 = hashlib.sha256(open(ca_path, "rb").read()).hexdigest()
    with open(output_path, "w", encoding="utf-8") as output:
        output.write("\n".join(rendered).replace(sentinel, trusted_ca_sha256))
    break
else:
    raise SystemExit("missing rendered OxiBelt configuration")
PY
}

install_variant() {
  local name="$1" fault="$2"
  local root="${temporary}/${name}-root"
  mkdir -p "${root}/etc/oxibelt/config" "${root}/etc/oxibelt/cert"
  cp "${temporary}/${name}.toml" "${root}/etc/oxibelt/config/oxibelt.toml"
  for directory in public-tls api-client-tls io-client-tls collaboration-edge-client-tls onlyoffice-edge-client-tls; do
    mkdir -p "${root}/etc/oxibelt/cert/${directory}"
    cp "${temporary}/ca.crt" "${root}/etc/oxibelt/cert/${directory}/server-ca.crt"
    cp "${temporary}/client.crt" "${root}/etc/oxibelt/cert/${directory}/tls.crt"
    cp "${temporary}/client.key" "${root}/etc/oxibelt/cert/${directory}/tls.key"
  done
  cp "${temporary}/public.crt" "${root}/etc/oxibelt/cert/public-tls/tls.crt"
  cp "${temporary}/public.key" "${root}/etc/oxibelt/cert/public-tls/tls.key"
  chmod 0444 "${root}/etc/oxibelt/config/oxibelt.toml"
  find "${root}/etc/oxibelt/cert" -name '*.crt' -exec chmod 0444 {} +
  find "${root}/etc/oxibelt/cert" -name '*.key' -exec chmod 0440 {} +
  case "${fault}" in
    none) ;;
    world-readable-api-key)
      chmod 0644 "${root}/etc/oxibelt/cert/api-client-tls/tls.key"
      ;;
    missing-api-key)
      rm -f -- "${root}/etc/oxibelt/cert/api-client-tls/tls.key"
      ;;
    missing-api-cert)
      rm -f -- "${root}/etc/oxibelt/cert/api-client-tls/tls.crt"
      ;;
    mismatched-api-cert-key)
      cp "${temporary}/mismatched-client.key" "${root}/etc/oxibelt/cert/api-client-tls/tls.key"
      chmod 0440 "${root}/etc/oxibelt/cert/api-client-tls/tls.key"
      ;;
    *)
      echo "unsupported OxiBelt configuration fault: ${fault}" >&2
      exit 2
      ;;
  esac
  python3 - "${root}" "${temporary}/${name}.tar" <<'PY'
import pathlib
import tarfile
import sys

root, archive = map(pathlib.Path, sys.argv[1:])
with tarfile.open(archive, "w") as output:
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        info = output.gettarinfo(str(path), arcname=str(relative))
        info.uid = 10001
        info.gid = 10001
        info.uname = ""
        info.gname = ""
        if path.is_file():
            with path.open("rb") as source:
                output.addfile(info, source)
        else:
            output.addfile(info)
PY
}

check_variant() {
  local case_name="$1" config_name="$2" fault="$3" expected="$4"
  install_variant "${config_name}" "${fault}"
  container="filebelt-oxibelt-helm-${case_name}-${RANDOM}-$$"
  docker create --name "${container}" --network none "${local_ref}" --check >/dev/null
  docker cp - "${container}:/" <"${temporary}/${config_name}.tar"
  if docker start --attach "${container}" >"${temporary}/${case_name}.log" 2>&1; then
    actual=success
  else
    actual=failure
  fi
  docker rm --force "${container}" >/dev/null
  container=''
  [[ "${actual}" == "${expected}" ]] || {
    echo "${case_name} OxiBelt configuration check expected ${expected}, got ${actual}" >&2
    cat "${temporary}/${case_name}.log" >&2
    exit 1
  }
}

render_variant default
render_variant collaboration-webtransport --set collaboration.enabled=true --set collaboration.webtransport.enabled=true
render_variant documents --set documents.enabled=true
check_variant default default none success
check_variant collaboration-webtransport collaboration-webtransport none success
check_variant documents documents none success
check_variant default-world-readable-api-key default world-readable-api-key failure
check_variant default-missing-api-key default missing-api-key failure
check_variant default-missing-api-cert default missing-api-cert failure
check_variant default-mismatched-api-cert-key default mismatched-api-cert-key failure

echo 'native OxiBelt Helm configuration checks passed'
