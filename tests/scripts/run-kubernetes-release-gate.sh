#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
  echo "usage: run-kubernetes-release-gate.sh --image-dir DIR" >&2
}

image_dir=
while (( $# > 0 )); do
  case "$1" in
    --image-dir) image_dir=${2:-}; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
[[ -d "${image_dir}" ]] || { usage; exit 2; }

for command in awk docker find grep jq sha256sum; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "required command is unavailable: ${command}" >&2
    exit 1
  }
done

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
active_roles=(
  filebelt-api
  filebelt-worker-io
  filebelt-worker-maintenance
  filebelt-collaboration
  filebelt-mcp-broker
  filebelt-controller
  filebelt-mcp-runner
  filebelt-tools
  filebelt-vfs
  filebelt-headscale-sync
  filebelt-nfs-relay
  filebelt-document
  filebelt-web
)
loaded_refs=()
compose_refs=()
fixture_built=0

cleanup() {
  local status=$?
  set +e
  for reference in "${compose_refs[@]:-}" "${loaded_refs[@]:-}"; do
    [[ -n "${reference}" ]] || continue
    docker image rm --force "${reference}" >/dev/null 2>&1 || true
  done
  if (( fixture_built == 1 )); then
    docker image rm --force filebelt-oidc-fixture:phase2 >/dev/null 2>&1 || true
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

find_one() {
  local pattern=$1
  mapfile -t matches < <(find "${image_dir}" -type f -name "${pattern}" -print)
  if (( ${#matches[@]} != 1 )); then
    echo "expected exactly one ${pattern}, found ${#matches[@]}" >&2
    return 1
  fi
  printf '%s\n' "${matches[0]}"
}

plan=$(find_one image-plan.json)
jq -e '
  .schemaVersion == 1
  and .channel == "release"
  and .version == .tag
  and (.tag | test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?$"))
  and .source.kind == "release"
  and .source.dirty == false
  and .source.url == "https://github.com/OxiBelt/FileBelt"
  and .source.ref == ("refs/tags/" + .version)
  and (.source.revision | test("^[0-9a-f]{40}$"))
  and .runtime == {uid:10001,gid:10001}
  and (.images | length) == 14
  and ([.images[].role] | sort) == ([
    "filebelt-api",
    "filebelt-mcp-broker",
    "filebelt-media-controller",
    "filebelt-document",
    "filebelt-collaboration",
    "filebelt-controller",
    "filebelt-mcp-runner",
    "filebelt-tools",
    "filebelt-vfs",
    "filebelt-headscale-sync",
    "filebelt-nfs-relay",
    "filebelt-web",
    "filebelt-worker-io",
    "filebelt-worker-maintenance"
  ] | sort)
  and all(.images[];
    .repository == ("ghcr.io/oxibelt/" + .role)
    and ([.platforms[]] | sort) == (["linux/amd64", "linux/arm64", "linux/riscv64"] | sort)
  )
' "${plan}" >/dev/null

version=$(jq -er '.version' "${plan}")
revision=$(jq -er '.source.revision' "${plan}")
plan_sha=$(sha256sum "${plan}" | awk '{print $1}')

for role in "${active_roles[@]}"; do
  archive=$(find_one "${role}-amd64.docker.tar")
  checksum=$(find_one "${role}-amd64.docker.tar.sha256")
  metadata=$(find_one "${role}-amd64.build.json")
  evidence=$(find_one "${role}-amd64.evidence.json")
  validation=$(find_one "${role}-amd64.validation.json")
  smoke=$(find_one "${role}-amd64.smoke.json")
  decision=$(find_one "${role}-amd64.vulnerability-decision.json")
  sbom=$(find_one "${role}-amd64.cdx.json")
  runtime_sbom=$(find_one "${role}-amd64.runtime.cdx.json")
  [[ -s "${sbom}" && -s "${runtime_sbom}" ]] || {
    echo "SBOM evidence is empty for ${role}/amd64" >&2
    exit 1
  }

  actual_sha=$(sha256sum "${archive}" | awk '{print $1}')
  metadata_sha=$(sha256sum "${metadata}" | awk '{print $1}')
  checksum_line=$(<"${checksum}")
  [[ "${checksum_line}" == "${actual_sha}  $(basename -- "${archive}")" ]] || {
    echo "archive checksum evidence mismatch for ${role}/amd64" >&2
    exit 1
  }
  repository="ghcr.io/oxibelt/${role}"
  local_reference="${repository}:${version}-amd64"
  jq -e \
    --arg role "${role}" \
    --arg version "${version}" \
    --arg plan_sha "${plan_sha}" \
    --arg repository "${repository}" \
    --arg local_reference "${local_reference}" \
    --arg revision "${revision}" \
    --arg archive "$(basename -- "${archive}")" \
    --arg sha "${actual_sha}" '
      .schemaVersion == 1
      and .planSha256 == $plan_sha
      and .role == $role
      and .platform == "linux/amd64"
      and .repository == $repository
      and .version == $version
      and .tag == $version
      and .localRef == $local_reference
      and .sourceRevision == $revision
      and .sourceKind == "release"
      and .sourceDirty == false
      and .archive == $archive
      and .archiveSha256 == $sha
    ' "${metadata}" >/dev/null
  jq -e \
    --arg role "${role}" \
    --arg version "${version}" \
    --arg plan_sha "${plan_sha}" \
    --arg repository "${repository}" \
    --arg local_reference "${local_reference}" \
    --arg revision "${revision}" \
    --arg archive "$(basename -- "${archive}")" \
    --arg archive_sha "${actual_sha}" \
    --arg metadata_sha "${metadata_sha}" '
      . == {
        schemaVersion:1,
        planSha256:$plan_sha,
        role:$role,
        platform:"linux/amd64",
        repository:$repository,
        tag:$version,
        localRef:$local_reference,
        sourceRevision:$revision,
        archive:$archive,
        archiveSha256:$archive_sha,
        metadataSha256:$metadata_sha
      }
    ' "${evidence}" >/dev/null
  jq -e \
    --arg role "${role}" \
    --arg revision "${revision}" \
    --arg local_reference "${local_reference}" '
      .schemaVersion == 1
      and .role == $role
      and .platform == "linux/amd64"
      and .sourceRevision == $revision
      and .repositoryTag == $local_reference
    ' "${validation}" >/dev/null
  jq -e \
    --arg role "${role}" \
    --arg revision "${revision}" '
      .schemaVersion == 1
      and .role == $role
      and .platform == "linux/amd64"
      and .sourceRevision == $revision
      and .passed == true
    ' "${smoke}" >/dev/null
  jq -e \
    '.schemaVersion == 1 and .allowed == true and (.blockedFindings | length) == 0' \
    "${decision}" >/dev/null

  load_output=$(docker load --input "${archive}")
  grep -F -- "Loaded image: ${local_reference}" <<<"${load_output}" >/dev/null || {
    echo "loaded archive did not report expected reference ${local_reference}" >&2
    exit 1
  }
  [[ "$(docker image inspect "${local_reference}" --format '{{.Architecture}}')" == amd64 ]] || {
    echo "loaded archive has the wrong architecture for ${role}/amd64" >&2
    exit 1
  }
  loaded_refs+=("${local_reference}")
  compose_reference="${role}:phase2"
  docker tag "${local_reference}" "${compose_reference}"
  compose_refs+=("${compose_reference}")
done

# The OIDC server is a pinned acceptance fixture, not a published FileBelt
# subject. Every FileBelt service below comes from a validated release archive.
docker build \
  --file "${repo_root}/tests/docker/oidc/Dockerfile" \
  --tag filebelt-oidc-fixture:phase2 \
  "${repo_root}/tests/docker/oidc"
fixture_built=1

FILEBELT_ACCEPTANCE_SKIP_BUILD=1 \
  "${repo_root}/tests/docker/phase2/run-acceptance.sh"

echo "Phase 3 exact-artifact Docker acceptance passed for ${version}"
