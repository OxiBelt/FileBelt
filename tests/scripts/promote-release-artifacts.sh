#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
  echo "usage: promote-release-artifacts.sh --plan FILE --artifacts-root DIR --registry HOST --output FILE" >&2
}

plan=
artifacts_root=
registry=
output=
while (( $# > 0 )); do
  case "$1" in
    --plan) plan=${2:-}; shift 2 ;;
    --artifacts-root) artifacts_root=${2:-}; shift 2 ;;
    --registry) registry=${2:-}; shift 2 ;;
    --output) output=${2:-}; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done

[[ -f "${plan}" && -d "${artifacts_root}" && -n "${registry}" && -n "${output}" ]] || {
  usage
  exit 2
}
[[ "${registry}" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*(\:[0-9]{1,5})?$ ]] || {
  echo "release registry is invalid" >&2
  exit 2
}

for command in awk docker find jq mktemp sha256sum; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "required command is unavailable: ${command}" >&2
    exit 1
  }
done

[[ "${registry}" == "ghcr.io" ]] || {
  echo "release publication is restricted to ghcr.io" >&2
  exit 2
}
[[ ! -e "${output}" ]] || {
  echo "refusing to replace release subject evidence: ${output}" >&2
  exit 1
}

jq -e --arg registry "${registry}" '
  .schemaVersion == 1
  and .channel == "release"
  and .version == .tag
  and (.tag | test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?$"))
  and .source.kind == "release"
  and .source.dirty == false
  and .source.url == "https://github.com/OxiBelt/FileBelt"
  and .source.ref == ("refs/tags/" + .version)
  and (.source.revision | test("^[0-9a-f]{40}$"))
  and (.source.created | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  and .runtime == {uid:10001,gid:10001}
  and (.images | length) == 9
  and ([.images[].role] | sort) == ([
    "filebelt-api",
    "filebelt-mcp-broker",
    "filebelt-media-controller",
    "filebelt-controller",
    "filebelt-mcp-runner",
    "filebelt-tools",
    "filebelt-web",
    "filebelt-worker-io",
    "filebelt-worker-maintenance"
  ] | sort)
  and all(.images[];
    .repository == ($registry + "/oxibelt/" + .role)
    and ([.platforms[]] | sort) == (["linux/amd64", "linux/arm64", "linux/riscv64"] | sort)
  )
' "${plan}" >/dev/null

active_roles=(
  filebelt-api
  filebelt-worker-io
  filebelt-worker-maintenance
  filebelt-mcp-broker
  filebelt-controller
  filebelt-mcp-runner
  filebelt-tools
  filebelt-web
)
architectures=(amd64 arm64 riscv64)
temporary=$(mktemp -d)
cleanup() {
  for reference in "${loaded_refs[@]:-}"; do
    docker image rm --force "${reference}" >/dev/null 2>&1 || true
  done
  rm -rf -- "${temporary}"
}
trap cleanup EXIT
loaded_refs=()
printf '[]\n' >"${temporary}/subjects.json"

find_one() {
  local pattern=$1
  mapfile -t matches < <(find "${artifacts_root}" -type f -name "${pattern}" -print)
  if (( ${#matches[@]} != 1 )); then
    echo "expected exactly one ${pattern}, found ${#matches[@]}" >&2
    return 1
  fi
  printf '%s\n' "${matches[0]}"
}

version=$(jq -er '.tag' "${plan}")
plan_sha=$(sha256sum "${plan}" | awk '{print $1}')
source_revision=$(jq -er '.source.revision' "${plan}")
source_ref=$(jq -er '.source.ref' "${plan}")
source_created=$(jq -er '.source.created' "${plan}")
for role in "${active_roles[@]}"; do
  repository=$(jq -er --arg role "${role}" '.images[] | select(.role == $role) | .repository' "${plan}")
  target_repository="${repository}"
  final_reference="${target_repository}:${version}"
  if docker buildx imagetools inspect "${final_reference}" >/dev/null 2>&1; then
    echo "refusing to replace existing release reference ${final_reference}" >&2
    exit 1
  fi

  child_digests=()
  child_subjects='[]'
  for architecture in "${architectures[@]}"; do
    archive=$(find_one "${role}-${architecture}.docker.tar")
    metadata=$(find_one "${role}-${architecture}.build.json")
    checksum=$(find_one "${role}-${architecture}.docker.tar.sha256")
    evidence=$(find_one "${role}-${architecture}.evidence.json")
    validation=$(find_one "${role}-${architecture}.validation.json")
    smoke=$(find_one "${role}-${architecture}.smoke.json")
    decision=$(find_one "${role}-${architecture}.vulnerability-decision.json")
    find_one "${role}-${architecture}.cdx.json" >/dev/null
    find_one "${role}-${architecture}.runtime.cdx.json" >/dev/null
    expected_sha=$(jq -er '.archiveSha256' "${metadata}")
    actual_sha=$(sha256sum "${archive}" | awk '{print $1}')
    metadata_sha=$(sha256sum "${metadata}" | awk '{print $1}')
    [[ "${actual_sha}" == "${expected_sha}" ]] || {
      echo "archive checksum mismatch for ${role}/${architecture}" >&2
      exit 1
    }
    checksum_line=$(<"${checksum}")
    [[ "${checksum_line}" == "${actual_sha}  $(basename -- "${archive}")" ]] || {
      echo "checksum evidence mismatch for ${role}/${architecture}" >&2
      exit 1
    }
    local_reference="${repository}:${version}-${architecture}"
    jq -e \
      --arg role "${role}" \
      --arg platform "linux/${architecture}" \
      --arg version "${version}" \
      --arg plan_sha "${plan_sha}" \
      --arg repository "${repository}" \
      --arg local_reference "${local_reference}" \
      --arg revision "${source_revision}" \
      --arg source_ref "${source_ref}" \
      --arg source_created "${source_created}" \
      --arg archive "$(basename -- "${archive}")" '
        .schemaVersion == 1
        and .planSha256 == $plan_sha
        and .role == $role
        and .platform == $platform
        and .repository == $repository
        and .version == $version
        and .tag == $version
        and .localRef == $local_reference
        and .sourceRevision == $revision
        and .sourceRef == $source_ref
        and .sourceCreated == $source_created
        and .sourceKind == "release"
        and .sourceDirty == false
        and .archive == $archive
      ' "${metadata}" >/dev/null
    jq -e \
      --arg role "${role}" \
      --arg platform "linux/${architecture}" \
      --arg plan_sha "${plan_sha}" \
      --arg repository "${repository}" \
      --arg version "${version}" \
      --arg local_reference "${local_reference}" \
      --arg revision "${source_revision}" \
      --arg archive "$(basename -- "${archive}")" \
      --arg archive_sha "${actual_sha}" \
      --arg metadata_sha "${metadata_sha}" '
        . == {
          schemaVersion:1,
          planSha256:$plan_sha,
          role:$role,
          platform:$platform,
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
      --arg platform "linux/${architecture}" \
      --arg revision "${source_revision}" \
      --arg local_reference "${local_reference}" '
        .schemaVersion == 1
        and .role == $role
        and .platform == $platform
        and .sourceRevision == $revision
        and .repositoryTag == $local_reference
      ' "${validation}" >/dev/null
    jq -e \
      --arg role "${role}" \
      --arg platform "linux/${architecture}" \
      --arg revision "${source_revision}" '
        .schemaVersion == 1
        and .role == $role
        and .platform == $platform
        and .sourceRevision == $revision
        and .passed == true
      ' "${smoke}" >/dev/null
    jq -e \
      '.schemaVersion == 1 and .allowed == true and (.blockedFindings | length) == 0' \
      "${decision}" >/dev/null

    load_output=$(docker load --input "${archive}")
    grep -F -- "${local_reference}" <<<"${load_output}" >/dev/null || {
      echo "loaded archive did not report expected reference ${local_reference}" >&2
      exit 1
    }
    loaded_refs+=("${local_reference}")
    platform_reference="${target_repository}:${version}-${architecture}"
    if docker buildx imagetools inspect "${platform_reference}" >/dev/null 2>&1; then
      echo "refusing to replace existing platform reference ${platform_reference}" >&2
      exit 1
    fi
    docker tag "${local_reference}" "${platform_reference}"
    loaded_refs+=("${platform_reference}")
    docker push "${platform_reference}" >/dev/null
    child_digest=$(docker buildx imagetools inspect "${platform_reference}" \
      --format '{{json .Manifest}}' | jq -er '.digest')
    [[ "${child_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
      echo "registry returned an invalid digest for ${platform_reference}" >&2
      exit 1
    }
    child_digests+=("${target_repository}@${child_digest}")
    child_subjects=$(jq -c \
      --arg architecture "${architecture}" \
      --arg digest "${child_digest}" \
      --arg reference "${platform_reference}" \
      '. + [{architecture:$architecture,digest:$digest,reference:$reference}]' \
      <<<"${child_subjects}")
  done

  docker buildx imagetools create --tag "${final_reference}" "${child_digests[@]}" >/dev/null
  final_manifest=$(docker buildx imagetools inspect "${final_reference}" --format '{{json .Manifest}}')
  final_digest=$(jq -er '.digest' <<<"${final_manifest}")
  [[ "${final_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo "registry returned an invalid index digest for ${final_reference}" >&2
    exit 1
  }
  resolved_digest=$(docker buildx imagetools inspect "${final_reference}" \
    --format '{{json .Manifest}}' | jq -er '.digest')
  [[ "${resolved_digest}" == "${final_digest}" ]] || {
    echo "release digest readback mismatch for ${final_reference}" >&2
    exit 1
  }
  readback=$(docker buildx imagetools inspect "${final_reference}" --raw)
  for index in "${!architectures[@]}"; do
    architecture="${architectures[${index}]}"
    expected_digest="${child_digests[${index}]#*@}"
    jq -e \
      --arg architecture "${architecture}" \
      --arg digest "${expected_digest}" '
        [.manifests[] | select(
          .platform.os == "linux"
          and .platform.architecture == $architecture
          and .digest == $digest
        )] | length == 1
      ' <<<"${readback}" >/dev/null || {
        echo "release index readback mismatch for ${role}/${architecture}" >&2
        exit 1
      }
  done
  [[ "$(jq -er '.manifests | length' <<<"${readback}")" == "${#architectures[@]}" ]] || {
    echo "release index contains an unexpected platform for ${role}" >&2
    exit 1
  }
  jq \
    --arg role "${role}" \
    --arg name "${target_repository}" \
    --arg reference "${final_reference}" \
    --arg digest "${final_digest}" \
    --argjson children "${child_subjects}" \
    '. + [{role:$role,name:$name,reference:$reference,digest:$digest,children:$children}]' \
    "${temporary}/subjects.json" >"${temporary}/subjects.next.json"
  mv "${temporary}/subjects.next.json" "${temporary}/subjects.json"
done

mkdir -p "$(dirname "${output}")"
jq -S --arg version "${version}" '{schemaVersion:1,version:$version,subjects:.}' \
  "${temporary}/subjects.json" >"${output}"
