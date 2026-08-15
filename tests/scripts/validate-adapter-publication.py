#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Cross-check adapter plan, compatibility policy, and produced evidence."""

from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import sys
import tarfile
import tomllib

from adapter_source_bundle import (
    BundleError,
    validate_bundle,
    validate_bundle_against_plan,
    validate_canonical_adapter_plan,
)

PRECONDITION_KEYS = {
    "sourceBundle": "source-bundle",
    "dependencyCompatibility": "dependency-compatibility",
    "componentPolicy": "component-policy",
    "licenseNotices": "license-notices",
    "buildInputs": "build-inputs",
    "immutableSource": "immutable-source",
    "buildContext": "build-context",
}


def fail(message: str) -> None:
    raise ValueError(message)


def nonempty_file(path: pathlib.Path) -> bool:
    return path.is_file() and path.stat().st_size > 0


def json_object(path: pathlib.Path, description: str) -> dict[str, object]:
    if not nonempty_file(path):
        fail(f"{description} is absent or empty: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{description} must be a JSON object: {path.name}")
    return value


def validate(plan_path: pathlib.Path, policy_path: pathlib.Path, evidence_root: pathlib.Path) -> dict[str, object]:
    validate_canonical_adapter_plan(plan_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    policy = tomllib.loads(policy_path.read_text(encoding="utf-8"))
    if plan.get("schemaVersion") != 2 or not isinstance(plan.get("roles"), list):
        fail("adapter plan schemaVersion must be 2")
    artifacts = policy.get("artifacts")
    if not isinstance(artifacts, list):
        fail("compatibility policy artifacts are missing")
    policy_by_id = {artifact.get("id"): artifact for artifact in artifacts if isinstance(artifact, dict)}
    if set(policy_by_id) != {row.get("role") for row in plan["roles"] if isinstance(row, dict)}:
        fail("adapter plan and compatibility policy role sets differ")
    created = plan.get("source", {}).get("created") if isinstance(plan.get("source"), dict) else None
    if not isinstance(created, str):
        fail("adapter plan creation time is missing")
    try:
        commit_timestamp = int(datetime.datetime.fromisoformat(created.replace("Z", "+00:00")).timestamp())
    except ValueError as error:
        raise ValueError("adapter plan creation time is invalid") from error
    evidence_rows: list[dict[str, object]] = []
    for row in plan["roles"]:
        if not isinstance(row, dict) or not isinstance(row.get("role"), str):
            fail("adapter plan contains a malformed role")
        role = row["role"]
        artifact = policy_by_id[role]
        planned_components = row.get("components")
        policy_components = artifact.get("components")
        normalized_policy = [
            {
                "id": item["id"],
                "version": item["version"],
                "license": item["license"],
                "relationship": item["relationship"],
                "path": item["path"],
                "sourceRequired": item["source_required"],
            }
            for item in policy_components
        ]
        if planned_components != normalized_policy:
            fail(f"{role} component inventory differs from compatibility policy")
        minimum = artifact.get("minimum_license_expression")
        image_license = row.get("imageLicense")
        if not isinstance(minimum, str) or not isinstance(image_license, str):
            fail(f"{role} license expressions are malformed")
        for required in minimum.split(" AND "):
            if required not in image_license.split(" AND "):
                fail(f"{role} image license omits required expression {required}")
        pre_image = row.get("preImage")
        if not isinstance(pre_image, dict) or set(pre_image) != set(PRECONDITION_KEYS):
            fail(f"{role} pre-image qualifications differ from policy")
        translated = {PRECONDITION_KEYS[name]: state for name, state in pre_image.items()}
        if any(state not in {"blocked", "qualified"} for state in translated.values()):
            fail(f"{role} pre-image qualification state is invalid")
        expected_state = "eligible" if all(state == "qualified" for state in translated.values()) else "blocked"
        image_build = row.get("imageBuild")
        if not isinstance(image_build, dict) or image_build.get("state") != expected_state:
            fail(f"{role} image-build decision is inconsistent")
        source_bundle = row.get("sourceBundle")
        evidence = row.get("evidence")
        source = row.get("source")
        if not isinstance(source_bundle, dict) or not isinstance(evidence, dict) or not isinstance(source, dict):
            fail(f"{role} evidence names are malformed")
        bundle_path = evidence_root / str(source_bundle.get("assetName"))
        image_path = evidence_root / f"{role}-{plan['version']}.docker.tar"
        runtime_sbom = evidence_root / str(evidence.get("runtimeSbom"))
        build_sbom = evidence_root / str(evidence.get("buildSbom"))
        provenance = evidence_root / str(evidence.get("provenance"))
        image_validation = evidence_root / str(evidence.get("imageValidation"))
        vulnerability = evidence_root / str(evidence.get("vulnerabilityDecision"))
        rebuild = evidence_root / str(evidence.get("rebuild"))
        notices = evidence_root / str(evidence.get("notices"))
        produced: list[str] = []
        if nonempty_file(bundle_path):
            if not isinstance(source.get("revision"), str):
                fail(f"{role} source identity is malformed")
            validate_bundle(
                bundle_path,
                role,
                str(plan["version"]),
                source["revision"],
                commit_timestamp,
            )
            validate_bundle_against_plan(bundle_path, plan_path, role)
            produced.append("source-bundle")
        if nonempty_file(image_path):
            produced.append("image")
        if nonempty_file(runtime_sbom) and nonempty_file(build_sbom):
            for path, description in ((runtime_sbom, "runtime SBOM"), (build_sbom, "build SBOM")):
                document = json_object(path, f"{role} {description}")
                if (
                    document.get("bomFormat") != "CycloneDX"
                    or not isinstance(document.get("components"), list)
                    or not document["components"]
                ):
                    fail(f"{role} {description} is not a CycloneDX component inventory")
            produced.append("image-sbom")
        if nonempty_file(provenance):
            statements = [json.loads(line) for line in provenance.read_text(encoding="utf-8").splitlines() if line.strip()]
            if not statements or not all(isinstance(statement, dict) for statement in statements):
                fail(f"{role} provenance is not JSON-lines statement evidence")
            identity = json.dumps(statements, sort_keys=True)
            if role not in identity or str(source_bundle.get("sha256")) not in identity:
                fail(f"{role} provenance is not bound to the role and source bundle")
            produced.append("image-provenance")
        if nonempty_file(image_validation):
            validation = json_object(image_validation, f"{role} image validation")
            if validation.get("role") != role or validation.get("sourceBundleSha256") != source_bundle.get("sha256"):
                fail(f"{role} image validation differs from the plan")
            produced.append("image-validation")
        if nonempty_file(vulnerability):
            decision = json_object(vulnerability, f"{role} vulnerability decision")
            if decision.get("allowed") is not True:
                fail(f"{role} vulnerability decision is not allowed")
            produced.append("vulnerability-decision")
        if nonempty_file(rebuild):
            json_object(rebuild, f"{role} rebuild evidence")
            produced.append("rebuild")
        if nonempty_file(notices):
            with tarfile.open(notices, mode="r:gz") as archive:
                members = archive.getmembers()
                if not members or any(not (member.isfile() or member.isdir()) for member in members):
                    fail(f"{role} notice archive is empty or unsafe")
            produced.append("notices")
        image_evidence_paths = (
            image_path,
            runtime_sbom,
            build_sbom,
            provenance,
            image_validation,
            vulnerability,
            rebuild,
            notices,
        )
        forbidden = [path for path in image_evidence_paths if path.exists()]
        if expected_state == "blocked" and forbidden:
            fail(f"{role} produced image evidence while its pre-image gate is blocked")
        required = {
            "source-bundle",
            "image",
            "image-sbom",
            "image-provenance",
            "image-validation",
            "vulnerability-decision",
            "rebuild",
            "notices",
        }
        if expected_state == "eligible" and set(produced) != required:
            fail(f"{role} eligible build lacks complete validated image evidence")
        evidence_rows.append({
            "id": role,
            "image_build_state": expected_state,
            "preconditions": translated,
            "produced": produced,
        })
    return {"schema_version": 1, "artifacts": evidence_rows}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=pathlib.Path, required=True)
    parser.add_argument("--policy", type=pathlib.Path, required=True)
    parser.add_argument("--evidence-root", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    arguments = parser.parse_args()
    try:
        result = validate(arguments.plan, arguments.policy, arguments.evidence_root)
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (BundleError, OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
