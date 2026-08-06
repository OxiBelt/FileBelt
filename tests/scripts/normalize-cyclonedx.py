#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Bind a Trivy CycloneDX document to the canonical FileBelt image subject."""

from __future__ import annotations

import argparse
import json
import uuid
from pathlib import Path
from typing import Any


COMPONENT_KEYS = {
    "type",
    "name",
    "version",
    "purl",
    "license",
    "relationship",
    "evidence",
}
COMPONENT_RELATIONSHIPS = {"runtime", "build-tool"}
COMPONENT_TYPES = {"application", "library"}


def load_object(path: Path, description: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{description} must be a JSON object")
    return value


def planned_components(image: dict[str, Any], platform: str) -> list[dict[str, Any]]:
    artifact = image.get("artifact")
    if not isinstance(artifact, dict):
        raise ValueError("image-plan artifact is malformed")
    if artifact.get("kind") == "oxibelt-edge":
        return []
    if artifact.get("kind") != "rust-binary":
        raise ValueError("image-plan artifact kind is unsupported")
    inventory = artifact.get("components")
    if not isinstance(inventory, dict) or set(inventory) != {
        "linux/amd64",
        "linux/arm64",
        "linux/riscv64",
    }:
        raise ValueError("Rust image component inventory must cover exactly three platforms")
    entries = inventory.get(platform)
    if not isinstance(entries, list) or not entries:
        raise ValueError("Rust image component inventory must be nonempty")

    result: list[dict[str, Any]] = []
    seen_purls: set[str] = set()
    relationships: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != COMPONENT_KEYS:
            raise ValueError(f"Rust image component {index} has missing or unknown properties")
        for field in ("name", "version", "purl", "license", "evidence"):
            if not isinstance(entry.get(field), str) or not entry[field]:
                raise ValueError(f"Rust image component {index} {field} must be nonempty")
        if entry["type"] not in COMPONENT_TYPES:
            raise ValueError(f"Rust image component {index} type is unsupported")
        if entry["relationship"] not in COMPONENT_RELATIONSHIPS:
            raise ValueError(f"Rust image component {index} relationship is unsupported")
        if not entry["purl"].startswith("pkg:") or entry["purl"] in seen_purls:
            raise ValueError(f"Rust image component {index} purl is invalid or duplicated")
        seen_purls.add(entry["purl"])
        relationships.add(entry["relationship"])
        result.append(
            {
                "bom-ref": entry["purl"],
                "type": entry["type"],
                "name": entry["name"],
                "version": entry["version"],
                "purl": entry["purl"],
                "scope": "required" if entry["relationship"] == "runtime" else "excluded",
                "licenses": [{"expression": entry["license"]}],
                "properties": [
                    {
                        "name": "io.filebelt.component.relationship",
                        "value": entry["relationship"],
                    },
                    {"name": "io.filebelt.component.evidence", "value": entry["evidence"]},
                    {"name": "io.filebelt.image.platform", "value": platform},
                ],
            }
        )
    if relationships != COMPONENT_RELATIONSHIPS:
        raise ValueError("Rust image inventory must contain runtime and build-tool components")
    return result


def component_relationship(component: dict[str, Any]) -> str:
    properties = component.get("properties", [])
    if not isinstance(properties, list):
        return "runtime"
    for prop in properties:
        if (
            isinstance(prop, dict)
            and prop.get("name") == "io.filebelt.component.relationship"
            and isinstance(prop.get("value"), str)
        ):
            return prop["value"]
    return "runtime"


def scanner_application(image: dict[str, Any], subject_ref: str) -> tuple[dict[str, Any], str]:
    artifact = image.get("artifact")
    if not isinstance(artifact, dict) or artifact.get("kind") != "rust-binary":
        raise ValueError("scanner application requires a Rust image artifact")
    binary = artifact.get("binary")
    if not isinstance(binary, str) or not binary:
        raise ValueError("Rust image artifact binary must be nonempty")
    reference = f"{subject_ref}:trivy-cargo"
    return (
        {
            "bom-ref": reference,
            "type": "application",
            "name": f"/usr/local/bin/{binary}",
            "properties": [
                {"name": "aquasecurity:trivy:Class", "value": "lang-pkgs"},
                {"name": "aquasecurity:trivy:Type", "value": "cargo"},
                {"name": "io.filebelt.component.relationship", "value": "runtime"},
            ],
        },
        reference,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-output", type=Path)
    args = parser.parse_args()

    plan = load_object(args.plan, "image plan")
    source = plan.get("source")
    images = plan.get("images")
    if not isinstance(source, dict) or not isinstance(images, list):
        raise ValueError("image plan source or images are missing")
    matches = [item for item in images if isinstance(item, dict) and item.get("role") == args.role]
    if len(matches) != 1 or args.platform not in matches[0].get("platforms", []):
        raise ValueError("role and platform do not match exactly one image-plan row")
    image = matches[0]

    raw = load_object(args.input, "Trivy CycloneDX document")
    if raw.get("bomFormat") != "CycloneDX" or raw.get("specVersion") != "1.7":
        raise ValueError("Trivy SBOM must be CycloneDX 1.7")
    metadata = raw.get("metadata")
    components = raw.get("components", [])
    dependencies = raw.get("dependencies", [])
    if not isinstance(metadata, dict) or not isinstance(components, list) or not isinstance(dependencies, list):
        raise ValueError("Trivy SBOM metadata, components, or dependencies are malformed")

    subject_ref = f"urn:filebelt:{source.get('revision')}:{args.role}:{args.platform}"
    serial = uuid.uuid5(uuid.NAMESPACE_URL, subject_ref)
    subject = {
        "bom-ref": subject_ref,
        "type": "container",
        "name": image.get("repository"),
        "version": plan.get("tag"),
        "properties": [
            {"name": "io.filebelt.image.role", "value": args.role},
            {"name": "io.filebelt.image.platform", "value": args.platform},
            {"name": "io.filebelt.image.license", "value": image.get("license")},
            {"name": "io.filebelt.build.revision", "value": source.get("revision")},
            {"name": "io.filebelt.build.source-ref", "value": source.get("ref")},
        ],
    }
    raw_subject = metadata.get("component")
    if not isinstance(raw_subject, dict):
        raise ValueError("Trivy SBOM subject component is malformed")
    inventory_components = planned_components(image, args.platform)
    component_refs_seen = {
        component.get("bom-ref")
        for component in components
        if isinstance(component, dict) and isinstance(component.get("bom-ref"), str)
    }
    for component in inventory_components:
        if component["bom-ref"] in component_refs_seen:
            raise ValueError("Trivy and image-plan component inventories have a duplicate bom-ref")
        component_refs_seen.add(component["bom-ref"])
    normalized_components = [*components, *inventory_components]
    if image.get("artifact", {}).get("kind") == "rust-binary" and not normalized_components:
        raise ValueError("Rust CycloneDX component inventory must be nonempty")

    normalized_dependencies = [
        dependency
        for dependency in dependencies
        if isinstance(dependency, dict)
        and dependency.get("ref") != raw_subject.get("bom-ref")
    ]
    component_refs = sorted(
        component["bom-ref"]
        for component in normalized_components
        if isinstance(component, dict)
        and isinstance(component.get("bom-ref"), str)
        and component_relationship(component) != "build-tool"
    )
    normalized_dependencies.append({"ref": subject_ref, "dependsOn": component_refs})
    result = {
        "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": source.get("created"),
            "tools": metadata.get("tools"),
            "component": subject,
        },
        "components": normalized_components,
        "dependencies": normalized_dependencies,
        "vulnerabilities": raw.get("vulnerabilities", []),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    if args.runtime_output is not None:
        runtime_components = [
            component
            for component in normalized_components
            if isinstance(component, dict) and component_relationship(component) != "build-tool"
        ]
        runtime_refs = {
            component["bom-ref"]
            for component in runtime_components
            if isinstance(component.get("bom-ref"), str)
        }
        cargo_refs = sorted(
            reference for reference in runtime_refs if reference.startswith("pkg:cargo/")
        )
        if image.get("artifact", {}).get("kind") == "rust-binary" and len(cargo_refs) != 1:
            raise ValueError("Rust runtime inventory must contain exactly one Cargo application")
        runtime_dependencies = []
        for dependency in normalized_dependencies:
            reference = dependency.get("ref")
            if reference != subject_ref and reference not in runtime_refs:
                continue
            depends_on = dependency.get("dependsOn", [])
            if not isinstance(depends_on, list):
                raise ValueError("CycloneDX dependency dependsOn must be an array")
            runtime_dependencies.append(
                {
                    "ref": reference,
                    "dependsOn": sorted(
                        item for item in depends_on if isinstance(item, str) and item in runtime_refs
                    ),
                }
            )
        if cargo_refs:
            application, application_ref = scanner_application(image, subject_ref)
            runtime_components.append(application)
            for dependency in runtime_dependencies:
                if dependency["ref"] == subject_ref:
                    dependency["dependsOn"] = sorted(
                        reference
                        for reference in dependency["dependsOn"]
                        if reference != cargo_refs[0]
                    )
                    dependency["dependsOn"].append(application_ref)
                    dependency["dependsOn"].sort()
                    break
            else:
                raise ValueError("Rust runtime subject dependency is missing")
            runtime_dependencies.append(
                {"ref": application_ref, "dependsOn": cargo_refs}
            )
        runtime_result = {
            **result,
            "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'{subject_ref}:runtime')}",
            "components": runtime_components,
            "dependencies": runtime_dependencies,
        }
        args.runtime_output.parent.mkdir(parents=True, exist_ok=True)
        args.runtime_output.write_text(
            json.dumps(runtime_result, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
