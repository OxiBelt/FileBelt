#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Generate deterministic Rust protocol modules with repository metadata."""

from __future__ import annotations

import argparse
import re
import subprocess
from collections import defaultdict
from pathlib import Path


GENERATOR = "buf.build/community/neoeinstein-prost:v0.5.0"
GENERATOR_REVISION = 1
PACKAGE_PATTERN = re.compile(r"^\s*package\s+([A-Za-z0-9_.]+)\s*;", re.MULTILINE)


def generated_modules(protocol: Path) -> dict[Path, list[Path]]:
    modules: dict[Path, list[Path]] = defaultdict(list)
    for schema in sorted(protocol.rglob("*.proto")):
        content = schema.read_text(encoding="utf-8")
        package_match = PACKAGE_PATTERN.search(content)
        if package_match is None:
            raise RuntimeError(f"schema has no package declaration: {schema}")
        package = package_match.group(1)
        output = protocol / "generated" / "rust" / Path(*package.split(".")) / f"{package}.rs"
        modules[output].append(schema)
    return modules


def validate_generator_pin(protocol: Path) -> None:
    config = (protocol / "buf.gen.yaml").read_text(encoding="utf-8")
    if f"remote: {GENERATOR}" not in config:
        raise RuntimeError(f"buf.gen.yaml must pin {GENERATOR}")
    if f"revision: {GENERATOR_REVISION}" not in config:
        raise RuntimeError(
            f"buf.gen.yaml must pin {GENERATOR} revision {GENERATOR_REVISION}"
        )


def metadata_header(root: Path, schemas: list[Path]) -> str:
    source_lines = "\n".join(
        f"// Source: {schema.relative_to(root).as_posix()}" for schema in schemas
    )
    return (
        "// SPDX-FileCopyrightText: 2026 PiQuark6046 and FileBelt contributors\n"
        "// SPDX-License-Identifier: Apache-2.0\n"
        "//\n"
        f"{source_lines}\n"
        f"// Generator: {GENERATOR} revision {GENERATOR_REVISION}\n"
        "// Regenerate: python3 protocol/generate.py --repo-root .\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    protocol = root / "protocol"

    validate_generator_pin(protocol)
    modules = generated_modules(protocol)
    subprocess.run(["buf", "generate"], cwd=protocol, check=True)

    actual_modules = set((protocol / "generated" / "rust").rglob("*.rs"))
    expected_modules = set(modules)
    if actual_modules != expected_modules:
        missing = sorted(path.relative_to(root) for path in expected_modules - actual_modules)
        unexpected = sorted(path.relative_to(root) for path in actual_modules - expected_modules)
        raise RuntimeError(
            f"generated Rust modules differ: missing={missing}, unexpected={unexpected}"
        )

    for output, schemas in modules.items():
        generated = output.read_text(encoding="utf-8")
        if not generated.startswith("// @generated\n"):
            raise RuntimeError(f"unexpected generator output header: {output}")
        output.write_text(metadata_header(root, schemas) + generated, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
