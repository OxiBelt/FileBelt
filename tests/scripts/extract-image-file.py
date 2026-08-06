#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Extract one regular file from the final layers of a Docker archive."""

from __future__ import annotations

import argparse
import io
import json
import tarfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    wanted = args.path.lstrip("/")
    content: bytes | None = None
    mode = 0o755
    with tarfile.open(args.archive, "r:*") as archive:
        manifest_file = archive.extractfile("manifest.json")
        if manifest_file is None:
            raise SystemExit("Docker archive has no manifest.json")
        manifest = json.load(manifest_file)
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise SystemExit("Docker archive must contain exactly one image")
        for layer_name in manifest[0]["Layers"]:
            layer_file = archive.extractfile(layer_name)
            if layer_file is None:
                raise SystemExit(f"Docker archive layer is missing: {layer_name}")
            with tarfile.open(fileobj=io.BytesIO(layer_file.read()), mode="r:*") as layer:
                names = {item.name.removeprefix("./"): item for item in layer.getmembers()}
                whiteout = str(Path(wanted).parent / (".wh." + Path(wanted).name))
                if whiteout in names:
                    content = None
                member = names.get(wanted)
                if member is not None and member.isfile():
                    source = layer.extractfile(member)
                    if source is None:
                        raise SystemExit(f"cannot read {args.path}")
                    content = source.read()
                    mode = member.mode
    if content is None:
        raise SystemExit(f"image file not found: {args.path}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(content)
    args.output.chmod(mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
