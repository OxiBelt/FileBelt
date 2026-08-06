<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt protocols

Protocol-neutral Protobuf `proto3` schemas live under
`protocol/<domain>/v1/` and use `filebelt.<domain>.v1` packages. No schema or
transport is defined in Phase 0. Phase 2 defines storage capabilities and
notification envelopes. Generated output is committed with its accepted source
schema and is checked for deterministic regeneration.

Rust messages under `generated/rust/` are produced with
`python3 protocol/generate.py --repo-root .` using the version- and revision-pinned
`community/neoeinstein-prost` plugin in `buf.gen.yaml`. The generated modules
are included by the Apache protocol crates and must never be edited directly.
The generation wrapper adds deterministic source, generator, command, and
Apache-2.0 metadata to each output file.

The browser client types under `ui/web/source/generated/` are produced with
`python3 protocol/generate-openapi-client.py --repo-root .` from the committed
OpenAPI contract. The exact `openapi-typescript` generator and `openapi-fetch`
runtime are pinned in `ui/web/package.json`.
