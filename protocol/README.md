<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt protocols

Protocol-neutral Protobuf `proto3` schemas live under
`protocol/<domain>/v1/` and use `filebelt.<domain>.v1` packages. The current
schemas define storage capabilities, notification envelopes, and collaboration
frames. The public HTTP
contract lives at `protocol/http/v1/openapi.yaml`. See
[Interfaces and Capabilities](../docs/InterfacesAndCapabilities.md) for the
transport, trust, compatibility, and key-rotation contract.

Schemas use FileBelt identifiers and stable wire enums. They never serialize a
database row, physical path, Kubernetes object, OxiBelt or Iggy internal, or an
adapter implementation type. Fields whose exact bytes are signed must be
deterministic and must not use maps or unordered collections. Released `v1`
contracts remain compatible; incompatible changes use a new version.

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

Generated output is committed, records its source, generator/version,
regeneration command, and Apache-2.0 license, and is checked for deterministic
regeneration. A schema change updates generated output and consumers together
and passes Buf lint and file-level breaking checks, generation drift, license,
deterministic serialization, and consumer tests.
