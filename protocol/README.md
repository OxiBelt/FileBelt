<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt protocols

Protocol-neutral Protobuf `proto3` schemas live under
`protocol/<domain>/v1/` and use `filebelt.<domain>.v1` packages. The current
schemas define browser/worker `fbcap1` capabilities, mount/worker `fbcap2`
capabilities, notification envelopes, and collaboration frames. The two
capability envelopes use distinct signing domains and prefixes so neither can
be admitted at the other's boundary. `protocol/vfs/v1/` additionally defines
the generic read-only, request-correlated mTLS boundary used by separately
licensed SMB and explicit-FTPS adapter processes; it carries FileBelt IDs and
opaque sessions, never adapter implementation or host-path types. The public HTTP
contract lives at `protocol/http/v1/openapi.yaml`. See
[Interfaces and Capabilities](../docs/InterfacesAndCapabilities.md) for the
transport, trust, compatibility, and key-rotation contract.

The same VFS v1 package reserves an additive, protocol-neutral NFS callback
surface. NFS bootstrap resolves a tenant slug and advertises compatibility;
post-authentication callbacks carry an RPCSEC_GSS binding plus bounded
client/session replay coordinates, and mutations additionally carry a fixed
request digest. Distinct sessionless gateway-control calls acknowledge an
atomically applied desired export manifest and fence a draining gateway epoch.
An acknowledgement is bound to the exact boot, epoch, authority generations,
manifest digest, and sorted export/root-handle digests, so neither an operator
nor a partially configured adapter can assert readiness. Persistent handles,
export manifests, ACLs, filesystem
information, sparse controls, and projected attributes remain FileBelt wire
types rather than NFS-Ganesha ABI types. Schema availability alone does not
activate NFS dispatch or an export. Successful NFS authentication returns the
immutable POSIX session projection selected by Core, including its mapping and
feature generations and allowed exports; those values construct a Ganesha
credential but never become authorization authority.

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
