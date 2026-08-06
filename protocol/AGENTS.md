<!-- SPDX-License-Identifier: Apache-2.0 -->

# Protocol guidance

This tree is Apache-2.0 and is a public, replaceable process boundary.

- Follow ADR-0004 and ADR-0009. Version Protobuf schemas below
  `protocol/<domain>/v1/` with `filebelt.<domain>.v1` packages.
- Use FileBelt tenant/principal/resource/operation identifiers and stable wire
  enums. Never serialize database rows, physical paths, OxiBelt/Iggy internals,
  or Samba, FTP, ONLYOFFICE, NFS-Ganesha, Kubernetes, or browser-library types.
- Signed messages use deterministic fields and exact serialized bytes. Avoid
  maps or unordered collections in signed claims.
- Generated output is committed, records source/generator/version/command and
  license, and is never hand-edited.
- Treat released `v1` compatibility as durable. Run lint, breaking, generation
  drift, license, and consumer tests in the same change.
- Adapters may consume these contracts through a documented process boundary;
  Apache packages may never import adapter implementation code.
