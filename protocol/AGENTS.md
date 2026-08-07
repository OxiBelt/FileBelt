<!-- SPDX-License-Identifier: Apache-2.0 -->

# Protocol automated-agent overlay

This file applies only to automated agents. Follow the
[root agent guidance](../AGENTS.md), [contributor workflow](../CONTRIBUTING.md),
[protocol documentation](README.md), and
[interfaces and capabilities contract](../docs/InterfacesAndCapabilities.md).

Enter Plan Mode before adding or changing a schema, transport, authentication
method, service, error, compatibility promise, generator, or adapter-facing
boundary. Stop and ask the maintainer when wire semantics, versioning,
authorization, replay behavior, compatibility, generation provenance, or
license effects are unresolved.

This tree is Apache-2.0 and defines public, replaceable process boundaries.

- Version Protobuf schemas below `protocol/<domain>/v1/` with
  `filebelt.<domain>.v1` packages.
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
