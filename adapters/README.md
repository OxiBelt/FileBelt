<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt adapters

Adapters are optional public integrations, not paid features. Each adapter is
a separate license, build, process, image, and source-distribution region. The
root Apache workspaces must never absorb adapter implementation code.

Adapters remain outside the root Cargo and pnpm workspaces and may consume only
Apache protocol schemas or clients through a documented, replaceable process
boundary. The SMB and FTP/FTPS regions are guarded previews, while ONLYOFFICE
contains a non-publishable implementation scaffold whose image inputs and
release evidence remain gated. No adapter may import another adapter's
implementation or become the only usable path for an Apache core capability.

Before adding source, a dependency or build manifest, generated output, a
Dockerfile, or an image, complete the same-pull-request design and license
review required by [`CONTRIBUTING.md`](../CONTRIBUTING.md). Record:

- the exact upstream project, revision or version, edition, configure flags,
  linked libraries, and resulting SPDX expression;
- package, process, protocol, authentication, authorization, storage, database,
  network, callback, TLS, secret, and image boundaries;
- notices, corresponding-source, network-source, replacement or relinking, and
  reproducible-build obligations that apply;
- supported platforms and functional, protocol, security, license, SBOM,
  vulnerability, and source-mapping evidence; and
- updates to the [license map](../docs/LicenseMap.md),
  [interfaces and capabilities](../docs/InterfacesAndCapabilities.md), and
  [runtime and deployment](../docs/RuntimeAndDeployment.md) contracts.

The reserved regions have these additional constraints:

- `smb/` is GPL-3.0-or-later and may integrate with Samba only through the
  generic FileBelt VFS process boundary.
- `ftp-ftps/` is GPL-3.0-or-later; its review must define the serving framework,
  credential mapping, TLS modes, data-channel exposure, and command surface.
- `onlyoffice/` is AGPL-3.0-only and receives no payload mount or general
  database credential; its review must define edition, network source access,
  JWT and callback handling, branding, and provider-specific browser code.
- `nfs/` is LGPL-3.0-or-later; any NFS-Ganesha FSAL review must define the exact
  ABI, linkage, replacement and relinking path, and protocol integration.
- `transcode/` remains an Apache-2.0 governance-only region. Do not add FFmpeg
  configuration, source, manifests, binaries, or images until the review fixes
  the exact upstream composition, GPL/LGPL result, notices, source mapping, and
  per-platform functional tests.
