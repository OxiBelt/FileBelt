<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt License Map

This engineering map is not legal advice. The machine-readable source of truth
is `supply-chain/license-regions.toml`.

| Paths | First-party SPDX expression | Owner | Boundary |
| --- | --- | --- | --- |
| Root files, `.cargo/`, `.github/`, `source/`, `protocol/`, `ui/`, `devops/`, `deploy/`, `tests/`, `docs/`, `supply-chain/`, `fuzz/`, `tools/` | Apache-2.0 | `@PiQuark6046` | Root Apache workspaces |
| `adapters/smb/` | GPL-3.0-or-later | `@PiQuark6046` | Separate workspace/process/image |
| `adapters/ftp-ftps/` | GPL-3.0-or-later | `@PiQuark6046` | Separate workspace/process/image |
| `adapters/onlyoffice/` | AGPL-3.0-only | `@PiQuark6046` | Separate workspace/process/image; network source access required |
| `adapters/nfs/` | LGPL-3.0-or-later | `@PiQuark6046` | Reserved separate workspace/process/image |
| `adapters/transcode/` governance files | Apache-2.0 | `@PiQuark6046` | No implementation until a composition ADR |

Apache packages may expose protocol-neutral schemas used by adapters. They may
not import, link, or path-depend on adapter implementation code. Every image
must carry a license expression matching its actual contents.
