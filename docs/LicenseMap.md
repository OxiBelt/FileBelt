<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt License Map

This engineering map is not legal advice. The machine-readable source of truth
is `supply-chain/license-regions.toml`.

| Paths | First-party SPDX expression | Owner | Boundary |
| --- | --- | --- | --- |
| Root files, `.cargo/`, `.github/`, `source/`, `protocol/`, `ui/`, `devops/`, `deploy/`, `tests/`, `docs/`, `supply-chain/`, `fuzz/`, `tools/` | Apache-2.0 | `@PiQuark6046` | Root Apache workspaces |
| `source/ops/runtime/musl-COPYRIGHT` | MIT | musl contributors | Reviewed upstream notice only; not a Cargo package or source dependency |
| `adapters/smb/` | GPL-3.0-or-later | `@PiQuark6046` | Separate workspace/process/image |
| `adapters/ftp-ftps/` | GPL-3.0-or-later | `@PiQuark6046` | Separate workspace/process/image |
| `adapters/onlyoffice/` | AGPL-3.0-only | `@PiQuark6046` | Separate workspace/process/image; network source access required |
| `adapters/nfs/` | LGPL-3.0-or-later | `@PiQuark6046` | Reserved separate workspace/process/image |
| `adapters/transcode/` governance files | Apache-2.0 | `@PiQuark6046` | No implementation until a composition ADR |

Apache packages may expose protocol-neutral schemas used by adapters. They may
not import, link, or path-depend on adapter implementation code. Every image
must carry a license expression matching its actual contents.

## Phase 2 runtime composition

The source-region expression and final-image expression answer different
questions. Original code under `source/`, `protocol/`, `ui/`, and `devops/`
remains Apache-2.0. A final executable or image also carries the compatible
licenses and notices of its linked runtime and copied upstream contents.

| Artifact/input | Composition rule | Boundary and evidence |
| --- | --- | --- |
| `filebelt-api` and `filebelt-worker-io` | `Apache-2.0 AND MIT AND CDLA-Permissive-2.0` | Apache FileBelt source, Rust/musl runtime, and admitted WebPKI certificate data; ship exact upstream notices and inspect native linkage |
| `filebelt-worker-maintenance` and `filebelt-tools` | `Apache-2.0 AND MIT AND MPL-2.0 AND CDLA-Permissive-2.0` | Adds the exact Iggy client and its unmodified MPL helper; ship its license and corresponding-source pointer with SBOM evidence |
| `filebelt-media-controller` and `filebelt-mcp-broker` | `Apache-2.0 AND MIT` | Apache FileBelt source plus the Rust/musl runtime; ship exact notices and inspect native linkage |
| `filebelt-web` | `Apache-2.0 AND MIT AND ISC AND 0BSD` | FileBelt Apache SPA/config, ISC Lucide assets, and 0BSD `tslib` copied onto the digest-pinned Apache-2.0 OxiBelt runtime; no source linkage or copied reference code |
| `tslib@2.8.1` | `0BSD` | Lockfile-pinned Fluent UI runtime helper admitted by the Node license policy; distributed only as part of the browser bundle |
| PostgreSQL 18.4 helper | Upstream PostgreSQL License | External Docker integration process; retain upstream label/notices; never republish as a FileBelt image |
| Apache Iggy 0.8.0 helper and client | Upstream Apache-2.0 evidence | Optional external event process and reviewed generic client; never authoritative and never republished as a FileBelt image |
| OIDC test provider | Exact upstream composition recorded by the Docker plan | External integration fixture only; not a FileBelt release image |

The OxiBelt prerelease and digest, PostgreSQL digest, Iggy digest/client, native
AWS-LC composition, Cargo features, Node packages, and generated-client
runtimes are dependency-admission records under
[the supply-chain policy](SupplyChain.md). Any version, feature, linkage, or
base-image change repeats license and notice review.

Runtime configuration and generic network protocols do not permit source to
cross a license region. Apache core must remain usable without an adapter and
must not deserialize Samba, FTP server, ONLYOFFICE, NFS-Ganesha, or FFmpeg
implementation structures. Container separation is operational evidence, not
the sole license analysis.
