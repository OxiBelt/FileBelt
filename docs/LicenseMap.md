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
| `adapters/transcode/` governance files | Apache-2.0 | `@PiQuark6046` | No implementation until the exact FFmpeg composition and license boundary are reviewed and documented |

Apache packages may expose protocol-neutral schemas used by adapters. They may
not import, link, or path-depend on adapter implementation code. Every image
must carry a license expression matching its actual contents.

## Runtime composition

The source-region expression and final-image expression answer different
questions. Original code under `source/`, `protocol/`, `ui/`, and `devops/`
remains Apache-2.0. A final executable or image also carries the compatible
licenses and notices of its linked runtime and copied upstream contents.

| Artifact/input | Composition rule | Boundary and evidence |
| --- | --- | --- |
| `filebelt-api`, `filebelt-worker-io`, `filebelt-collaboration`, `filebelt-vfs`, and `filebelt-headscale-sync` | `Apache-2.0 AND MIT AND CDLA-Permissive-2.0` | Apache FileBelt source, Rust/musl runtime, and admitted WebPKI certificate data; ship exact upstream notices and inspect native linkage |
| `filebelt-worker-maintenance` and `filebelt-tools` | `Apache-2.0 AND MIT AND MPL-2.0 AND CDLA-Permissive-2.0` | Adds the exact Iggy client and its unmodified MPL helper; ship its license and corresponding-source pointer with SBOM evidence |
| `filebelt-media-controller` and `filebelt-mcp-runner` | `Apache-2.0 AND MIT` | Apache FileBelt source plus the Rust/musl runtime; ship exact notices and inspect native linkage |
| `filebelt-mcp-broker` and `filebelt-controller` | `Apache-2.0 AND MIT AND CDLA-Permissive-2.0` | Apache FileBelt source, Rust/musl runtime, and admitted WebPKI certificate data; the controller also contains the reviewed Sigstore verifier graph |
| `filebelt-web` | `Apache-2.0 AND MIT AND ISC AND 0BSD` | FileBelt Apache SPA/config, ISC Lucide assets, and 0BSD `tslib` copied onto the digest-pinned Apache-2.0 OxiBelt runtime; no source linkage or copied reference code |
| `tslib@2.8.1` | `0BSD` | Lockfile-pinned Fluent UI runtime helper admitted by the Node license policy; distributed only as part of the browser bundle |
| PostgreSQL 18.4 helper | Upstream PostgreSQL License | External Docker integration process; retain upstream label/notices; never republish as a FileBelt image |
| Apache Iggy 0.8.0 helper and client | Upstream Apache-2.0 evidence | Optional external event process and reviewed generic client; never authoritative and never republished as a FileBelt image |
| OIDC test provider | Exact upstream composition recorded by the Docker plan | External integration fixture only; not a FileBelt release image |
| Rustls/OTLP/Prometheus runtime support | Apache-2.0 and compatible MIT/ISC dependencies recorded in `Cargo.lock` | Shared only through the Apache-2.0 `filebelt-runtime` crate; exact graph, notice, SBOM, vulnerability, and Cargo Vet admission are required before promotion |
| `filebelt-smb-gateway` | `GPL-3.0-or-later` final image | Separate adapter workspace plus exact Samba `4.24.4` source/patch/build context. The scaffold pins the official archive SHA-256 and ships notices/source-offer requirements, but no image may publish until the complete corresponding source and working reviewed bridge are packaged. |
| `filebelt-ftp-ftps-gateway` | `GPL-3.0-or-later` final image | Separate adapter workspace with exact `libunftp 0.23.0` lock and notice evidence. Its Docker recipe is deliberately blocked until digest-pinned build/runtime bases, the complete buildable source context, SBOM, and corresponding-source offer are reviewed. |

`filebelt-mcp-broker` uses the exact reviewed MCP model/runtime graph and
`filebelt-controller` uses the exact offline Sigstore verification graph. Those
dependencies remain linked only into Apache-region processes; they do not move
third-party MCP server source into FileBelt. `filebelt-mcp-runner` is a generic
relay/shim and neither links to nor copies a catalog server implementation.

Operator-supplied MCP egress gateways and catalog server images are external
processes, not FileBelt release artifacts. Every admitted catalog entry records
its own source and license and uses a digest-pinned image plus verified Sigstore
bundle. The operator remains responsible for that image's distribution terms,
notices, and corresponding source. Catalog verification and a Pod boundary are
security/process evidence; they are not a substitute for license review.

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

Helm templates, Kubernetes and NetworkPolicy manifests, operational scripts,
Prometheus rules, Grafana dashboards, and OpenTelemetry examples are original
Apache-2.0 repository content. They introduce no source link from Apache core
to an adapter. PostgreSQL, Iggy, OIDC, the OIDC/MCP egress gateways, CSI
provider, certificate issuer, and monitoring services remain external
processes and are not redistributed by the FileBelt chart. New Rust TLS,
metrics, and telemetry crates must appear in the exact Cargo graph, image SBOM,
notices, Cargo Vet, Cargo Deny, and vulnerability evidence before their images
can be promoted.

Changing a license region, moving code between regions, admitting a copyleft or
native dependency, or changing an image's composition requires an explicit
license and architecture review in the same pull request. Record contributor
relicensing authority where applicable and update this map, the machine-readable
region policy, [dependency boundaries](DependencyBoundaries.md),
[supply-chain policy](SupplyChain.md), and
[runtime specification](RuntimeAndDeployment.md) together.
