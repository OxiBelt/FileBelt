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
| `adapters/git/` | Apache-2.0 | `@PiQuark6046` | Apache wrapper in a separate workspace/process/image and RWX repository volume; its bundled Git executable remains GPL-2.0-only |
| `adapters/git/GIT_COMPONENT.toml` | GPL-2.0-only | Git contributors | Reviewed upstream component record; not FileBelt wrapper source |
| `adapters/nfs/` | LGPL-3.0-or-later | `@PiQuark6046` | Separate dynamic FSAL/bridge workspace and image; no reverse Apache dependency |
| `adapters/transcode/` | GPL-3.0-or-later | `@PiQuark6046` | Separate FFmpeg-linked wrapper workspace and image; no reverse Apache dependency |

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
| `filebelt-api`, `filebelt-worker-io`, `filebelt-collaboration`, `filebelt-document`, `filebelt-vfs`, `filebelt-headscale-sync`, and `filebelt-nfs-relay` | `Apache-2.0 AND MIT AND CDLA-Permissive-2.0` | Apache FileBelt source, Rust/musl runtime, and admitted WebPKI certificate data; ship exact upstream notices and inspect native linkage |
| `filebelt-worker-maintenance` and `filebelt-tools` | `Apache-2.0 AND MIT AND MPL-2.0 AND CDLA-Permissive-2.0` | Adds the exact Iggy client and its unmodified MPL helper; ship its license and corresponding-source pointer with SBOM evidence |
| `filebelt-media-controller` and `filebelt-mcp-runner` | `Apache-2.0 AND MIT` | Apache FileBelt source plus the Rust/musl runtime; ship exact notices and inspect native linkage |
| `filebelt-mcp-broker` and `filebelt-controller` | `Apache-2.0 AND MIT AND CDLA-Permissive-2.0` | Apache FileBelt source, Rust/musl runtime, and admitted WebPKI certificate data; the controller also contains the reviewed Sigstore verifier graph |
| `filebelt-web` | `Apache-2.0 AND MIT AND ISC AND 0BSD` | FileBelt Apache SPA/config, ISC Lucide assets, and 0BSD `tslib` copied onto the digest-pinned Apache-2.0 OxiBelt runtime; no source linkage or copied reference code |
| `tslib@2.8.1` | `0BSD` | Lockfile-pinned Fluent UI runtime helper admitted by the Node license policy; distributed only as part of the browser bundle |
| Rolldown `1.2.4` and `@rolldown/binding-*` `1.2.4` | `MIT` | Registry-integrity-pinned native Vite build/test tooling with no install-time lifecycle hooks; selected only for the runner platform and not copied into `filebelt-web` or another release image |
| Lightning CSS `1.33.0` and `lightningcss-*` `1.33.0` | `MPL-2.0` | Exact package-and-version Node policy admission for unmodified native Vite build/test tooling. Preserve upstream license/source evidence; no package or binary is copied into `filebelt-web` or another release image. |
| PostgreSQL 18.6 helper | Upstream PostgreSQL License | External Docker integration process; retain upstream label/notices; never republish as a FileBelt image |
| Apache Iggy 0.8.0 helper and client | Upstream Apache-2.0 evidence | Optional external event process and reviewed generic client; never authoritative and never republished as a FileBelt image |
| OIDC test provider | Exact upstream composition recorded by the Docker plan | External integration fixture only; not a FileBelt release image |
| Rustls/OTLP/Prometheus runtime support | Apache-2.0 and compatible MIT/ISC dependencies recorded in `Cargo.lock` | Shared only through the Apache-2.0 `filebelt-runtime` crate; exact graph, notice, SBOM, vulnerability, and Cargo Vet admission are required before promotion |
| `filebelt-smb-gateway` | `GPL-3.0-or-later` final image | Separate adapter workspace plus exact Samba `4.24.4` source/patch/build context. The scaffold pins the official archive SHA-256 and ships notices/source-offer requirements, but no image may publish until the complete corresponding source and working reviewed bridge are packaged. |
| `filebelt-ftp-ftps-gateway` | `GPL-3.0-or-later` final image | Separate adapter workspace with exact `libunftp 0.23.0` lock and notice evidence. Its Docker recipe is deliberately blocked until digest-pinned build/runtime bases, the complete buildable source context, SBOM, and corresponding-source offer are reviewed. |
| `filebelt-onlyoffice-adapter` | `AGPL-3.0-only` final image plus permissively licensed locked Rust dependencies | Separate first-party adapter workspace and AGPL launcher. Its exact `hmac@0.13.0`, `sha2@0.11.0`, and `zip@8.6.0` graph and notices are included in the SBOM and corresponding-source bundle. Network users receive exact version/revision/license/corresponding-source/build metadata. The release contains no copied DocumentServer program or `api.js`; the operator supplies the separately licensed provider and retains required ONLYOFFICE branding. |
| `filebelt-git-adapter` | `Apache-2.0 AND GPL-2.0-only AND MIT AND Zlib` final image | The FileBelt-authored Apache wrapper links the Apache revision protocol and permissive Rust/runtime dependencies, then invokes the separate static Git `2.55.0` GPL executable. It owns only its dedicated RWX bare-repository PVC; the Apache coordinator never mounts Git state or links to the adapter. |
| ONLYOFFICE Docs Community `9.4.0` | Upstream `AGPL-3.0-only` external process | Operator-supplied, separately deployed provider. FileBelt does not build, copy, republish, or cluster it. Its 20-simultaneous-connection Community limit, branding, complete corresponding source, image digest, database, and operational terms remain the operator's responsibility and are not satisfied by the FileBelt adapter source offer. |
| `filebelt-nfs-gateway` | `LGPL-3.0-or-later` FileBelt adapter plus the exact licenses of Ubuntu, NFS-Ganesha `6.5-8`, Kerberos, `nix@0.31.3`, and runtime packages | Dynamic LGPL FSAL and adapter-local bridge remain outside the Apache workspace. The MIT-licensed Rust `nix` wrapper does not change the Ganesha ABI or dynamic relinking boundary. Publish the dated Ubuntu 26.04 package snapshot, upstream and modified source, patches, build scripts, exact Rust lock and crate sources, notices, replacement/relink instructions, ABI probe, per-platform SBOM, and corresponding-source URL. |
| `filebelt-transcoder` | `GPL-3.0-or-later` final image | First-party GPL wrapper dynamically links a GPL-enabled FFmpeg `8.1.2` build with libaom `3.14.1`, libvpx `1.16.0`, and Opus `1.5.2`. Configure with `--enable-gpl` and without `--enable-version3` or `--enable-nonfree`; publish exact source, patches, flags, notices, build instructions, SBOM, and corresponding-source URL. |

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

The Apache `filebelt-media-controller` and provider-neutral media schema do not
link, invoke through shared memory, or exchange FFmpeg internal types with the
GPL adapter. The NFS FSAL and bridge consume only the generic VFS process
contract; Apache core contains no Ganesha header or implementation type.

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

For the Git wrapper relicense, contributor-history review at commit
`1769aeb841b9fa48fa64cea093d58df54ef8eb91d` found exactly one author identity
under `adapters/git/`: `PiQuark6046 <piquark6046@proton.me>`. The relicense
changes only FileBelt-authored wrapper material. Upstream Git `2.55.0`, its
COPYING text, source archive, notices, and source-offer obligations remain
GPL-2.0-only evidence for a separate executable.
