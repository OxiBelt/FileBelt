<!-- SPDX-License-Identifier: Apache-2.0 -->

# Supply-Chain Policy

Rust and Node lockfiles are committed. Dependencies use reviewed registries and
exact versions; unpinned Git sources and unexpected lifecycle scripts are
blocked. Apache runtime graphs allow reviewed permissive licenses. MPL, CDDL,
LGPL, GPL, AGPL, native linkage, bundled source, and `*-sys` dependencies need
an accepted review before admission.

Rust changes run `cargo audit`, `cargo deny`, and `cargo vet`. Node changes use
frozen pnpm installation with scripts disabled, license admission, audit,
linting, typechecking, tests, and build checks. GitHub Actions are pinned by
commit and run with read-only permissions during pull-request validation.
The Node license admission step compares pnpm's resolved report with
`supply-chain/node-policy.toml` and fails closed on every unknown license.

Phase 1 image builds use digest-pinned Dockerfile frontends and bases and create
local Docker image archives only. Each of the seven roles is checked against an
immutable plan containing its repository, version, source revision and ref,
build kind, license, and platform. The archive must contain the corresponding
static Rust probe or web assets, the expected license evidence, numeric
user/group `10001:10001`, and the complete OCI label contract from ADR-0007.

Native Rust builds install exact binutils, GCC, musl, musl development, and
musl-tools package versions from immutable Debian snapshot
`20260713T000000Z`. RISC-V uses the digest-pinned cross-toolchain recorded in
`supply-chain/tooling.toml`. A live package mirror or an unversioned toolchain
package is not an admitted build input.

Each role/platform archive produces:

- a SHA-256 archive checksum and machine-readable artifact contract;
- a normalized CycloneDX JSON SBOM scoped to that platform;
- a Trivy `0.73.0` JSON vulnerability report and policy decision; and
- extracted image metadata used by static, identity, and smoke checks.

Static Rust SBOMs are augmented from the immutable image plan with the exact
FileBelt Cargo application and per-platform Rust standard-library, musl,
compiler, and linker inventory.
Every entry records its package URL, version, license, relationship, standard
CycloneDX scope, and immutable evidence source. A Rust SBOM must contain both
runtime and build-tool records; an empty or partial inventory fails even when
Trivy reports no package records for the `scratch` filesystem. Runtime records
use `required` scope, while build tools use `excluded` scope and are omitted
from the image subject's dependency edge. Rust images use the aggregate license
expression `Apache-2.0 AND MIT` and ship upstream Rust and musl copyright
manifests. The static web image remains `Apache-2.0` and excludes those
Rust-only notices.

Unexcepted `HIGH` or `CRITICAL` vulnerabilities fail the gate. Exceptions in
`supply-chain/image-vulnerability-exceptions.json` must match the role,
platform, advisory, package, installed version, and target exactly, include a
rationale, and expire within 90 days. Missing or malformed scanner output fails
closed. The normalizer emits a runtime-only CycloneDX derivative that excludes
build-tool records and identifies the exact executable as a Cargo scan target.
Trivy scans that derivative, while the linked musl and Rust standard-library
records remain explicit SBOM components without treating compilers as shipped
packages. A Rust scan with no target or Cargo package inventory fails closed,
while the static web role may truthfully produce an empty package report.
Normalized rebuild verification compares the root filesystem, modes, numeric
ownership, selected image config and labels, embedded identity, and SBOM
content while excluding archive transport bookkeeping.

The read-only pull-request matrix validates all roles on native AMD64 and
ARM64. Default-branch, scheduled, and manual checks also validate RISC-V by
cross-compiling the static probes and running the extracted binaries in a
rootless, digest-pinned QEMU helper container. The release dry run covers all
21 role/platform combinations and an AMD64 normalized rebuild.

No Phase 1 workflow has package, release, or attestation write permission.
Archives and reports are downloadable CI evidence, not published releases.
Signed release tags are verified in a temporary keyring containing only the
[tracked authorized signers](../supply-chain/release-tag-signers/README.md),
and the tag must peel to the checked-out source revision.
When publication is introduced, a separate least-privilege job must consume the
already validated artifacts, attach GitHub artifact attestations, verify the
pushed digest, and avoid rebuilding. Until that later decision is accepted,
rollback consists of disabling the image workflow calls and discarding local or
CI `artifacts/` output. Native smoke tests remove the archive tag they load, and
RISC-V smoke tests remove their temporary helper image, so the matrix leaves no
role or helper tag in the local daemon. There is no registry artifact to revoke.
