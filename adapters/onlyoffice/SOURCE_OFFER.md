<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Corresponding-source requirements

Any network deployment of `filebelt-onlyoffice-adapter` must make the complete
corresponding source available from the public `/onlyoffice/source` endpoint
and the persistent `Source & License` link. For each released image, the link
and endpoint must identify the exact immutable source bundle and SHA-256 for
the running binary. That bundle contains the exact FileBelt revision/tag,
including this adapter directory, its complete versioned Cargo vendor closure,
the directly linked Apache-2.0 document-protocol crate and generated protobuf
source, AGPL and Apache license texts, adapter-local Cargo and pnpm lockfiles,
Dockerfile, build inputs, notices, source manifest, and rebuild instructions.
The OCI labels and external release evidence map the same bundle to exact
platform and image-index digests.

For `linux/amd64`, the complete build inputs include the closed
`FILEBELT_AMD64_ISA=x86-64-v3` and `FILEBELT_TARGET_CPU=x86-64-v3` arguments,
Rust `-Ctarget-cpu=x86-64-v3`, C/C++ `-march=x86-64-v3`, and the GNU linker
`-z x86-64-v3` property requirement. Other architectures retain their
architecture-default compiler settings.

An unmodified upstream deployment may use the matching upstream immutable
source bundle. A downstream operator who modifies this AGPL adapter and exposes
that modified version over a network must point the visible source opportunity
to the corresponding source for the running modified version. It must not keep
an upstream source URL or checksum that no longer matches the binary.
Redistribution of an adapter image must preserve equivalent source access,
notices, and license texts. These obligations do not require publication of
unrelated private deployment configuration, secrets, database contents, user
data, or provider credentials.

ONLYOFFICE Document Server is operator-supplied and is not redistributed by
this adapter. Operators must independently meet that provider's source,
license, trademark, branding, connector, and image obligations for the exact
`9.4.0` deployment they choose. No provider source or asset may be copied into
this adapter without a separate licensing and corresponding-source review.
