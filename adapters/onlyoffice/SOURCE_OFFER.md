<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Corresponding-source requirements

Any network deployment of `filebelt-onlyoffice-adapter` must make the complete
corresponding source available from the public `/onlyoffice/source` endpoint
or a clearly linked durable source location. For each released image, publish
the exact complete FileBelt revision/tag, including this adapter directory, the
linked Apache-2.0 document-protocol crate and generated protobuf source,
AGPL-3.0 text, adapter-local Cargo and pnpm lockfiles, Dockerfile, build inputs,
notices, SBOM, platform digests, rebuild instructions, and source URL in the
OCI label.

ONLYOFFICE Document Server is operator-supplied and is not redistributed by
this adapter. Operators must independently meet that provider's source,
license, trademark, branding, connector, and image obligations for the exact
`9.4.0` deployment they choose. No provider source or asset may be copied into
this adapter without a separate licensing and corresponding-source review.
