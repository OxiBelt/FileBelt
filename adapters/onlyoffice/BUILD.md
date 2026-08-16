<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Rebuilding the FileBelt ONLYOFFICE adapter

The release source bundle is the build context. It contains the exact tracked
FileBelt revision plus qualified inputs under `adapter-inputs/onlyoffice/`:

- `.cargo/config.toml` and `vendor/cargo/` provide the complete locked,
  versioned Rust source closure;
- `SOURCE-MANIFEST.json` identifies linked, build-only, and image components;
- `LICENSES/` and `NOTICES/` contain the reviewed release evidence; and
- this file records the build contract without embedding provider software.

Build the adapter with the digest-pinned builder declared by the release plan,
the source bundle as the ordinary Docker context, and the tracked Dockerfile:

```sh
docker build --network=none \
  --file adapters/onlyoffice/Dockerfile \
  --platform linux/amd64 \
  --build-arg FILEBELT_ONLYOFFICE_BUILDER_IMAGE=<reviewed-builder-digest> \
  --build-arg FILEBELT_AMD64_ISA=x86-64-v3 \
  --build-arg SOURCE_URL=<https-source-repository> \
  --build-arg SOURCE_REF=refs/tags/<version> \
  --build-arg SOURCE_REVISION=<40-lowercase-hex-commit> \
  --build-arg CORRESPONDING_SOURCE_URL=<immutable-bundle-url> \
  --build-arg CORRESPONDING_SOURCE_SHA256=<lowercase-sha256> \
  --build-arg CHART_VERSION=<version> \
  --build-arg CREATED=<rfc3339-release-time> \
  --build-arg LICENSE_EXPRESSION=AGPL-3.0-only \
  <source-bundle-root>
```

The Docker build also disables networking for the Cargo step and uses
`--locked --offline`. A qualified build fails when the release metadata,
vendor closure, source manifest, license texts, or generated notices are
missing. It does not download or include ONLYOFFICE Docs, `api.js`, a provider
connector, provider fonts, branding, image, database, assets, or source.
For AMD64, `FILEBELT_AMD64_ISA` is a closed argument derived from adapter-plan
schema v3 and must be exactly `x86-64-v3`; it applies to the Rust executable
and its native Cargo dependencies. ARM64 builds omit this argument. The plan
also supplies `FILEBELT_TARGET_CPU`, recorded as `io.filebelt.build.target-cpu`.

For direct Rust verification from an unpacked source bundle, copy the staged
Cargo configuration and vendor tree to the locations used by the Dockerfile,
then run:

```sh
FILEBELT_SOURCE_URL=<https-source-repository> \
FILEBELT_SOURCE_REF=refs/tags/<version> \
FILEBELT_SOURCE_REVISION=<40-lowercase-hex-commit> \
FILEBELT_CORRESPONDING_SOURCE_URL=<immutable-bundle-url> \
FILEBELT_CORRESPONDING_SOURCE_SHA256=<lowercase-sha256> \
FILEBELT_CHART_VERSION=<version> \
cargo build --locked --offline --release \
  --features qualified-release \
  --manifest-path adapters/onlyoffice/Cargo.toml
```
