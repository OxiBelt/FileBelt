<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# FileBelt transcoder

This independent GPL-3.0-or-later workspace wraps the approved GPL-enabled
FFmpeg composition. It is excluded from the root Apache workspace. The Apache
media controller sends a provider-neutral, job-scoped plan over the reviewed
process boundary; this wrapper never imports Apache controller implementation
code, accesses PostgreSQL, resolves payload/cache paths, or accepts browser
credentials.

The wrapper accepts only local paths rooted at `/work/input` and `/work/output`,
the `av1-opus` or `vp9-opus` profiles, and a duration at most four hours. It
invokes FFmpeg with an argument vector, a `file,pipe` protocol whitelist, and
no shell. Admission, source/output capability issuance, receipt verification,
cache publication, authorization rechecks, network isolation, and resource
limits belong to the controller/I/O/Job layers.

Run the adapter-local policy tests without network access:

```sh
cargo fmt --check --manifest-path Cargo.toml
cargo test --manifest-path Cargo.toml --locked --offline
```

`Dockerfile` is not a release recipe until the independent image plan supplies
immutable builder/runtime inputs and the complete source/SBOM/provenance
evidence described in [SOURCE_OFFER.md](SOURCE_OFFER.md).
