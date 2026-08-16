<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt Git revision adapter

The FileBelt Git adapter is an Apache-2.0 wrapper distributed with and invoking
a separate GPL-2.0-only Git executable. The wrapper links only the Apache-2.0
`filebelt-revision-protocol` private protobuf framing contract and reviewed
Rust dependencies; it never links Git or another Git implementation. Apache
core has no dependency on this workspace.

The adapter requires exactly Git `2.55.0`. It manages one SHA-256 bare
repository per opaque FileBelt node UUID, permits only `refs/heads/filebelt`,
and writes unsigned commits containing exactly one mode-`100644` `content`
tree entry. Core supplies the immutable version UUID, UTC timestamp, and
ordinal; the adapter uses fixed `FileBelt <noreply@filebelt.invalid>` identity
and the deterministic message `FileBelt revision <version-id> ordinal <n>`.

No Git wire protocol, remote, user ref/path/message, hooks, filters,
textconv, external diff, prompt, alternates, or replace refs is admitted. The
private `8092` listener requires TLS 1.3 mTLS and exactly
`spiffe://filebelt/revision-coordinator/git`; it accepts one bounded protobuf
frame and closes. The unauthenticated `9090` listener serves only low-
information kubelet health routes and is never a Service port.

The `serve` process accepts `--max-concurrent-private-requests` (default `8`,
range `1..=64`) and `--max-concurrent-git-processes` (default `2`, range
`1..=16`). The Git-process limit must not exceed the private-request limit.
These operator limits are command-line deployment inputs so the strict,
operator-owned TOML contract remains unchanged. A private socket beyond the
request-task limit is closed before TLS work is spawned. Every system-Git
process independently holds one process permit; comparisons reject immediately
with typed admission exhaustion and a five-second retry hint, while other
authenticated operations wait within their existing bounded request lifetime.
Permits are released on success, failure, timeout, and cancellation.

The source-first Dockerfile accepts only a staged, verified build context. It
cannot download source and refuses to build until the adapter qualification
plan marks both source/license evidence and image construction eligible. A
qualified build produces a static scratch aggregate containing the Apache
wrapper and separate GPL Git executable; publication remains blocked until the
independent platform, SBOM, vulnerability, restore, and fsck gates pass.
For `linux/amd64`, the closed adapter plan passes only
`FILEBELT_AMD64_ISA=x86-64-v3`; the Dockerfile applies it to the Rust wrapper,
zlib, and Git C executable. ARM64 receives no AMD64 ISA argument. Every
platform labels the plan-derived target as `io.filebelt.build.target-cpu`.

The operator supplies the Git-only RWX claim and every mTLS Secret. There is no
database credential, payload mount, browser route, general egress, or Git
transport in this adapter.

```sh
cargo fmt --check --manifest-path adapters/git/Cargo.toml
cargo test --manifest-path adapters/git/Cargo.toml --locked
tests/scripts/check-git-helm-chart.sh
```
