<!-- SPDX-License-Identifier: GPL-2.0-only -->

# FileBelt Git revision adapter

This is the separate GPL-2.0-only system-Git adapter for FileBelt revision
storage. It consumes only the Apache-2.0 `filebelt-revision-protocol` private
protobuf framing contract. Apache core has no dependency on this workspace.

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

The source-first Dockerfile and Helm chart are non-publishable sentinels. The
operator supplies the Git-only RWX claim and every mTLS Secret. There is no
database credential, payload mount, browser route, general egress, or Git
transport in this adapter.

```sh
cargo fmt --check --manifest-path adapters/git/Cargo.toml
cargo test --manifest-path adapters/git/Cargo.toml --locked
```
