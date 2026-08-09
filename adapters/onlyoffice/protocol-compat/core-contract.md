<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Core transport and adapter-state interface

This adapter owns no SQL migration, database driver, or general database
credential. It calls the Apache `filebelt.document.v1` protobuf envelope only
over its existing mTLS identity; Apache packages have no dependency on this
adapter. The generic Core-side protocol must provide the following durable
interface atomically:

The adapter configuration keeps `public_origin`, `launch_origin`, and
`document_server_origin` as pairwise-distinct bare HTTPS hosts. Core-issued
document input and callback URLs use `public_origin`; the browser submits the
one-use handoff only to `launch_origin`. The launch host never serves input,
callbacks, or source/about metadata.

| Operation | Input | Required durable behavior |
| --- | --- | --- |
| `redeem_one_use_launch` | opaque launch ID | Bind a launch to its exact tenant, participant, document version, and authorization generations; consume the digest once. Core admits at most 20 active/reconnecting participant-tabs under its provider lock and permits only one consumed launch lifetime per participant. |
| `issue_fresh_read_capability` and `fetch_input_with_capability` | document and participant IDs, then an exact byte range and opaque capability | Reauthorize Virtual ACL/session/generation state, issue a fresh capability scoped to the immutable whole source, and allow only a range contained by that scope. The capability is never returned to the provider. |
| `record_callback` | verified callback fields and a canonical 32-byte fingerprint | Insert the fingerprint once under a unique durable constraint. Return `Duplicate` only after terminal handling; return `Pending` if a previous output fetch did not commit. |
| `commit_callback_output` | callback fingerprint and bounded egress result | Allocate or recover the exact revision, use fresh scoped write/finalize capabilities, and perform the ordinary immutable version commit only once after output validation and expected-head/generation checks. Timer checkpoints stop after durable finalization and do not advance the file head. |

`record_callback` must support an output-pending state so an egress failure is
retryable without treating the callback as a duplicate success. The adapter
calls `commit_callback_output` only after a bounded no-redirect gateway fetch.
That table and
its migration belong to Core's authoritative PostgreSQL schema, not this AGPL
adapter. The adapter's Rust `CoreClient` trait intentionally exposes only
opaque IDs and values, never SQL types or a database connection string.

`RedeemDocumentLaunch` and `RefreshDocumentSource` return exact 60-second
source-read capabilities. `ReceiveDocumentCallback` persists the canonical
digest before egress, `BeginDocumentRevision` returns one whole-payload write
and finalize capabilities, and `CommitDocumentRevision` is idempotent for
ordinary saves. Terminal checkpoint receipts acknowledge timer retries without
another fetch. The adapter retains no callback or version authority and never
creates an adapter-local shadow of FileBelt's authoritative history.
