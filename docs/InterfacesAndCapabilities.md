<!-- SPDX-License-Identifier: Apache-2.0 -->

# Interfaces and Capabilities

This specification defines FileBelt's replaceable public and internal protocol
boundaries. Interface types carry FileBelt identifiers and stable operations;
they do not expose database rows, host paths, physical payload locators,
Kubernetes objects, event-system internals, browser-library types, or adapter
implementation structures.

## HTTP contracts

The public control-plane contract is the OpenAPI 3.1 JSON REST API under
`/api/v1`. The committed source is
[`protocol/http/v1/openapi.yaml`](../protocol/http/v1/openapi.yaml). It covers
OIDC and local sessions, drives and nodes, trash, immutable versions, upload and
download grants, direct shares, ACL-governed shared views, Markdown
collaboration summaries and first-frame grants, exact Markdown import intents,
per-principal MCP
registrations, capability review, approvals, invocation, version-pinned data
grants, and tenant-administrator MCP templates, service identities, service
grants, and global blocks. General tenant administration, preferences, and
audit/privacy mutation endpoints are not in the current public contract. Group
and anonymous-link share values are reserved but unavailable.

Payload bytes travel over ordinary HTTP streaming under `/io/v1`:

- `PUT /io/v1/uploads/{upload_id}/parts/{part}`;
- `POST /io/v1/uploads/{upload_id}/finalize`; and
- `GET|HEAD /io/v1/downloads/{grant_id}`.

No anonymous `/public/v1` exchange or download endpoint is implemented. The
reserved `/public/share` SPA shell must therefore fail closed and is not a
promise of public-link availability.

Responses use stable `application/problem+json` codes, RFC 3339 UTC timestamps,
integer byte counts, opaque keyset cursors, and generation ETags. Pages default
to 50 items and accept 1 through 200. Mutations carry an expected namespace,
resource, or head generation as applicable.

Allocation and commit operations identified in OpenAPI require an
`Idempotency-Key`. The key is bound to tenant, principal, route, request
fingerprint, response status, and response body for 24 hours. Repeating the same
request returns the stored result; reusing a key for a different request returns
`idempotency.key_reused` without performing the new mutation.

The generated TypeScript contract under `ui/web/source/generated/` is derived
from OpenAPI and consumed by the browser client. UI route guards, hidden
controls, and disabled actions remain usability behavior, never authorization.
The MCP settings UI keeps CSRF material only in memory and stores no credential,
OAuth state, approval digest, invocation result, or registration secret in Web
Storage or IndexedDB.

## Edge trust boundary

OxiBelt terminates public TLS, serves the SPA, and proxies API and byte routes
to isolated backends. FileBelt authorizes from its configured public origin and
validated local session, never from `X-User`, `X-Group`, `Forwarded`, or another
proxy-supplied identity. The edge removes client-supplied identity/internal
headers and sanitizes forwarding metadata.

Safe reads may use the reviewed route retry policy. FileBelt writes are not
retried by the proxy, and authenticated content is never cached. Hashed static
assets may be immutable; SPA entry points, session routes, APIs, byte grants,
content, and reserved public-token exchange routes are `no-store`.

Backend transport is deployment-specific but may not weaken the trust
boundary. Kubernetes uses isolated NetworkPolicy and TLS 1.3 client identities;
local integration may use an isolated private HTTP network. Backend listeners
must never be exposed as public alternatives to OxiBelt. Deployment details
belong in [Runtime and Deployment](RuntimeAndDeployment.md).

## Storage-worker capabilities

After namespace resolution and Virtual ACL authorization, the API may issue an
`fbcap1` capability. The envelope contains exact deterministic Protobuf claim
bytes and an Ed25519 signature over the explicit
`filebelt.storage.capability.v1` domain prefix. The API holds the private key;
the I/O worker receives only overlapping public verification keys and narrow
PostgreSQL privileges. The API has no payload mount.

Claims bind the capability and key generation to an audience, operation,
tenant, principal, session, resource, grant, upload, payload, permitted part or
byte range, ACL/membership/namespace generations, fencing token, nonce, issue
time, and expiry as applicable. The lifetime is at most 60 seconds. Signed
claims contain no maps, unordered fields, user paths, or physical locators.

The operation vocabulary covers upload part, upload finalization, download,
payload deletion, and payload scrub. Collaboration uses the same signed
capability envelope with dedicated scoped operation/resource bindings for CRDT
object finalization and manifest reads; it never gives a browser or the
collaboration role a payload mount. Before touching storage, the worker
validates wire encoding, signature and key generation, audience and operation,
time bounds, identifiers and ranges, fencing, replay state, and the current
generation projection. Upload-part nonces are replay protected. The worker
resolves UUID locators through narrow operation/payload state, cannot mutate
namespace or ACL state, and never accepts a browser session cookie as
authority.

Browser download admission exchanges an API authorization result for a
short-lived, path-scoped `Secure` and `HttpOnly` capability cookie. Non-browser
clients use `Authorization: fbcap1 <base64url-envelope>`. An admitted long
stream rechecks the authoritative generation projection within 60 seconds and
stops on mismatch or database uncertainty.

## Markdown and collaboration contracts

`filebelt-gfm-v1` accepts GitHub-Flavored Markdown with alerts, footnotes,
Mermaid, and KaTeX. Raw HTML is rendered as literal text, not executed or
sanitized HTML. Editable content is at most 2 MiB and viewable content is at
most 8 MiB; invalid UTF-8 or a NUL byte is a fatal content error. The declared
media type in `BeginUpload` is only a caller declaration. `Node.head_media_type`
and `FileVersion.media_type` are trusted only after finalized bytes have been
validated by the service.

`GET .../collaboration` reports only the current durable room summary. `POST
.../collaboration-grants` returns a no-store, opaque, one-use grant valid for
at most 60 seconds; it is sent only in `filebelt.collaboration.v1`'s first
`Authenticate` frame. WebSocket is the sole deployed transport. WebTransport
has no Phase 5 listener, route, or configuration toggle; a future transport
must repeat this contract review before it can carry these frames. Every
participant reauthenticates within 60 seconds. Frame groups are capped at 2
MiB, transferred chunks at 256 KiB, and use only the `yjs-v1` codec.
The collaboration runtime verifies join grants exclusively with the configured
API key generation. Its distinct collaboration capability key may sign only
scoped storage capabilities and is never accepted as a join-grant issuer.
An active room admits each opaque client identifier once; a second connection
cannot replace the existing participant record and must reconnect with a new
identifier.

The collaboration role rejects a live source containing NUL before persisting
or checkpointing it. It sends an acknowledgement only after the scoped I/O
worker has finalized and fsynced the UUID-addressed CRDT object and PostgreSQL
has fenced and committed its manifest. Awareness frames are ephemeral. A
checkpoint is not an immutable file version; an explicit save consumes the
checkpoint through the existing expected-head upload/commit path and creates a
linear immutable version. `DELETE .../collaboration` discards dirty state; a
head change outside the room freezes it for deterministic diff3 review.

`POST .../markdown-import-intents` binds one short-lived import to an exact
source drive/node/version and a new named sibling. A later `BeginUpload` may consume
that `import_intent_id` or a `collaboration_checkpoint_id`, never both. Its
version response includes trusted media type and provenance: origin, optional
source version, creator display name, and whether MCP assisted the operation.
The browser conversion path accepts only CSV, DOCX, ODP, ODS, ODT, PPTX, RTF,
and XLSX at most 8 MiB. It uses the `officeparser/slim` browser module with OCR,
attachment extraction, and remote assets disabled; conversion warnings,
truncation, non-UTF-8 output, and NUL output fail rather than becoming an
implicit save. The resulting Markdown remains a proposed new sibling and uses
the exact import intent and ordinary upload/commit authorization path.

The Markdown preview is a sandboxed opaque-origin iframe at
`/markdown-preview/` with only `allow-scripts`. The parent has no Trusted Types
policy; the child has only `filebelt-markdown-generated`, no network connection,
and an allowlisted AST/message boundary. Mermaid and KaTeX output is sanitized
before the child uses that policy. The child alone permits inline styles for
that sanitized generated output; it does not permit inline script. The parent
accepts only typed link messages
from that frame and never treats preview output as authority. A data-free
wildcard `postMessage` is permitted only for the initial connection handshake
that transfers a dedicated `MessageChannel` port to the opaque child. All AST
and link messages use that port, are bounded and typed, and the child
recursively validates the complete AST before rendering it.

## MCP mediation contracts

The public MCP workflow is intent-first. `POST /api/v1/mcp/invocation-intents`
accepts one exact `McpInvocationRequest` and returns a five-minute
`McpInvocationIntent`. When approval is required, the browser confirms the
displayed registration, capability, application, arguments, attachment
versions, and expiry, then posts only the approval scope and expiry to the
intent-bound approval route. The server derives all keyed argument and
attachment digests from its stored intent. `POST .../{intent_id}/stream` must
receive the same request semantics and returns bounded
`application/x-ndjson`; a mismatch, consumed intent, missing approval, or
disconnect fails closed and cancels execution.

Browser result rendering is data-only. Text is placed in a `<pre>` element;
JSON is a non-editable tree capped at depth 16, 200 entries per object or
array, and 2,000 rendered values across the complete result. Media is decoded
into a revocable Blob URL only after exact size and magic checks and is limited
to 4 MiB and PNG, JPEG, WebP, MP3, Ogg, or WAV.

For Markdown-capable MCP routes, `semantic_input` and `semantic_output` use
the route-specific `filebelt.markdown.semantic.v1` envelope. Each is valid
UTF-8 normalized to LF without NUL and is limited to 2 MiB measured as UTF-8
bytes. Input additionally carries an exact node and immutable base-version
context and is part of the exact invocation-intent digest; output remains a
context-free data-only proposal and never becomes an implicit file save or
version. Invocation persistence retains only the context and domain-separated
normalized-source digests, never raw Markdown.
The broker carries that envelope only in MCP request/result `_meta` under the
`filebelt/semantic` key and rejects a malformed or oversized value on either
side. A collaboration update may record a successful proposal only when the
authority transaction matches tenant, principal, node, base version, and the
staged normalized source-before/source-after digests. A later explicit save
derives the version's `mcp_assisted` provenance solely from those verified
groups; ordinary uploads, saves, and copies carry no MCP provenance field and
clients cannot assert the provenance boolean themselves.
Images are rejected above 4,096 pixels on either axis or 16 million pixels;
audio is metadata-only until user action, never autoplays, and is rejected
above five minutes. HTML, script, SVG, remote media URLs, and unrecognized
content never enter an executable DOM sink.

MCP mutation routes require the normal CSRF, exact Origin, Fetch Metadata,
idempotency, and generation ETag controls shown in OpenAPI. Problems use stable
`mcp.*` codes. Registration export contains configuration only, never a
credential, OAuth token, capability decision, approval, grant, or activity.
Session-scope approval is unavailable for `tool_call` even when the hostile MCP
descriptor claims `readOnlyHint=true`; tool calls always consume a one-shot
approval. Reusable approval remains limited to reviewed low-risk non-tool
operations and one hour.
OAuth start stores PKCE verifier, state, issuer, registration, principal,
session, and return path on the server for at most ten minutes. The callback is
the single allowlisted `/api/v1/mcp/oauth/callback`; it consumes the attempt,
binds tokens to the exact resource/audience, and redirects only to the stored
local settings path. Authorization-code and refresh exchanges send the exact
registration endpoint as the OAuth resource indicator; access state stores the
same resource, and an expired access token can be replaced only by a bounded,
rotated refresh token. Specifically,
`POST /api/v1/mcp/registrations/{registration_id}/oauth/start` accepts
`StartMcpOauth` with a local `/settings/mcp` return path and optional configured
issuer, then returns `McpOauthStart` with the authorization URL and expiry. The
unauthenticated issuer redirect reaches the callback with bounded `code`,
`state`, optional `iss`, or `error` query values and receives only a `303` back
to that stored local path; OAuth tokens never appear in the public response.

The API delegates broker work with an Ed25519-signed `fbmcp1` envelope over
deterministic Protobuf. Claims bind audience and operation, tenant, principal,
session or exact service grant, application, registration, capability and
argument digests, attachment versions/disclosures/generations, policy and
membership generations, nonce, and a maximum 120-second lifetime. The broker
accepts no browser cookie or unsigned authority. Internal invocation frames are
limited to 4 MiB and carry a request ID, ordered sequence, bounded payload, and
terminal state.

Remote Streamable HTTP sessions are opened by the broker through the
operator-managed mTLS egress gateway using an exact target origin and trust
profile. The gateway, not a caller-controlled proxy setting, enforces host,
CIDR, port, public-WebPKI/custom-CA, and dynamic-registration policy. The
supported MCP protocol values are current `2026-07-28` and fallback
`2025-11-25`; negotiation to any other value fails closed. Local
stdio servers are selected only from the offline-Sigstore-verified catalog.
The broker requests a runner through the controller's mTLS, bounded Protobuf
interface; the one-shot runner presents a 32--4096-byte bootstrap token over
the `filebelt.mcp.runner.v1` relay and uses ordered payload frames no larger than
65,536 bytes. These internal routes are not public APIs.

The admitted upstream method set is deliberately small: initialization,
`tools/list`, `resources/list`, `prompts/list`, `tools/call`, `resources/read`,
and `prompts/get`. Each discovery class is capped at 1,000 descriptors, names
are capped at 256 bytes, and every tool must declare `readOnlyHint=true`.
Tool results are capped at 128 content blocks. Sampling, elicitation, roots,
subscriptions, arbitrary notifications, and payload writes are not mediated;
adding one of them requires a new protocol, authorization, threat-model, and
deployment review.

## Key rotation and configuration

`filebeltctl` creates capability signing material and keyed-digest material as
versioned generations. The current capability generation signs new envelopes;
workers retain retiring public keys for at least the 60-second capability
window. Retiring session digest keys remain available for seven days and share
digest keys for 30 days. Removal is an audited, restart-driven operation, and a
generation still required by an unexpired credential cannot be removed.

Runtime configuration is typed and versioned in `filebelt.toml`, with narrow
`FILEBELT_*` overrides and secret-file references. Validation and startup reject
invalid public origins, missing or inconsistent key generations, exposed
listeners, unsafe timing relationships, and inconsistent limits. Configuration
changes take effect through a graceful restart, not untracked hot reload.
The current format is version 4; older versions are rejected. `mcp.enabled`
defaults to false, and `mcp.runners.enabled` is a separate Kubernetes-only
opt-in that requires broker/controller mTLS, a digest-pinned runner image, and
the verified catalog inputs.

## Protobuf and generated contracts

Apache-2.0 Protobuf `proto3` schemas live under `protocol/<domain>/v1/` and use
packages named `filebelt.<domain>.v1`. Buf v2 applies `STANDARD` lint and
file-level breaking-change checks. `PACKAGE_DIRECTORY_MATCH` is the documented
exception because the public source tree omits the repository-wide `filebelt`
package prefix.

Generated clients are committed. Exact generators and runtime dependencies are
pinned; regeneration writes deterministic package-local output and must leave
no unexplained diff. Every generated file records its source schema,
generator/version, regeneration command, and license, and generated files are
never edited by hand. See [the protocol guide](../protocol/README.md) for the
commands and current pins.

Released `v1` OpenAPI and Protobuf contracts are durable. Compatible additions
update schemas, generated output, consumers, and contract tests together;
incompatible changes use a new version. Lint, file-level breaking checks,
deterministic serialization tests, generation drift, license checks, and
consumer tests are required in the same change.

Event envelopes follow the same versioning rules, but an event is only a
notification or invalidation hint. PostgreSQL remains authoritative, and no
consumer may apply an event payload as the sole record of committed state.
