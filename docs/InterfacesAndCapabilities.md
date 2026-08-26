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
grants, global blocks, and per-principal mount policies, credentials, devices,
and sessions. General tenant administration, preferences, and
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

`GET|PUT /api/v1/drives/{drive_id}/nodes/{node_id}/acl` is resource-scoped by
`MANAGE_ACL` before node or subject disclosure. GET returns the exact 26-action
stable vocabulary and direct rows with user email or group ID, source, and
read-only provenance. PUT accepts at most one row per action, supports the
exact `self`, `children`, `descendants`, and legacy `self_and_descendants`
scopes, and replaces only mutable `core` rows for one subject. Its `If-Match`
and authorization generations are rechecked under the PostgreSQL resource lock;
stale state is `409`, while unauthorized and missing resources remain the same
`404`.

While a tenant's descendant-share admission gate is blocked,
`POST /api/v1/drives/{drive_id}/nodes/{node_id}/shares` returns `503` Problem
code `share.remediation_in_progress`, and
`POST /api/v1/drives/{drive_id}/nodes/{node_id}/mcp-grants` returns `503`
Problem code `mcp.data_grant.remediation_in_progress`. Both responses carry
`Retry-After: 60`. This is an admission result, not an idempotency replay or
an authorization disclosure; clients must not retry earlier. The OpenAPI source
defines these explicit responses and the generated TypeScript contract remains
derived from it.

Resource mutations identified in OpenAPI require an `Idempotency-Key`. Content
policy changes, collaboration grant/intent/discard operations, upload
allocation and commit, version restore, and direct-share creation reserve the
key, perform the authoritative write, and finalize the exact response in one
PostgreSQL transaction. The key is bound to tenant, principal, route, concrete
drive/node/upload/parent/version identifiers, request fingerprint, response
status, and response body for 24 hours. Repeating the same request returns the
stored result; reusing a key for a different request returns
`idempotency.key_reused` without performing the new mutation. During the
24-hour fingerprint cutover, pre-cutover upload allocation/commit receipts may
replay by their exact legacy request-only digest, but every new reservation
stores the identifier-complete digest.

Document create-session, conflict-copy, own-session revoke, and manager
force-close requests cross a separate coordinator process. For those commands,
the API derives an opaque operation digest from the authenticated browser
session, route, and public idempotency key, and the coordinator binds that
digest plus the request fingerprint to a successful result in the same
PostgreSQL transaction as its authoritative mutation. A retry after an
uncertain coordinator response therefore replays the committed result and lets
the API finalize the public HTTP receipt. The one-use launch handoff remains a
separate non-idempotent operation and is not covered by these receipts.

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

## Mount protocol and `fbcap2` contracts

The Apache core exposes a deterministic Protobuf boundary at
`protocol/vfs/v1/filebelt_vfs.proto`. Copyleft SMB and explicit-FTPS adapters
connect to that VFS process over TLS 1.3 mutual authentication. A gateway first
sends `Hello` with its fixed protocol identity and zero local epoch; the VFS
returns the authoritative PostgreSQL gateway epoch. Subsequent authentication
and filesystem requests bind tenant, gateway, epoch, request ID, and the opaque
session issued by the VFS. Responses echo the request ID and use stable,
existence-hiding errors. Adapter structs, Samba ABI types, FTP-server types,
host paths, and payload locators never cross this boundary.

The current operation surface is `Authenticate`, `List`, `Stat`, `Open`,
`Read`, `Close`, shared `Lock`, and `Unlock`. It is intentionally read-only:
create, write, truncate, rename, delete, exclusive locks, and write-enabled
policies or credentials are rejected as unsupported. FTPS passes the ephemeral
raw `PASS` exchange only inside the mTLS request so the core can verify its
peppered HMAC. FileBelt-owned adapter serialization buffers and VFS request
buffers are zeroized after use; the FTP framework retains its command-owned
string only for the bounded authentication-call lifetime. The SMB wire reserves
a channel-binding field, but the adapter remains fail-closed until a reviewed
Samba authentication/session IPC bridge can populate it.

For a content read, the VFS revalidates the open handle and signs a distinct
`fbcap2` envelope with the current purpose-local `mount-storage` generation. The deterministic
`filebelt.mount.capability.v2` claims bind the I/O audience, read operation,
tenant, principal, mount session, credential, drive, node, immutable version,
byte range, gateway epoch, all relevant authorization generations, nonce,
fence, and a maximum 15-second lifetime. The I/O worker atomically consumes
each nonce, accepts `fbcap2` only on `GET /io/v1/mount-reads/{handle_id}`,
revalidates the handle and immutable version in PostgreSQL, and streams the
exact range. The VFS, Headscale sync, API, and adapters never receive the
payload mount.

The public OpenAPI surface is `GET /api/v1/mounts`, `PUT
/api/v1/mounts/policies/{protocol}`, `POST
/api/v1/mounts/credential-operations`, `POST /api/v1/mounts/credentials`,
`DELETE /api/v1/mounts/credential-operations/{operation_id}`, and `DELETE
/api/v1/mounts/credentials/{credential_id}`. Policy and credential mutations
use the ordinary CSRF/origin/fetch-site rules; operation prepare/cancel and
credential create/revoke additionally require recent OIDC authentication, and
credential lifetimes are capped at seven days. A plaintext credential appears
only in the create response and is absent from every later list, activity, log,
audit, and error contract.

PostgreSQL prepares one current creation slot per tenant/principal and returns
its server-generated UUID, positive monotonic generation, and database-clock
expiry two minutes later. A repeated prepare returns `200` with the same
unexpired prepared tuple; a new or rotated tuple returns `201`. Credential
creation must carry that exact tuple and never retries to recover plaintext.
Only a transport-unknown create is resolved through the dedicated operation
DELETE with the expected generation; a definite create rejection never
cancels a tuple that another client may share. Create and recovery cancel serialize on the slot row;
cancel re-reads the credential only after obtaining that lock, so it either
blocks the create or revokes the credential that committed first. A stale,
expired, mismatched, cross-principal, or unknown tuple without an exact
credential committed by that tuple returns an existence-hiding not-found
result without mutation. Exact committed credentials remain recoverable after
the principal's current slot rotates. A transport-unknown cancel
keeps new credential creation blocked and exposes the prepared tuple plus a
retry control. Ordinary credential DELETE only revokes an existing owned
credential; a missing UUID creates no durable state.

## Text revision, editing, and collaboration contracts

Every validated text file uses the provider-neutral `filebelt.revision.v1`
process contract and a SHA-256 bare Git repository owned by the separately
licensed Git adapter. Classification is byte-based: the complete object must
be valid UTF-8, contain no NUL byte, be no larger than 100 MiB, and have a
text-capable registered media type or filename. `content_class_policy=binary`
is the persistent, `SET_ATTRIBUTES`-authorized escape hatch; a declaration or
filename alone never turns invalid bytes into text. Git exposes no wire
protocol, worktree, user ref, author, or browser credential. Each immutable
version maps to one unsigned commit with a single mode-`100644` `content` entry,
a fixed FileBelt identity and message, and a full 64-lowercase-hex commit ID.

Authenticated users persist edit limits of 1/2/4/8/16 MiB (default 2 MiB) and
inline view limits of 8/16/32/64/100 MiB (default 8 MiB), with the inline limit
never below the edit limit. The preference and content-class mutations require
`If-Match`; the latter also freezes an incompatible live editor. Version pages
are lazy and cursor-bound. Comparing any two Git-backed versions requires
current `READ_CONTENT`, rechecks the authorization generation fence at the
coordinator, and returns a typed Git histogram line diff with three context
lines. A comparison fails atomically after 5 seconds, 50,000 lines, or 8 MiB;
partial output is never returned.

### Directory Git repository contracts

Directory Git has only compatibility-disabled OpenAPI endpoints in
the current release; the revision Protobuf, Git adapter, HTTPS, SSH, and mount
listeners remain unavailable. A later, explicitly enabled surface adds an
opaque directory-repository resource keyed by its `directory_git` root node
ID; no wire contract exposes a host path, bare-repository path, Git
implementation type, PostgreSQL row, payload locator, or adapter credential.

The public repository API will allocate/revoke HTTPS device tokens, register
tailnet SSH keys, list repository state, and manage branches, tags, pull
requests, rules, signatures, LFS, and retention. It applies the additive
`READ_REPOSITORY`, `WRITE_REPOSITORY`, `MANAGE_REPOSITORY`, and
`BYPASS_REPOSITORY_RULES` actions. Mutations use CSRF, idempotency, expected
repository/root generations, and current Virtual ACL authorization. Bypass is
one-operation scoped, reasoned, audited, recent-OIDC authenticated, and allowed
only by the matching ruleset. Git HTTPS and tailnet SSH use independently
scoped, revocable credentials and are not browser-session substitutes.

An accepted receive-pack may contain at most 1 GiB of incoming pack data, 32
newly admitted first-parent commits, 10,000 changed paths per commit, and
100,000 entries per tree. Ordinary Git blobs are limited to 100 MiB. An LFS
object may use the configured FileBelt max-file limit (default 1 TiB), but only
after its bytes, digest, quota reservation, and PostgreSQL record are durable.
The complete push is rejected before a partial FileBelt `main` projection is
visible.

Only `main` is FileBelt-projected. A validated accepted tree creates derived
immutable per-file versions in one PostgreSQL transaction and rechecks ordinary
per-path actions; other refs and Git metadata are Git-only. Git-side state
never grants FileBelt authority or overrides namespace, ACL, retention, quota,
current-head, or recovery state.

Mount writes remain outside this contract. NFS, SMBv3, and FTPS writes stay
disabled until independently reviewed protocol, replay, adapter, and
qualification gates complete. When later enabled, their exact save boundaries
are NFS successful `COMMIT` or final dirty `CLOSE`, SMB reviewed close/flush
without durable handles, and completed non-resumable FTPS upload. No remote
mutation makes a Git commit visible before expected-head, namespace, ACL, quota,
and durable-receipt transaction success.

After authentication, a comparison must acquire both the coordinator-wide and
authenticated-`user_id` admission permits before any database or adapter work.
The defaults are two comparisons globally and one per user; neither scope
queues. Saturation returns HTTP `429` with problem code
`revision.admission_limited` and `Retry-After: 5`. The private revision protocol
reports `ADMISSION_LIMITED` with a 5,000-millisecond retry hint. This overload
result is distinct from the existing HTTP `413` and private
`RESOURCE_EXHAUSTED` result for input or output size bounds. Cancellation,
timeout, success, and every error release both permits.

`filebelt-gfm-v1` accepts GitHub-Flavored Markdown with alerts, footnotes,
Mermaid, and KaTeX. Raw HTML is rendered as literal text, not executed or
sanitized HTML. Markdown uses the same configured text limits; invalid UTF-8
or a NUL byte is a fatal content error. The declared
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
Snapshot restore and each live group are decoded, applied, and fully
re-encoded only on an isolated document before acceptance. A decoded
zero-length garbage-collection block is structurally rejected. Any Rust unwind
panic raised by Yrs while processing the isolated document is contained and
reported through the existing invalid-snapshot or invalid-update result. This
narrows acceptance only for malformed states: canonical and sparse Yjs updates,
including a valid explicit zero state-vector clock, remain compatible. No new
public error, frame, codec, or byte limit is introduced.
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
and XLSX at most the user's inline limit. It uses the `officeparser/slim` browser module with OCR,
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

## Provider-neutral document contracts

The Apache control plane exposes provider-neutral document sessions in the
committed OpenAPI contract. An authenticated user may create a session for one
exact current DOCX, XLSX, or PPTX version, list and revoke their own sessions,
and inspect conflict state. A fixed drive owner or `MANAGE_ACL` principal may
list or force-close all sessions for a node. Creation and own-session detail
return session metadata and the exact non-secret operator-configured external
provider HTTPS origin for pre-launch consent; they return no launch value. A
separate non-idempotent handoff request, issued only after that consent,
returns one no-store, one-use launch value that the SPA submits by a top-level
form POST to the exact operator-configured editor action. That action is HTTPS,
has the exact path `/onlyoffice/launch`, and uses a hostname distinct from both
the FileBelt public hostname and the provider hostname; a different port on the
same hostname is not isolation because cookies are not port-scoped. Neither the
launch value nor a FileBelt browser credential appears in a URL, idempotency
record, browser store, or provider JavaScript state. The editor hostname has no
FileBelt API route or API CORS authority.

The generic `filebelt.document.v1` Protobuf contract is the replaceable process
boundary between API, the Apache document coordinator, and provider adapters.
It carries FileBelt UUIDs, stable modes/states/errors, exact generations,
opaque one-use launch values, revision digests, and typed commit outcomes. It
does not carry ONLYOFFICE status numbers, editor configuration objects,
callback URLs, browser-library types, PostgreSQL rows, or payload locators.
The coordinator accepts this contract on two private TLS 1.3 mutual-TLS
listeners. Port 8089 admits only API create/query/revoke/close/copy/handoff
commands; port 8090 admits only adapter launch redemption, source refresh,
callback receipt, revision allocation, and commit commands. Independent
certificate and client-identity allowlists prevent either peer from invoking
the other peer's commands.

The revoke and force-close commands require exact 32-byte API-derived operation
digests and request fingerprints. The coordinator accepts a replay only when
both values and the command kind match the stored transaction-bound receipt;
key reuse for a different close target or effect fails without another state
transition, audit row, or fencing-token advance.

Document byte access extends `fbcap1` with three operations whose signing key
generation is 4: exact immutable document-version read, one whole-payload
revision write, and revision finalization. Claims bind tenant, initiating
principal and API session, document session/participant, node, immutable base
version or allocated revision and payload, all authorization generations,
session fence, byte range/maximum size, nonce, and a lifetime no longer than 60
seconds. The document coordinator has no payload mount; the I/O worker resolves
UUID locators only after capability admission and rechecks authorization at
most every 60 seconds. A provider and its adapter never receive a general
upload/download capability or database credential.

The first provider mapping is isolated under `adapters/onlyoffice/` and pins
ONLYOFFICE Docs Community `9.4.0`. It accepts only the documented callback
statuses `1`, `2`, `3`, `4`, `6`, and `7`; force-save types map `0` to command,
`1` to explicit user save, `2` to timer checkpoint, and `3` to form submission.
Provider callbacks require an exact route/session binding and HS256 JWT with a
separate current provider-outbox verification secret; browser configuration is
signed with an independent secret. A retiring outbox secret may overlap for at
most 30 minutes. Status `1` carries one authenticated connect or disconnect
activity. Disconnect and close-without-changes callbacks leave a bounded
100-second reconnect window, after which maintenance closes the participant
and an otherwise-empty session. Only statuses `2` and `6` fetch provider
output. The adapter sends a canonical digest of document key, status, activity,
force-save type, provider event identity, revision, and validated output
identity to the durable Core callback-receipt command before initiating any
output fetch. Duplicate receipt returns the same revision. After the exact
length is known, allocation retry returns the same payload; write, finalize,
and commit use that revision's scoped capabilities and durable outcome, so
duplicate, reordered, restart, and response-loss delivery cannot create a
second version.

An output URL is hostile input even after a valid provider JWT. It must use
HTTPS at the single configured DocumentServer origin, contain no userinfo or
fragment, survive strict DNS/IP policy, and be fetched only through the
operator's mTLS egress gateway with redirects disabled, bounded headers and
timeouts, and a 100 MiB streaming ceiling. DOCX, XLSX, and PPTX are the only
admitted input/output media types. Timer force-saves are retained as one
superseding 24-hour checkpoint; user/form/final saves enter durable
reconciliation and expected-head commit. A conflict is terminal and
user-visible, with produced bytes retained for seven days; it is never an
implicit overwrite.

The Apache web shell owns only provider-neutral consent, session activity,
conflict, and source-link surfaces. It navigates by form POST to a separate
FileBelt-controlled editor hostname where OxiBelt exposes only the AGPL launch
POST and launcher asset GET routes. The adapter rejects a missing or non-exact
public-origin `Origin` on launch and rejects every route on the wrong host.
ONLYOFFICE `api.js` is loaded at runtime from the configured DocumentServer and
is not copied into the Apache bundle. The launcher response sets no cookie or
CORS header, is `no-store` and `no-referrer`, denies framing, and uses a CSP
with only the required provider sources plus exactly `sandbox allow-scripts
allow-same-origin allow-forms allow-downloads allow-popups`. The launch page
uses no Web Storage, validates any cross-origin messages against the exact
provider origin and schema, and has no FileBelt public-origin browser
credential with which to call generic APIs.
`GET /onlyoffice/source` and `/onlyoffice/about` remain accessible to network
users and report the adapter version, revision, license, immutable
corresponding-source bundle URL and SHA-256, build instructions, provider
version, and notices. The launch shell always renders a visible `Source &
License` link derived from the configured public origin, outside
provider-controlled content.

## MCP mediation contracts

Format 9 adds named `[mcp.gateways.<name>]` entries. A trust profile may select
one by its `gateway` field; profiles without a selector retain the existing
`mcp.egress` default. `kind = "private_tunnel"` is Kubernetes-only and routes
through the dedicated private-egress protocol gateway. It forbids dynamic
client registration and OAuth discovery, authorization, token, and refresh
flows. Registrations on that profile may use only no authentication, a bearer
secret, or an API key. An unknown gateway name, incomplete absolute mTLS paths,
or an enabled private gateway outside Kubernetes invalidates configuration.

The private gateway is not Streamable HTTP forwarding authority in general.
For MCP it accepts only the exact configured canonical target and trust-profile
control values at `/`; for ONLYOFFICE it accepts only the existing bounded
`/v1/fetch` contract under one canonical origin and path prefix. It follows no
redirect, performs no DNS resolution, and cannot request a target from the
tunnel relay. Inner target TLS remains end to end across the opaque relay.

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
PostgreSQL-local MCP mutations bind the key to the authenticated principal,
normalized route, concrete route identifiers, exact request body, and
`If-Match` value where present. Registration creation and lifecycle changes,
capability review, approval revocation, invocation-intent creation and
cancellation, data-grant revocation, and tenant-administrator template,
assignment, service-identity, service-grant-revocation, and block-rule writes
commit their authoritative state and exact response receipt in one transaction.
Matching concurrent requests return one stored result; a mismatched fingerprint
returns `idempotency.key_reused`; a failed or abandoned transaction exposes no
pending receipt.

Broker-mediated registration configuration/deletion, static credential
replacement/deletion, OAuth start, connection test, and capability discovery
use the existing Protobuf `request_id` as a stable, API-keyed operation UUID.
The signed `capability_id` must equal that UUID and the signed nonce carries the
exact keyed public request fingerprint, including registration ID, request
body, and `If-Match`. The broker rejects any scope/fingerprint reuse, returns a
completed journal result before consuming rate or concurrency capacity, and
rechecks the expected revision only for a newly admitted operation. Its
transaction commits broker-local writes with the safe replay result. The API
then commits any local continuation, the broker-completion marker, and the
exact public receipt together; delete resumes from the journaled post-erasure
revision, while test/discovery reuse the journaled probe result.
Session-scope approval is unavailable for `tool_call` even when the hostile MCP
descriptor claims `readOnlyHint=true`; tool calls always consume a one-shot
approval. Reusable approval remains limited to reviewed low-risk non-tool
operations and one hour.
OAuth start stores the PKCE verifier only in its encrypted attempt envelope and
stores a keyed state digest, issuer, registration, principal, session, and
return path on the server for at most ten minutes. Raw state, challenge, and
authorization URL are reconstructed in memory and never journaled. The callback is
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
terminal state. For the seven idempotent broker operations, request-ID equality
is accepted only with the exact signed tenant, principal, registration,
operation, and keyed request fingerprint stored by the broker. Other operations
retain ordinary random request IDs and receive no implied replay semantics.

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

## Phase 8 media contracts

`protocol/media/v1/media.proto` is the Apache, provider-neutral boundary
between the controller and a replaceable transcoder. It contains immutable
source/version identity, a bounded profile, source and output capability
references, attempt/fencing identity, verified segment receipts, manifest
revision, and terminal result. It contains no FFmpeg option, library structure,
Kubernetes type, payload path, or adapter-internal error.

The public HTTP contract adds:

- `POST /api/v1/drives/{drive_id}/nodes/{node_id}/media-previews` with an
  immutable source version, validated browser capabilities, explicit
  confirmation, and `Idempotency-Key`; it returns `202` for the durable request;
- `GET` and `DELETE` on that resource's
  `/media-previews/{preview_id}` child for status and fenced cancellation.

Playback-grant, segment-delivery, and drive-manager eviction routes remain
reserved until the probe-only controller and scoped I/O cache path are
qualified. The checked-in preview component is isolated prequalification code
and is not wired into the application shell.

Playback manifests are versioned FileBelt JSON. They name one selected codec
ladder, immutable initialization/media segment identifiers, BLAKE3 digests,
byte lengths, time ranges, and a monotonic revision. Segment URLs contain no
bearer token. A manifest cannot reference a segment until the I/O service has
durably verified its receipt.

## Phase 8 NFS and WebTransport contracts

The mount protocol enum adds `NFS`; password-credential endpoints reject it.
Tenant-administrator feature, export, POSIX-group, proposal, active-mapping,
and quarantine endpoints live below `/api/v1/admin/mounts/nfs/`. They require
recent OIDC authentication, generation preconditions, idempotency keys, exact
tenant confirmation for every mutation client, tenant uniqueness, and audit.
The NFS overview returns the exact configured tenant slug; browsers require the
administrator to type that value without trimming, normalization, or case
folding and clear it after one mutation. The API validates the confirmation
before idempotency replay and binds it into every new request fingerprint. For
the bounded 24-hour rollout window, an existing receipt may replay only when
the supplied confirmation is exact and the receipt fingerprint equals that
route's exact pre-confirmation request projection; the legacy fingerprint is
never written for a new request.

The NFS binding workflow has these public routes:

- `GET|POST /api/v1/admin/mounts/nfs/mapping-proposals` lists and creates exact
  immutable proposals;
- `DELETE /api/v1/admin/mounts/nfs/mapping-proposals/{proposal_id}` cancels one
  pending proposal;
- `GET /api/v1/admin/mounts/nfs/quarantined-mappings` lists legacy mappings
  that require a fresh proposal;
- `GET /api/v1/admin/mounts/nfs/mappings` lists approved active mappings, and
  `PUT /api/v1/admin/mounts/nfs/mappings/{credential_id}/scope` may only remove
  drives from an alias ceiling; the existing administrator `DELETE` revokes an
  approved active mapping;
- `GET /api/v1/mounts/nfs` returns the authenticated user's pending proposals
  and active aliases;
- `POST /api/v1/mounts/nfs/mapping-proposals/{proposal_id}/approval` and
  `POST /api/v1/mounts/nfs/mapping-proposals/{proposal_id}/decline` consume the
  expected proposal generation; and
- `DELETE /api/v1/mounts/nfs/mappings/{credential_id}` lets the target revoke
  an active alias with its expected generation.

The former direct-activation `POST /api/v1/admin/mounts/nfs/mappings` always
returns `409 mount.nfs.target_approval_required`. Proposal creation never
creates a credential, policy, session, or NFS authority. A proposal expires
after 24 hours, only its exact recently reauthenticated target may approve or
decline it, and changed fields require cancellation and a new proposal.
Approval atomically rechecks the proposal, target, proposer administrator
status, and both principals' current `READ_METADATA` on every drive. The
browser submits only the expected proposal generation on approval or decline;
it does not echo mapping fields or a server digest.

Proposal displays contain the exact Kerberos principal, target and proposer,
UID/GID and primary POSIX-group projection, expiry, and server-derived drive
labels and UUIDs. Labels are untrusted display text; UUIDs and other server-held
identifiers remain the authority inputs. The target Mount Settings inbox polls
this state. There is no email, push, or Iggy-dependent approval channel. All NFS
binding mutations retain the ordinary CSRF, exact Origin, Fetch Metadata,
idempotency, generation, and stable stale/expired/conflict problem contracts.

`GET /api/v1/admin/mounts/nfs/conflicts` lists only the authenticated
principal's unresolved, unexpired retained writes. `POST
/api/v1/admin/mounts/nfs/conflicts/{conflict_id}/copy` requires the exact
conflict drive, an authorized target parent, a new display name, the expected
parent namespace generation, `CREATE_CHILD`, tenant confirmation, and an
idempotency key before publishing the retained bytes as a new immutable file.
`DELETE /api/v1/admin/mounts/nfs/conflicts/{conflict_id}` requires the same
recent administrator authentication, exact tenant confirmation, ownership,
and idempotency, and admits fenced cleanup without erasing the retained
inventory row before its fixed deadline. Neither route exposes a payload
locator or GSS material.

VFS v1 adds additive NFS-generic attribute, ACL, xattr, symlink, sparse-write,
flush, commit, open-unlink, and reclaim messages. Existing field numbers remain
stable. Filehandles are opaque versioned values authenticated with a dedicated
rotating key and include export, node, and generation scope without exposing a
physical locator. Current and immediately previous handle keys may validate;
capability signing keys are not reused.

The adapter-local `FsalCall` wrapper does not change VFS v1. Ganesha/FSAL is the
trusted producer of its already-verified RPCSEC_GSS fields, but the bridge
accepts that wrapper only over the fixed `10002:10002` peer identity. The
reverse export-control channel accepts only bridge identity `10001:10001`.
Both `0660` sockets are assigned to dedicated group `10003` and require exact
socket metadata, `SO_PEERCRED`, and matching `SCM_CREDENTIALS`; group membership
alone never authenticates a caller.

`NfsAuthenticateRequest.source_address` is the immediate TCP peer observed by
Ganesha. In the supported split topology it is the relay Pod address, not the
tailnet client's address. The field remains part of conservative session reuse
fencing, so a relay reschedule creates a fresh FileBelt session. It is never an
identity, authorization, rate-limit, or end-client audit claim; Kerberos
principal mapping, the internal session principal, generations, and Virtual
ACL remain authoritative. The relay is byte-transparent and PROXY protocol is
prohibited.

Create, mkdir, and symlink carry an optional mode containing only `0777`
permission bits; omission selects `0644`, `0755`, and `0777` respectively,
while Core always derives UID/GID from the authenticated NFS projection. Lock
ranges distinguish a finite non-zero length from an explicit `to_eof` range.
`TestLock` is a separate read-only conflict query and is never implemented as
an acquire-and-release pair at one replay coordinate.

The current VFS checkpoint qualifies only persistent-handle resolution,
export-root and lookup traversal, metadata/access/list, immutable read-only
open/read/close, xattr reads, readlink, heartbeat, and end-session handling.
Create-like operations, writes, namespace and attribute mutations, ACLs,
locks, reclaim, open-unlinked, sparse operations, flush, and commit return a
stable pre-authority qualification sentinel. Their additive messages and
database authority are contracts for later qualification, not an enabled
write surface.

NFS slot replay never bypasses live VFS admission. Ordinary retransmissions
execute an operation-specific side-effect-free authorization preflight, then
validate its session, generation, resource, handle, and replay-slot fences in
the repeatable PostgreSQL snapshot that selects the canonical receipt. Read replay proves the current handle, immutable version,
and `READ_CONTENT` without repeating payload I/O; atomic open re-enters its
target/action preflight before its database-owned replay point. A changed
read/list/metadata projection yields a stale or existence-hiding response with
no cached payload or metadata. `EndSession` alone may replay after its session
is closed, and only as the exact applied, empty success acknowledgement while
credential, principal, policy, mapping, feature/export, gateway, GSS, and
expiry authority remain current. This tightens internal behavior without a VFS
protobuf or public route change.

Collaboration additionally advertises `/collaboration/v1/wt` when enabled.
One WebTransport session and one client-created reliable bidirectional stream
carry the unchanged length-delimited Protobuf frames for one room participant;
datagrams and extra streams are rejected. Authentication remains the first
frame using the one-use 60-second join grant. Reauthorization is bounded to 60
seconds, tokens never enter URLs, and WebSocket remains the behaviorally
equivalent fallback. Browser preference/backoff policy remains a client concern;
the current editor continues to request WebSocket unless it explicitly opts in.

## Key rotation and configuration

Configuration format 9 scopes signing material by purpose. `[keys]` contains
only `digest_key_file` and `digest_key_generation`; every signer has
`private_key_file`, `public_keyset_file`, and `current_generation`. API storage
is always `[keys.api_storage]`; API collaboration-grant and MCP-delegation are
enabled only with their features. Collaboration, document, and mount storage
signers occur only in enabled feature blocks; media storage is always
provisioned for administrative preflight and recovery. Strict
`filebelt-capability-keyset-v2` files contain `purpose=<name>`, a current key,
and at most one retiring key. Public-key bytes are globally disjoint and every
newly provisioned purpose begins at local generation 1.

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
The current format is version 9; older versions are rejected. API `fbcap1`,
collaboration `fbcap1`, document, and mount `fbcap2` signing keys use distinct
purpose-local private keys; I/O receives only API-storage and enabled
storage-purpose public keysets. `mcp.enabled`
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
