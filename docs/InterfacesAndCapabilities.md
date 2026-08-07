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
download grants, direct shares, and ACL-governed shared views. Tenant
administration, preferences, and audit/privacy mutation endpoints are not in the
current public contract. Group and anonymous-link share values are reserved but
unavailable.

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
payload deletion, and payload scrub. Before touching storage, the worker
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
