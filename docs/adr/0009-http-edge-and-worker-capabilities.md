<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0009: HTTP edge and worker capabilities

- Status: Accepted
- Date: 2026-08-06
- Owners: `@PiQuark6046`
- Reviewers: none
- Supersedes: none
- Affected license regions: Apache-2.0 and protocol consumers

## Context

Phase 2 exposes the first public application contract and permits browser byte
streams to reach storage workers without routing payloads through the API. The
edge, API, I/O worker, browser, and public-share route are distinct trust
boundaries. A user cookie or proxy-supplied identity must never become a worker
authorization mechanism.

## Decision drivers

- Keep metadata correctness available on ordinary HTTP semantics.
- Prevent the API and browser from choosing physical storage locators.
- Bound stolen or stale worker authority and make revocation independent of
  Iggy delivery.
- Keep the edge replaceable and avoid retries or caching that alter
  authenticated write semantics.

## Decision

### Public contract

FileBelt publishes an OpenAPI 3.1 JSON REST API below `/api/v1`. It covers
OIDC/session state, drives, nodes, trash, versions, upload/download grants,
direct shares, ACLs, audit/privacy/preferences, and tenant administration.
Group and anonymous-link share kinds are reserved but unsupported in Phase 2.
Raw byte operations use ordinary HTTP streaming below `/io/v1`; a future
anonymous exchange, if accepted, must use isolated `/public/v1` routes.

Responses use stable `application/problem+json` error codes, RFC 3339 UTC
timestamps, integer byte counts, opaque keyset cursors, a default page size of
50 and maximum of 200, and generation ETags. Mutation requests carry the
expected generation or head. Allocation and commit `POST` operations require
`Idempotency-Key`; records bind principal, route, request fingerprint, and
response for 24 hours and conflict on mismatched reuse.

The byte routes are:

- `PUT /io/v1/uploads/{upload_id}/parts/{part}`;
- `POST /io/v1/uploads/{upload_id}/finalize`;
- `GET|HEAD /io/v1/downloads/{grant_id}`; and
- future anonymous token exchange and download endpoints below `/public/v1`
  remain unimplemented and fail closed in Phase 2.

REST is the Phase 2 correctness contract. GraphQL, gRPC-web, WebTransport, and
HTTP/3-specific application behavior are deferred. Generated TypeScript
clients consume the OpenAPI document. Versioned Protobuf schemas under the
ADR-0004 layout define only capability and event envelopes.

### Edge boundary

The supported edge is the exact OxiBelt image pinned by ADR-0011. OxiBelt
terminates TLS, serves the SPA, and proxies to isolated HTTP backends. FileBelt
derives security decisions from its configured public origin and validated
local session, not `X-User`, `X-Group`, or another proxy identity header.
OxiBelt removes client-supplied internal/identity headers and sanitizes
`Forwarded` metadata before forwarding.

OxiBelt may retry safe reads according to the route profile. It does not retry
FileBelt writes and does not cache authenticated content downloads. A future
anonymous content route inherits the same no-cache rule. Hashed static assets
may be cached immutably; SPA entry points, session routes, APIs, and any future
public-token exchange responses are `no-store`.

OxiBelt and FileBelt communicate over an isolated HTTP network in Phase 2.
mTLS and Kubernetes NetworkPolicy arrive with the Phase 3 deployment boundary.
The lack of backend TLS is not permission to expose backend ports outside that
isolated development/integration network.

### Worker capabilities

After resolving namespace and authorizing an operation, the API emits an
`fbcap1` capability containing deterministic Protobuf claim bytes and an
Ed25519 signature. The API holds the private key; the I/O worker receives only
the overlapping public verification keyset and narrow PostgreSQL privileges.

Claims contain:

- format version, key generation, audience, and operation;
- tenant, principal, session, resource, upload, payload, and grant identifiers
  applicable to the operation;
- allowed part number or byte range;
- ACL, membership, session, and resource generation projection;
- fencing token, single-use nonce where applicable, issue time, and expiry.

Expiry is no more than 60 seconds from issue. Signed messages do not contain
maps, unordered fields, user paths, or physical locators. Implementations sign
the exact serialized claim bytes with an explicit domain prefix.

The worker validates format, signature, key generation, audience, operation,
time, IDs, bounds, fencing, replay status, and generation before touching
storage. Upload-part nonces are replay protected. The worker resolves physical
locators only through its narrow operation/payload repository and may neither
write namespace/ACL state nor accept browser cookies.

The API does not mount payload storage. OxiBelt sends byte operations directly
to the I/O worker. Browser downloads exchange an API authorization result for
a short-lived path-scoped `Secure` and `HttpOnly` capability cookie;
non-browser clients may use the `fbcap1` authorization scheme. An admitted
long stream checks the narrow generation projection at most every 60 seconds
and stops on mismatch or database uncertainty.

### Keys and configuration

`filebeltctl` generates overlapping keysets. The current generation signs new
capabilities and digests new sessions/share tokens; retiring capability public
keys remain accepted for at least 60 seconds, session digest keys for seven
days, and share digest keys for 30 days. Removing a generation is an audited
restart operation.

Runtime configuration is a versioned typed `filebelt.toml` with narrow
`FILEBELT_*` overrides and secret-file references. `filebeltctl config
validate` and service startup reject invalid public origins, missing keys,
overbroad listener exposure, unsafe timing relationships, and inconsistent
limits. Changes take effect on graceful restart rather than untracked hot
reload.

## Alternatives considered

Proxying all bytes through the API was rejected because it joins payload and
control-plane privileges. Passing a database-backed bearer token to the worker
was rejected in favor of offline-verifiable, audience- and operation-bound
claims. JWT was not selected for the worker envelope because committed
deterministic Protobuf already serves FileBelt's language-neutral protocol
boundary. Proxy identity headers, authenticated download caching, write
retries, and a WebTransport-only correctness path were rejected.

## Consequences

The API is the sole issuer of payload authority but is not on the byte path.
The worker needs narrow PostgreSQL reads for capabilities, generation
projections, operation state, and payload state. Open streams accept a bounded
revocation delay; all new mutations retain transactional authorization.

Public API and Protobuf `v1` changes are compatibility-reviewed. Incompatible
wire changes require a new version under ADR-0004.

## Security, data, and license analysis

Capabilities, sessions, CSRF tokens, share tokens, and public URLs are secrets
and must be redacted from logs, telemetry, diagnostics, and error bodies.
Rate limits apply at both edge and authoritative application layers; a proxy
limit is not an authorization control. Unknown or stale signing generations
fail closed.

The OpenAPI, Protobuf, generated clients, edge configuration, API, and workers
remain in Apache-2.0 regions. No OxiBelt implementation code is copied or
linked into an Apache package; the external image is a replaceable process
boundary with its own source, license, notices, and SBOM evidence.

## Verification

- Contract tests validate OpenAPI, generated clients, Protobuf regeneration,
  deterministic serialization, and breaking changes.
- Capability tests cover signature, audience, operation, ranges, expiry,
  replay, fencing, generation invalidation, and key overlap.
- Integration tests prove the API has no payload mount, the worker cannot
  mutate namespace/ACL state, and cookies/proxy identity headers are rejected.
- OxiBelt tests cover header stripping, origin handling, no write retry, Range
  streaming, no content caching, public-token redaction, and graceful drain.

## Rollout and rollback

Deploy compatible keysets and worker verification first, then the API issuer,
then activate edge routes. During rollback, stop admission of new uploads,
drain byte streams for at most the 60-second capability bound, retain all key
generations required by unexpired credentials, and restore the prior compatible
route configuration and binaries. Never roll back by deleting operation or
idempotency records.

## Open questions

None.
