<!-- SPDX-License-Identifier: Apache-2.0 -->

# Phase 8 Media, NFS, WebTransport, and Existing Platform Threat Model

- Date: 2026-08-09
- Owner: `@PiQuark6046`
- Scope: repository and image supply chain, OIDC and browser sessions, tenant
  administration, namespace and Virtual ACL, REST and authenticated sharing,
  OxiBelt, capability-limited storage workers, PostgreSQL, UUID payload
  storage, durable jobs, optional Iggy, audit, Markdown rendering and
  collaboration rooms, MCP registrations and vault,
  remote MCP mediation, one-shot curated runners, read-write mount VFS,
  Headscale device synchronization, GPL SMB/explicit-FTPS process boundaries,
  provider-neutral external document sessions, purpose-bound document I/O
  capabilities, the separately licensed AGPL ONLYOFFICE adapter and launcher,
  provider callback/JWT processing, output-fetch egress isolation,
  NFSv4.1/v4.2 with external Kerberos `krb5p`, NFS-Ganesha recovery and
  filehandles, media scheduling, hostile FFmpeg input, progressive derivative
  publication and cache, HTTP/3/WebTransport collaboration and WebSocket
  fallback, Kubernetes 1.34-1.36,
  NetworkPolicy, backend mTLS, GHCR/Helm publication, and quiesced recovery
- Excluded: managed-cluster/provider internals, online backup, HA/PITR and
  numeric production RPO/RTO, operator-supplied ONLYOFFICE DocumentServer and
  its database/cluster internals, paid ONLYOFFICE editions, application
  encryption, NFSv3/v4.0, macOS/BSD NFS qualification, pNFS, delegations,
  NVIDIA encoding, and any collaboration codec other than Yjs/Yrs `yjs-v1`

## Assets and security objectives

- PostgreSQL metadata, policy, generations, audit, jobs, and outbox remain the
  authoritative and tenant-separated control-plane state.
- Payload bytes and immutable versions remain confidential, integral, and
  available only through authorized UUID-addressed operations.
- OIDC identities resolve through exact issuer/subject mappings; host users,
  email, headers, filesystem ownership, and external IDs never become internal
  principals by implication.
- Every object path uses the common Virtual ACL and fails closed on stale or
  uncertain policy state.
- Session, CSRF, share, capability, signing, hashing, OIDC, database, and TLS
  secrets do not appear in URLs after exchange, logs, metrics, diagnostics,
  browser storage, images, or build evidence.
- A filesystem/database crash window recovers to one explainable state without
  unauthorized publication, silent loss, or premature deletion.
- Iggy loss, delay, duplication, or compromise cannot alter committed state or
  make revocation depend solely on event delivery.
- MCP server authentication never becomes FileBelt data authority. Every
  capability, approval, data disclosure, service grant, and revocation remains
  exact, tenant/principal-bound, generation-qualified, and PostgreSQL-backed.
- MCP credentials, OAuth verifier/state, bootstrap tokens, and vault keys do
  not cross into browser storage, untrusted server containers, telemetry,
  build evidence, or broader database roles. Exact approved arguments and
  selected attachment disclosures cross only to the chosen server; arguments,
  attachments, and results remain ephemeral and never enter browser
  persistence, telemetry, or build evidence.
- Remote and stdio MCP servers cannot select arbitrary egress, images,
  commands, resources, Kubernetes authority, payload mounts, or FileBelt
  credentials.
- Markdown preview content is isolated in an opaque-origin, sandboxed iframe;
  generated markup can reach only the child Trusted Types policy after reviewed
  sanitization, and conversion output is never an implicit write authority.
- MCP-assisted Markdown provenance cannot be asserted by a browser client or
  inferred from an unrelated invocation: it is bound to the exact tenant,
  principal, node, immutable base version, and normalized source transition.
- Pull-request inputs cannot cross license regions, publish artifacts, or
  broaden a FileBelt Pod's privileges. Tag-only promotion publishes only
  previously validated immutable subjects.
- SMB and explicit-FTPS paths resolve the same internal principal and Virtual
  ACL as the web API. Gateway, credential, device, session, handle, and lock
  authority remains fenced in PostgreSQL; Headscale, Tailscale, adapter memory,
  and host ownership are never authorization truth.
- Raw mount passwords are one-time or ephemeral, verifier ciphertext is bound
  to a distinct mount-vault context, and the mount signing key cannot mint API
  or collaboration authority. VFS and adapters have no payload mount.
- External document sessions cannot turn a provider callback or browser launch
  into ambient FileBelt authority. Input reads, revision writes, finalization,
  and commits remain exact, short-lived, generation-qualified, fenced, and
  PostgreSQL-backed; a concurrent head can only create a retained conflict.
- Provider JavaScript executes only on a FileBelt-controlled editor hostname
  distinct from the public and provider hostnames. The editor host exposes no
  API route or API CORS authority, receives no public-host FileBelt cookie, and
  is constrained by the fixed launcher CSP sandbox.
- The AGPL adapter and DocumentServer receive no payload mount, browser session,
  general database credential, or unrestricted egress. Provider-specific code,
  JWTs, callback status mapping, editor assets, branding, and network source
  access remain outside the Apache process and bundle.
- Kerberos and numeric POSIX projections cannot become FileBelt authority by
  implication. Every NFS principal is explicitly tenant-mapped, every path
  component is authorized through `TRAVERSE`, every mutation rechecks current
  Virtual ACL, and neither AUTH_SYS nor Kerberos root has a bypass.
- A compromised Ganesha/FSAL or bridge cannot obtain payload paths, database
  credentials, browser sessions, capability-signing keys, or KDC material not
  required by its container. Forged filehandles, stale stateids, replayed
  slots, old gateway epochs, and old filehandle-key generations fail closed.
- Hostile media cannot cause Internet/device access, parser widening, payload
  disclosure, unbounded resource consumption, or publication of partial
  output. The controller, job wrapper, FFmpeg process, I/O service, and
  PostgreSQL receipts are independent admission and publication gates.
- A READY media artifact remains cache state rather than authorization state.
  Playback and cache reuse require current source authorization, and revocation
  fences publication within 60 seconds even when Iggy is unavailable.
- WebTransport cannot weaken collaboration authentication, framing, durable
  acknowledgement, revocation, drain, or replay semantics relative to
  WebSocket. QUIC 0-RTT, datagrams, extra streams, forwarded cookies, and URL
  credentials are disabled.

## Trust boundaries and data flow

```text
OIDC issuer <──TLS CONNECT── egress gateway <── NetworkPolicy ── API
       │                                                        │
       └──code+PKCE──> browser ──TLS/session+CSRF──> OxiBelt    ├──> PostgreSQL
                                                   │           └── signed capability
                                                   ├──mTLS──> API
                                                   └──mTLS──> I/O worker ──> RWX payload root

PostgreSQL outbox ──> publisher ──optional──> Iggy ──wake/invalidate──> workers
PostgreSQL jobs  <──────────────────── five-second polling fallback ────────┘

browser ──session+CSRF──> API ──signed fbmcp1/mTLS──> MCP broker
                              │                         ├──mTLS/target profile──> MCP egress gateway ──> remote server
                              │                         └──mTLS──> controller ──namespaced API──> one-shot runner Pod
                              └──exact version/data grant──> I/O worker             ├──trusted relay──> broker/gateway
                                                                                     └──stdio──> untrusted catalog server

Headscale API ──TLS/token──> Headscale sync ──atomic device snapshot──> PostgreSQL
tailnet client ──SMB/explicit FTPS──> GPL gateway ──mTLS/VFS v1──> VFS
                                                                  ├──> PostgreSQL
                                                                  └──fbcap2/mTLS──> I/O worker ──> RWX payload root

browser ──session+CSRF──> public OxiBelt ──mTLS/API──> API ──mTLS/document v1──> document coordinator
       └──one-use top-level form POST──> editor OxiBelt ──mTLS──> AGPL adapter ──provider JWT/config──> DocumentServer
                                                                   ├──mTLS/document v1─────────> coordinator
                                                                   ├──document-storage fbcap1/mTLS─> I/O worker ──> RWX payload root
                                                                   └──mTLS/exact target────────> output egress gateway ──> DocumentServer
```

OxiBelt terminates public TLS. Kubernetes API and I/O backends require TLS 1.3
client identity and are also isolated by NetworkPolicy. The API has PostgreSQL
access and signing keys but no payload mount. The I/O worker has the shared
payload mount, verification keys, and narrow database access but cannot mutate
namespace or ACL state. Maintenance uses a distinct database role and the same
RWX root. Iggy is an untrusted, at-least-once notification path.

The API owns browser intent and approval admission but has no MCP-vault access.
The broker owns narrow MCP policy/vault access, receives signed delegations,
has no payload mount, and can reach remote servers only through the MCP egress
gateway. The controller is the only FileBelt workload with a ServiceAccount
token; it runs in the core namespace, but its cross-namespace Role is limited
to runner Pods, bootstrap Secrets, and its leadership Lease in a separate,
exclusive runner namespace. The runner relay is trusted FileBelt code, while the
catalog server sharing its Pod is hostile. That server receives no token,
Secret, database, payload, or Kubernetes API authority and reaches the network
only through the loopback relay proxy and default-deny NetworkPolicy. Runner
Pods have no DNS egress: the trusted controller resolves the broker and gateway
to bounded numeric address lists, and the relay rejects hostnames while keeping
TLS server-name authentication separate.

VFS and Headscale sync are Apache processes with distinct narrow PostgreSQL
roles and no payload mount. The VFS is the only process that decrypts a mount
verifier and signs `mount-storage` `fbcap2`; the I/O worker verifies that envelope
and authoritative handle/version fences before reading bytes. GPL gateways are
replaceable clients of the generic mTLS protocol and receive no database,
vault, signing, browser-session, Kubernetes-token, or payload authority.
Headscale and the gateway tailnet are external trust inputs, not policy stores.
Only gateway sidecars receive `NET_ADMIN`, `/dev/net/tun`, and protocol-local
RWO tailstate. The mount topology is disabled because the Samba IPC and both
adapter release images lack production acceptance evidence.

The Apache document coordinator owns provider-neutral session, participant,
revision, and reconciliation state through its narrow PostgreSQL role. It has
the `document-storage` signing key and no payload mount or Internet egress. The AGPL
adapter owns ONLYOFFICE configuration, status mapping, callback JWT validation,
and launcher/source surfaces; OxiBelt reaches it with a dedicated exact mTLS
identity, it can reach Core and capability-limited I/O only with its own exact
mTLS identities, and it fetches provider output only through the exact-target
egress gateway.
DocumentServer is hostile with respect to FileBelt identity and storage. A
valid provider JWT authenticates a bounded callback but does not authorize a
FileBelt commit; Core rechecks the initiating API session and Virtual ACL in
the expected-head transaction. The feature and all routes are disabled by
default, so Apache FileBelt remains usable when every external component is
absent.

The public and editor OxiBelt virtual hosts terminate under one
FileBelt-controlled certificate with both DNS names, but their route sets are
disjoint. The public host serves the SPA, API, adapter input/callback, and
source/about routes; the editor host serves only the launch POST and launcher
asset GET. The launch POST requires the exact public-origin `Origin`, and the
adapter repeats exact host enforcement behind the edge. Host-only cookies do
not cross the hostname boundary. This design assumes no known provider-script
compromise at rollout. If compromise is suspected, operators block
reauthentication and rotate the FileBelt public origin under the incident plan
rather than treating the one-time cutover as sufficient containment.

The production namespace is one trusted FileBelt deployment and tenant.
Adjacent Pods and compromised public clients are hostile. The Kubernetes
control plane, cluster and node administrators, CNI, CSI/storage provider,
database operator, certificate issuer, OIDC issuer, and egress-gateway operator
remain powerful trusted parties. Namespace isolation does not protect against
a compromised node or cluster administrator. ServiceAccount tokens are absent
from every workload except the runner controller's narrowly authorized Pod.

## Threats and controls

| Threat | Control | Required evidence |
| --- | --- | --- |
| OIDC login injection, replay, or callback confusion | Exact issuer and callback allowlists; code+PKCE, state, nonce, signature, audience, and time validation | OIDC negative and replay tests |
| Mount credential bypasses Virtual ACL or survives a policy change | Random protocol credential resolves one internal principal; every operation revalidates policy, credential, drive, namespace, membership, resource, ACL, gateway, device, and session generations in PostgreSQL | Two-user allow/deny, policy-replace, ACL-revoke, credential-revoke, and stale-handle tests |
| Raw FTPS password or SMB verifier leaks through browser, logs, adapter memory, or another tenant | One-time create response, recent-OIDC requirement, mTLS-only ephemeral FTPS exchange, zeroization of FileBelt-owned serialization and VFS buffers, bounded framework command lifetime, encrypted verifier-only vault with context-bound AAD and distinct KEK, stable redacted errors | UI/browser-storage, log-redaction, zeroization, vault context-swap, and cross-tenant tests |
| Brute force exhausts verifier comparison or reveals valid usernames | Keyed username/source throttle in PostgreSQL, constant verifier comparison, uniform authentication failure, bounded session/credential lifetimes | Rate-window, successful-clear, unknown-user equivalence, and concurrent-attempt tests |
| Stale or malicious Headscale data authorizes another principal or preserves a disappeared device | Exact OIDC issuer/subject mapping; ignore tagged/service nodes; validate bounded full snapshot, duplicate IDs and expiry before one atomic replacement; device ownership generation fences sessions | Partial/malformed/duplicate/expired snapshot, identity swap, disappearance, and rollback tests |
| Gateway restart or another replica replays an opaque session | PostgreSQL gateway epoch returned by zero-epoch hello and bound to every request/session/handle; restart or retirement invalidates dependent state | Cross-gateway, stale-epoch, restart, request-correlation, and expiry tests |
| Mount capability is replayed, widened, or accepted as API authority | Distinct `fbcap2` prefix and purpose-tagged `mount-storage` keyset; exact read audience/range/version/handle/generation claims, random nonce, <=15-second expiry, I/O PostgreSQL revalidation | Prefix/key confusion, claim mutation, stale-handle/version, range, expiry, and cross-audience tests |
| Compromised VFS or gateway reads arbitrary payload paths | No payload mount; VFS can issue read-only `fbcap2` only for an admitted handle; I/O resolves UUID locator through narrow immutable-version state; gateway receives only bytes and generic IDs | Container mount, DB grant, arbitrary-ID, write-operation, and direct-worker denial tests |
| Adapter falls back to local filesystem or crosses the license boundary | Apache core imports only generic schema; separate GPL workspaces/processes/images/notices/source offers; Samba callbacks return `ENOSYS` until reviewed IPC exists; adapters disabled by default | Cargo boundary, dependency graph, ABI callback, local-fallback, REUSE, notice, source-offer, and image-plan tests |
| Tailnet sidecar or state expands core Pod authority | Tailscaled exists only beside gateways, kernel networking is explicit, non-privileged sidecar has only `NET_ADMIN` and one `/dev/net/tun`, separate RWO state, no ServiceAccount token, default-deny peers | Rendered securityContext/device/mount/RBAC and NetworkPolicy tests |
| Provider callback is forged, replayed, reordered, or used for another document | Exact opaque route binding, HS256 algorithm/claim/context validation with separate current and bounded-retiring secret, canonical event digest persisted before acknowledgement, monotonic state/fence checks, and idempotent Core outcome lookup | Bad-algorithm/signature/claim/key, cross-document, duplicate, out-of-order, response-loss, and restart tests |
| Provider output URL performs SSRF, DNS rebinding, redirect escape, or oversized download | Exact configured HTTPS origin and provider identity; no userinfo/fragment; direct adapter Internet denied; mTLS egress gateway revalidates DNS/IP and TLS target, refuses redirects, and streams under header/time/100 MiB limits | Private/link-local/metadata, IPv4/IPv6, rebinding, redirect, slow/large, CA/SNI, and NetworkPolicy denial tests |
| Callback overwrites a newer Web, Markdown, mount, or document version | Core locks current authorization/session generations, revision fence, and expected node head in one PostgreSQL transaction; mismatch creates a seven-day retained conflict and never updates the head | Two-writer head race, ACL/session revoke, conflict-copy authorization, retry, and no-overwrite tests |
| Adapter or DocumentServer reads arbitrary FileBelt content | No browser cookie, payload mount, API signing key, or general DB credential; one-use launch; `document-storage` exact-version/range capability; I/O resolves only the signed immutable version and rechecks generations | Cross-tenant/node/version/range, expired/replayed grant, arbitrary-ID, mount, database-grant, and direct-worker tests |
| Malicious editor script escapes into the Apache SPA, uses a FileBelt browser session, misstates the external provider, or leaks a launch grant | Dedicated FileBelt-controlled editor hostname distinct from public/provider hosts; disjoint OxiBelt routes and repeated adapter host checks; exact public `Origin` on top-level POST; no API CORS or launcher cookie; Core-issued display-only provider origin; memory-only one-use form value; fixed script/connect sources and exact CSP sandbox; no FileBelt token in query/referrer/storage | Chromium/Firefox real-provider CSP and cookie isolation, hostile-script API denial, old-route 404, consent-origin, clickjacking, form-action, postMessage schema/origin, referrer, Web Storage, and cross-tab tests |
| Community edition limits or license/source obligations are hidden or bypassed | Fixed provider `9.4.0`, 20 active-participant admission under PostgreSQL lock, no clustering claim, retained branding, public exact source/about endpoints, immutable source URL/build instructions/notices, truthful distinct OCI labels | Capacity race, source-link HTTP, branding, REUSE, notice, SBOM/source-map, image-label, and release-gate tests |
| Document save is acknowledged but lost or duplicated across adapter/Core/I/O crash | Durable event/revision/reconciliation rows precede acknowledgement; UUID allocation and quota reserve are transactional; I/O fsync and digest precede staged state; reconciliation reads terminal committed/no-op/conflict result and never creates a second version | Kill points at callback, allocation, byte write, finalize, commit, and response; duplicate revision and Iggy-down tests |
| MCP OAuth callback is mixed up, replayed, or used for another server | Ten-minute one-shot server-held attempt bound to user, session, registration, credential generation, issuer, exact callback and local return path; every credential/config change erases pending attempts; PKCE/state and resource/audience binding; no token passthrough | MCP OAuth fixture, generation change, mix-up, expiry, replay, and audience tests |
| MCP credential is exposed to the API, browser, logs, or another registration | Separate vault schema and broker role; AES-256-GCM envelope with context-bound AAD and KEK generation; write-only UI; configuration PATCH is broker-mediated cryptographic erasure through one narrow definer function | Database privilege, direct-config denial, vault context-swap, browser-storage, redaction, and deletion tests |
| Remote endpoint performs SSRF, DNS rebinding, or trust-profile escape | Broker has no direct Internet path; mTLS gateway receives exact target origin/profile and enforces host, CIDR, port, CA, redirect, and resolved-address policy on every connection | Gateway redirect/rebinding/private-address and NetworkPolicy denial tests |
| Remote capability drifts after approval | Immutable snapshot and descriptor fingerprint; enablement requires exact review; rediscovery/drift disables authority until review | Capability drift, fingerprint, and enablement-state tests |
| Browser silently approves or replays changed arguments | Five-minute intent with server-derived keyed argument/attachment digests; explicit confirmation; one-shot atomic approval; exact request resubmission | Browser no-preapproval, changed-request, second-use, and cross-session tests |
| Collaborator falsely labels an unrelated edit as MCP-assisted | Invocation retains only exact node/base-version context and normalized input/output digests; the fenced collaboration manifest transaction matches those values with tenant and principal; direct upload/save/copy routes expose no invocation-provenance binding | Cross-node, base-version, principal, before/after-digest, direct-upload, and duplicate-update provenance tests |
| Collaboration grant is replayed, leaked in a URL, or used by a spectator | Opaque one-use first-frame-only grant, <=60-second expiry, no URL/session secret, exact principal/session/room/generation binding, and READ_CONTENT plus WRITE_CONTENT admission with no spectator mode | URL/referrer, replay, cross-session, expired-grant, and read-only-user denial tests |
| CRDT update is acknowledged then lost or reordered | 256 KiB chunk and 2 MiB group bounds; ACK only after I/O finalize/file-and-directory fsync and fenced PostgreSQL manifest commit; reconstruct from ordered manifests, never Iggy | Kill-point, duplicate/group-order, restart, and Iggy-down recovery tests |
| ACL revoke or external head change silently merges dirty edits | Reauthorize at most every 60 seconds; fence/freeze on generation or head change; preserve 30-day dirty state for explicit deterministic diff3 review | ACL-revoke, head-race, reconnect, diff3, day-23 warning, and day-30 expiry tests |
| Markdown or MCP semantic data executes markup or exhausts resources | filebelt-gfm-v1 renders raw HTML literally; strict UTF-8/no-NUL validation; 2 MiB edit/semantic and 8 MiB view bounds; Mermaid/KaTeX run only in reviewed, isolated render paths | XSS, malformed-UTF8, NUL, size-bound, Mermaid/KaTeX, and semantic-output tests |
| Preview frame or converted Office document escapes its browser boundary | Opaque-origin `sandbox=allow-scripts` preview, parent Trusted Types policy `none`, child-only generated-markup policy and inline-style allowance for sanitized Mermaid/KaTeX output (never inline script), a data-free handshake that transfers a dedicated MessageChannel port for typed recursive-AST validation, and `officeparser/slim` with OCR, attachments, and remote assets disabled | Chromium/Firefox iframe CSP, Trusted Types, postMessage/MessageChannel, Office-format, warning, and size-bound tests |
| Data grant follows a moving file head or reaches another server | Grant binds destination registration, drive/node and immutable version, disclosures, expiry, and ACL/namespace generations; revalidate before transfer | Version-head race, registration-swap, revoke, and ACL-generation tests |
| Service identity or saved grant becomes broad ambient authority | Exact SPIFFE binding, application/capability/arguments/data-grant set, hourly quota and <=30-day expiry; suspend/delete revokes dependent state | SPIFFE mismatch, attenuation, quota, expiry, and service-revocation tests |
| Malicious result executes script or exhausts the browser | Render text literally, JSON as a bounded non-editable tree, and only allowlisted magic-checked media through Blob URLs; no HTML injection or autoplay | Chromium/Firefox script-result, media-bound, CSP, and accessibility tests |
| Compromised broker reads arbitrary payload or browser identity | No payload mount, no browser session/OIDC/ACL/user/payload-locator database privileges, signed narrow delegation, and I/O mediation for approved versions | Mount, database-grant, delegation, and direct-storage denial tests |
| Curated server steals bootstrap, broker, gateway, or Kubernetes credentials | Secrets mount only in the trusted relay; the server receives only its reviewed command, runner shim, memory socket, bounded temporary storage, loopback proxy settings, no ServiceAccount token, and a scrubbed environment | Rendered-Pod secret/mount/env and in-Pod abuse tests |
| Runner catalog substitutes an image, command, signature, or resource limit | Schema-v1 bounded catalog, digest-only image, offline Sigstore trusted root/bundle with exact issuer/identity, allowlisted registry/architecture/egress profile, fixed command and resources | Catalog traversal, signature, digest, command, architecture, and quantity tests |
| Compromised controller gains core or cluster-wide authority | Pre-created exclusive runner namespace, core controller ServiceAccount bound only to a Role in that runner namespace, no core Role and no ClusterRole | Static RBAC, `kubectl auth can-i`, cross-namespace, and leader tests |
| Orphan runner survives cancellation or controller failover | Invocation lifecycle owns create, create/cancel share a mutation lock, cancellation-before-ack performs idempotent cleanup, resources are invocation-named, and Pods have a 130-second deadline | Cancellation/create race, controller failover, stale Secret, and cleanup tests |
| MCP flood exhausts broker, controller, or remote server | Bounded request/result/attachment sizes and deadlines, principal/registration/replica semaphores, bounded queue, persisted rate buckets, and PostgreSQL-authoritative runner slots reserved before create and held until confirmed delete | Oversize, timeout, queue-full, rate-limit, cross-replica concurrent-runner, expired-slot, and delete-failure tests |
| Revocation depends on event delivery or leaves a recoverable token | PostgreSQL registration/block generations cancel invocations and revoke dependent approvals, immutable-version data grants, snapshots, and reviews; Iggy is unused for authority; broker erases vault/OAuth envelopes and records only a tombstone | Iggy-down revocation, admin-block in-flight cancel, generation-bound grant, cryptographic erasure, and tombstone tests |
| Restore omits a vault generation or MCP policy inventory | Recovery checkpoint v2 records MCP counts/tombstones and referenced KEK generations without ciphertext; verification must match before traffic | Quiesced v2 checkpoint, missing-KEK, mismatched-inventory, and fresh-target restore tests |
| Public login requests exhaust PostgreSQL | Expired or consumed attempts are reclaimed under a tenant lock and active attempts have a fixed admission bound | Retention and admission-limit tests |
| Stale or malicious JWKS authorizes a new identity | Bounded 24-hour freshness plus 24-hour known-key outage window; unknown `kid` and new discovery fail closed | Rotation/outage/unknown-key tests |
| Mutable email takes over an account or share | Identity is exact issuer/subject; only verified email resolves an already-linked principal; grant stores principal ID | Identity collision and share-resolution tests |
| First login obtains deployment control | Explicit administrator issuer/subject allowlist and separate idempotent tenant bootstrap | Bootstrap and first-user tests |
| Administrator reads private content by role | Tenant administration is control-plane-only and receives no implicit content ACL | Cross-user admin isolation tests |
| Disabled IdP user retains access indefinitely | Authoritative local suspend/revoke; bounded local session expiry; no refresh token | Suspend and session-revocation tests |
| Session theft, fixation, or CSRF | 256-bit opaque token, keyed digest, Secure/HttpOnly/SameSite cookie, rotation, CSRF token, Origin and Fetch Metadata checks | Cookie, fixation, CSRF, and logout tests |
| Browser secret persists or leaks through a referrer | No raw session or capability token in browser storage; no-referrer and restrictive CSP; anonymous links remain disabled | Browser storage/referrer tests |
| ACL allow overrides a more restrictive ancestor | Except for non-removable ownership authority outside the entry set, applicable deny always wins and inherited deny cannot be overridden | Authorization table/property tests |
| Manager grants rights they do not have or removes an ACL row for such a right | Separate actions and strict delegation attenuation over submitted rows and non-share advanced rows removed by exact replacement; reject rather than trim, and revalidate at the fenced database mutation | Delegation and ACL-replacement property tests, including omitted deny/allow rows, empty clears, stale fences, and owner/share preservation |
| Recursive direct share or historical MCP data grant retains broader authority after an attenuation defect | Tenant state starts fail-closed; database admission triggers block old and new writers; resumable 1,000-row repair revokes every active recursive share and pre-fence grant, removes linked ACL rows, records receipts/audit/outbox, and requires verified tenant-admin activation | Migration seed/new-tenant, raw-writer, API 503/Retry-After, repair/resume, generation/outbox, privilege, verify/activate, and old-replica rollout tests |
| Stale group or ACL cache extends access | Transactional generation advance; mutations revalidate; streams check at most every 60 seconds; uncertainty fails closed | Revocation and outage tests |
| Object existence leaks across ACL boundary | Unauthorized lookup uses indistinguishable `404`; share resolution is minimal-reveal | Cross-user response equivalence tests |
| Recursive operation skips a descendant check | One generation snapshot, per-node authorization, 1,000-node request bound, fenced durable path above it | Bulk race and rollback tests |
| Client or proxy forges an internal principal | Resolve local session only; strip identity/internal headers; never authorize from proxy identity metadata | Header-smuggling tests |
| Adjacent Pod connects directly to a backend | Namespace default-deny plus per-role allowlist; backend TLS 1.3 requires the exact OxiBelt API or I/O client URI SAN | Calico/Cilium denial and mTLS-negative tests |
| Compromised web client identity reaches the other backend | Separate client certificates and exact URI SAN allowlists for API and I/O; one retiring identity allowed only during rotation | Cross-upstream certificate and rotation tests |
| Kubelet cannot authenticate to an mTLS application listener | Separate low-information operations listener; never expose it publicly; metrics ingress restricted to configured monitoring peers | Probe and NetworkPolicy tests |
| Mutable Secret changes or a projected keyset crosses a purpose boundary | Existing key-filtered, purpose-specific Secret projections plus an explicit generation in the Pod template; v2 keysets bind a purpose and globally disjoint public-key bytes | Secret/certificate rollout and hostile-signer tests |
| Unexpected ServiceAccount token or RBAC expands a compromised Pod | Token automount disabled for every role except the controller; its exact runner-namespace Role is the only Role/Binding rendered and grants no core-namespace authority | Static manifests and `kubectl auth can-i` tests |
| API bypasses the OIDC egress allowlist | Dedicated OIDC HTTP client uses an explicit in-cluster CONNECT gateway; NetworkPolicy permits only its namespace/pod/port; gateway allowlists the issuer | Direct-Internet denial and gateway destination tests |
| DNS or external dependency addressing creates catch-all egress | Core roles use explicit DNS peers; runner Pods have no DNS path and receive only controller-resolved numeric broker/gateway addresses; chart rejects IPv4/IPv6 default routes | Schema/helper and live policy tests |
| Proxy retries a non-idempotent write | OxiBelt write retries disabled; allocation/commit require scoped idempotency records | Lost-response and duplicate-write tests |
| Edge cache serves another user's content | Authenticated content and reserved public routes are never cached; only non-JavaScript hashed static assets are immutable | Cache-control and cross-user tests |
| Stolen capability is replayed or used for another object | `fbcap1` audience/operation/ID/bounds/generation/fence/nonce/expiry signature; upload nonce replay record | Capability mutation and replay tests |
| Worker accepts a cookie or arbitrary physical UUID | Worker accepts capabilities only and resolves locator through narrow operation state | Direct-worker abuse tests |
| Compromised API edits payload bytes | API image has no payload mount; worker owns byte paths | Container mount contract tests |
| Compromised worker grants namespace access | Worker database role cannot modify principals, namespace, ACL, versions, or audit authority | Database-grant tests |
| Path traversal, symlink, or special-file substitution | Logical names never enter paths; UUID sharding, pre-open/no-follow/exclusive-create behavior, startup ownership/mode probes | Filesystem attack tests |
| Acknowledged bytes disappear after crash | File and directory fsync plus durable operation state before acknowledgement; atomic same-filesystem rename | Kill-point and restart tests |
| Concurrent or cancelled finalization amplifies whole-payload work | Atomic leased `FINALIZING` claim before filesystem work, heartbeat in a detached orchestration task, owner/fence completion, and expired-lease recovery | Claim, heartbeat, cancellation, and recovery tests |
| Finalized bytes are deleted before version commit | Explicit states, 24-hour orphan grace, fenced deletion intent, recheck references | Finalize/commit/GC race tests |
| Client digest masks corrupted data | Server recomputes part and whole BLAKE3 at upload/finalization, verifies every chunk selected for a download, and performs scheduled full scrubs; corruption becomes quarantined | Digest, Range, and scrub tests |
| Quota race overcommits storage | Transactional declared-byte reservation and physical-byte accounting | Concurrent reservation tests |
| Disk exhaustion destabilizes all roles | Reject reservations below 5 percent or 10 GiB; bounded request/chunk limits | Low-space tests |
| Lease takeover causes duplicate destructive work | PostgreSQL time, heartbeat, fencing, idempotent state transition and reference recheck | Lease/fencing tests |
| Iggy outage blocks commits or revocation | Transactional outbox, PostgreSQL generations, five-second job polling, rebuild from PostgreSQL | Iggy-down and replay tests |
| Duplicate or forged event mutates truth | Consumers treat events as hints, validate version/topic, deduplicate, and read authority from PostgreSQL | Duplicate/malformed event tests |
| Audit reveals secrets or can be edited | Structured allowlisted fields, keyed actor/resource references, redaction, append-only grants, bounded retention | Audit mutation/redaction tests |
| Backup restores mismatched database and payload state | Quiesce/fence, shared watermark, fresh-volume restore, reconcile, manifest/BLAKE3 verification | Backup/restore acceptance test |
| Helm migration races replicas or silently skips owner grants | Non-hook migration under the migrator role, explicit DBA `grants.sql` pause, grant/schema verification, then workload rollout; APIs never migrate | Staged upgrade and privilege-matrix tests |
| Administrative Job combines owner, runtime, and payload authority | No owner Secret; operation-specific DB Secret and volume projection; one explicit Job per revision | Rendered Job/mount/egress tests |
| Metrics, traces, or Job evidence disclose identities or content | Bounded label/attribute vocabulary, structured redaction, private listeners, synthetic-only retained recovery artifacts | Observability asset and log-redaction tests |
| Quiesce checkpoint races active Pods | Separate Helm revision first scales every writer to zero; a later revision runs checkpoint while still quiesced | Restore orchestration test |
| RWX provider violates POSIX durability or changes ownership | Existing claim only, UID/GID 10001 provisioning, startup and pre-rollout fsync/rename/no-follow probe, no privileged chown init container | Storage probe and chart contract tests |
| Real Iggy helper broadens stack privileges | `SYS_NICE`, memlock, and seccomp exception apply only to the digest-pinned Iggy container | Compose/container inspection |
| OxiBelt prerelease or native crypto input is substituted | Exact version/digest, source map, lockfile, SBOM, notice, vulnerability, ELF, and three-platform evidence | Supply-chain and image tests |
| Cargo Vet acceptance is mistaken for a source audit or silently broadened | Exact locked-version exemptions only; no trusted publishers or ranges; independent audit, deny, lockfile, and import-lock gates | Cargo Vet policy tests and `cargo vet --locked` |
| Pull request or manual run publishes an untrusted image | Read-only validation workflows; tag-only promotion job consumes validated archives, verifies an authorized signed tag, attests and reads back immutable digests | Workflow-integrity and release dry-run tests |
| Promotion rebuilds or moves a tag after validation | Promotion cannot build; it assembles validated per-platform archives, publishes only version tags, verifies manifest/chart digests, and emits attestations | Release artifact/digest tests |
| Apache core imports an adapter implementation | Workspace and resolved dependency enforcement; generic protocol process boundary | Dependency-boundary tests |
| Kerberos, AUTH_SYS, or projected UID/GID bypasses Virtual ACL | `krb5p` only; explicit tenant mapping; AUTH_SYS disabled; zero/root has no privilege; every component requires current `TRAVERSE` and the exact operation action | Real KDC, spoofed AUTH_SYS, unmapped/root, ACL-revoke, and path-component tests |
| Forged NFS handle, replay, or stale gateway commits bytes | Dedicated rotating handle MAC; current/previous key only; export/node/generation binding; PostgreSQL gateway epoch, replay receipt, expected head, quota, and authorization recheck before immutable commit | Handle fuzzing, key rotation, restart/grace, slot replay, stale epoch, and expected-head tests |
| Open-unlinked or conflicting NFS writes resurrect or overwrite a name | Tombstoned handle state, immutable base, final-close fence, seven-day retained conflict, separately authorized conflict copy, and no automatic abandoned commit | Open-unlink, concurrent Web/NFS writer, crash, retention, and no-resurrection tests |
| Malicious media input escapes sandbox or consumes unbounded resources | Exact demuxer/decoder/filter allowlist, no FFmpeg network/device protocols, bounded preflight, `emptyDir`, CPU/memory/deadline limits, no token/DB/payload mount or egress | Parser corpus, network/device/attachment rejection, resource ceiling, seccomp, mount, and NetworkPolicy tests |
| Partial or attacker-selected transcode bytes become playable | Controller-selected immutable source/profile; job-scoped capabilities; server-computed BLAKE3; durable segment receipt before manifest reference; fenced revision and current ACL/session check | Digest mismatch, partial upload, reordered receipt, stale attempt, revoke-before-publish, and crash tests |
| Cache hit discloses a revoked source | Cache key is not authority; playback grant creation and renewal re-evaluate current source `READ_CONTENT`; opaque route with scoped HttpOnly cookie | Cross-user, revoke, expiry, cookie scope, URL/referrer, and cache-eviction tests |
| QUIC retry, 0-RTT, extra streams, or fallback duplicates collaboration updates | Retry enabled, 0-RTT/datagrams/extra streams disabled, first-frame one-use grant, durable update IDs, fenced replay, fresh grant on fallback, bounded drain | Chromium/Firefox loss/reconnect, replay, stream/datagram, grant, drain, and WebSocket-parity tests |

## Audit and privacy

Audit all authentication/session/administrator activity, mutations, ACL/share
changes, download starts, conflicts, corruption, and
denials. Do not emit routine list results or chunk progress. Records contain
stable IDs and reason codes, not raw credentials or payload content. The
default durable retention is 365 days and the user-visible privacy subset is
90 days; operator configuration remains within the bounds in
[Namespace and Authorization](NamespaceAndAuthorization.md).

## Residual risk

The single maintainer, cluster/operator plane, storage/database providers,
certificate issuer, OIDC and MCP egress gateways, configured OIDC issuer,
Headscale/tailnet operator, MCP and mount vault KEK custodians, and
runner-catalog signing authorities remain
concentrations of trust. A compromised API signing key can issue byte or MCP
delegations until the key generation is retired, although claims and worker or
broker generation checks limit scope and time. A storage or database
administrator can deny service and may observe unencrypted-at-application-layer
data; encryption at rest is delegated to the volume/provider.

Open byte streams can retain access for up to the configured 60-second check
interval. The Kubernetes recovery procedure proves a coordinated quiesced
restore into fresh targets, but it does not claim production availability,
online backup, PITR, HA, or an RPO/RTO. Standard NetworkPolicy cannot identify
an Internet FQDN, so OIDC and remote MCP depend on their operator gateways.
A compromised controller can replace eligible Pods and Secrets only in the
exclusive runner namespace; exact RBAC, offline catalog verification, short Pod lifetime,
and separate broker/gateway authentication limit but do not eliminate that
risk. A malicious admitted server can consume its assigned CPU, memory, and
ephemeral storage and return adversarial data until its deadline; it cannot be
made trustworthy by sandboxing.
The mount topology remains disabled by default and is not production-ready in
this revision: the SMB gateway has no reviewed Samba authentication/session IPC
path, neither adapter has qualified release-image evidence, and the FTPS bridge
has no live VFS/certificate end-to-end result. These are explicit delivery
gates, not risks accepted by enabling the current preview.
The ONLYOFFICE topology is likewise disabled by default. Its provider is an
operator-supplied AGPL network service with its own parser/rendering attack
surface, availability, database, branding, source-delivery, and 20-connection
Community limit. Exact-target egress, process separation, capability fencing,
and expected-head commits reduce FileBelt impact but cannot make provider
content or the provider process trustworthy. Operators must not enable the
route until the adapter source/SBOM/provenance, real or contract-faithful
callback fixtures, real digest-pinned `9.4.0` Chromium/Firefox acceptance, and
live NetworkPolicy/mTLS denial evidence pass.
Dependency scans, attestations, and signed source mappings reduce known
supply-chain risk but do not eliminate unknown vulnerabilities. Cargo Vet exemptions record
acceptance of the current locked graph rather than a complete source audit, so
their review debt remains until equivalent audit evidence replaces them.

The threat model must be extended before enabling a second issuer, another
tenant per deployment, a service mesh, another adapter, mount writes, media, MCP
sampling/elicitation or payload-write mediation, application
encryption/deduplication, multi-root/RWO storage, or online backup.
