<!-- SPDX-License-Identifier: Apache-2.0 -->

# Phase 3 Kubernetes Threat Model

- Date: 2026-08-07
- Owner: `@PiQuark6046`
- Scope: repository and image supply chain, OIDC and browser sessions, tenant
  administration, namespace and Virtual ACL, REST and authenticated sharing,
  OxiBelt, capability-limited storage workers, PostgreSQL, UUID payload
  storage, durable jobs, optional Iggy, audit, Kubernetes 1.34-1.36,
  NetworkPolicy, backend mTLS, GHCR/Helm publication, and quiesced recovery
- Excluded: managed-cluster/provider internals, online backup, HA/PITR and
  numeric production RPO/RTO, adapters, MCP, media, Markdown editing,
  ONLYOFFICE, WebTransport, and application encryption

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
- Pull-request inputs cannot cross license regions, publish artifacts, or
  broaden a FileBelt Pod's privileges. Tag-only promotion publishes only
  previously validated immutable subjects.

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
```

OxiBelt terminates public TLS. Kubernetes API and I/O backends require TLS 1.3
client identity and are also isolated by NetworkPolicy. The API has PostgreSQL
access and signing keys but no payload mount. The I/O worker has the shared
payload mount, verification keys, and narrow database access but cannot mutate
namespace or ACL state. Maintenance uses a distinct database role and the same
RWX root. Iggy is an untrusted, at-least-once notification path.

The production namespace is one trusted FileBelt deployment and tenant.
Adjacent Pods and compromised public clients are hostile. The Kubernetes
control plane, cluster and node administrators, CNI, CSI/storage provider,
database operator, certificate issuer, OIDC issuer, and egress-gateway operator
remain powerful trusted parties. Namespace isolation does not protect against
a compromised node or cluster administrator. ServiceAccount tokens are absent
because no FileBelt workload needs the Kubernetes API.

## Threats and controls

| Threat | Control | Required evidence |
| --- | --- | --- |
| OIDC login injection, replay, or callback confusion | Exact issuer and callback allowlists; code+PKCE, state, nonce, signature, audience, and time validation | OIDC negative and replay tests |
| Public login requests exhaust PostgreSQL | Expired or consumed attempts are reclaimed under a tenant lock and active attempts have a fixed admission bound | Retention and admission-limit tests |
| Stale or malicious JWKS authorizes a new identity | Bounded 24-hour freshness plus 24-hour known-key outage window; unknown `kid` and new discovery fail closed | Rotation/outage/unknown-key tests |
| Mutable email takes over an account or share | Identity is exact issuer/subject; only verified email resolves an already-linked principal; grant stores principal ID | Identity collision and share-resolution tests |
| First login obtains deployment control | Explicit administrator issuer/subject allowlist and separate idempotent tenant bootstrap | Bootstrap and first-user tests |
| Administrator reads private content by role | Tenant administration is control-plane-only and receives no implicit content ACL | Cross-user admin isolation tests |
| Disabled IdP user retains access indefinitely | Authoritative local suspend/revoke; bounded local session expiry; no refresh token | Suspend and session-revocation tests |
| Session theft, fixation, or CSRF | 256-bit opaque token, keyed digest, Secure/HttpOnly/SameSite cookie, rotation, CSRF token, Origin and Fetch Metadata checks | Cookie, fixation, CSRF, and logout tests |
| Browser secret persists or leaks through a referrer | No raw session or capability token in browser storage; no-referrer and restrictive CSP; anonymous links remain disabled | Browser storage/referrer tests |
| ACL allow overrides a more restrictive ancestor | Except for non-removable ownership authority outside the entry set, applicable deny always wins and inherited deny cannot be overridden | Authorization table/property tests |
| Manager grants rights they do not have | Separate actions and strict delegation attenuation; reject rather than trim | Delegation property tests |
| Stale group or ACL cache extends access | Transactional generation advance; mutations revalidate; streams check at most every 60 seconds; uncertainty fails closed | Revocation and outage tests |
| Object existence leaks across ACL boundary | Unauthorized lookup uses indistinguishable `404`; share resolution is minimal-reveal | Cross-user response equivalence tests |
| Recursive operation skips a descendant check | One generation snapshot, per-node authorization, 1,000-node request bound, fenced durable path above it | Bulk race and rollback tests |
| Client or proxy forges an internal principal | Resolve local session only; strip identity/internal headers; never authorize from proxy identity metadata | Header-smuggling tests |
| Adjacent Pod connects directly to a backend | Namespace default-deny plus per-role allowlist; backend TLS 1.3 requires the exact OxiBelt API or I/O client URI SAN | Calico/Cilium denial and mTLS-negative tests |
| Compromised web client identity reaches the other backend | Separate client certificates and exact URI SAN allowlists for API and I/O; one retiring identity allowed only during rotation | Cross-upstream certificate and rotation tests |
| Kubelet cannot authenticate to an mTLS application listener | Separate low-information operations listener; never expose it publicly; metrics ingress restricted to configured monitoring peers | Probe and NetworkPolicy tests |
| Mutable Secret changes without a controlled restart | Existing key-filtered Secret projections plus an explicit generation in the Pod template; configuration and trust load only at startup | Secret/certificate rollout tests |
| ServiceAccount token or RBAC expands a compromised Pod | Per-role token automount disabled on ServiceAccount and Pod; no Role/Binding is rendered | Static manifests and `kubectl auth can-i` tests |
| API bypasses the OIDC egress allowlist | Dedicated OIDC HTTP client uses an explicit in-cluster CONNECT gateway; NetworkPolicy permits only its namespace/pod/port; gateway allowlists the issuer | Direct-Internet denial and gateway destination tests |
| DNS or external dependency addressing creates catch-all egress | Explicit DNS peer and dependency namespace/pod/IPBlock values; chart rejects IPv4/IPv6 default routes | Schema/helper and live policy tests |
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

## Audit and privacy

Audit all authentication/session/administrator activity, mutations, ACL/share
changes, download starts, conflicts, corruption, and
denials. Do not emit routine list results or chunk progress. Records contain
stable IDs and reason codes, not raw credentials or payload content. The
default durable retention is 365 days and the user-visible privacy subset is
90 days; operator configuration remains within ADR-0008 bounds.

## Residual risk

The single maintainer, cluster/operator plane, storage/database providers,
certificate issuer, egress gateway, and configured OIDC issuer remain
concentrations of trust. A compromised API signing key can issue byte capabilities until the key
generation is retired, although the claims and worker generation checks limit
scope and time. A storage or database administrator can deny service and may
observe unencrypted-at-application-layer data; encryption at rest is delegated
to the volume/provider.

Open byte streams can retain access for up to the configured 60-second check
interval. The Kubernetes recovery procedure proves a coordinated quiesced
restore into fresh targets, but it does not claim production availability,
online backup, PITR, HA, or an RPO/RTO. Standard NetworkPolicy cannot identify
an Internet FQDN, so OIDC depends on the correctness of the operator gateway.
Dependency scans, attestations, and signed source mappings reduce known
supply-chain risk but do not eliminate unknown vulnerabilities. Cargo Vet exemptions record
acceptance of the current locked graph rather than a complete source audit, so
their review debt remains until equivalent audit evidence replaces them.

The threat model must be extended before enabling a second issuer, another
tenant per deployment, a service mesh, a controller, an adapter, WebTransport,
MCP, media, application encryption/deduplication, multi-root/RWO storage, or
online backup.
