<!-- SPDX-License-Identifier: Apache-2.0 -->

# Namespace and Authorization

This specification defines FileBelt's shared tenant, identity, session,
namespace, Virtual ACL, sharing, retention, and revocation contract. Browser,
API, worker, and adapter entry points must resolve an internal principal and
apply this model; host users, external identity claims, and filesystem ownership
are never authorization inputs by themselves.

## Tenancy, principals, and drives

All persisted identifiers and relationships are tenant-scoped. One tenant is
supported per deployment. Internal principals include users, flat local groups,
organizations, services, and bounded session/share identities. A drive may be
owned by a user, group, organization, or service principal; a transient device,
session, or share-link principal cannot own one.

A user's first successful login idempotently creates the internal user,
principal, private drive, and drive root. Client collections such as `My Drive`,
`Shared with me`, and `Shared drives` are views over stable drive and node UUIDs,
not additional namespace nodes. When a visible drive label collides under the
namespace comparison rules, append a parenthesized lowercase owner UUID prefix,
starting at eight hexadecimal characters and extending in four-character
increments until unique.

## Logical namespace

Each drive is a strict rooted tree. Every node other than the drive root has one
parent. Hard links, symbolic links, device nodes, sockets, and FIFOs are not
supported. Logical names never become physical storage paths, and payload
objects use UUID locators rather than user-controlled names.

Every component is processed as follows:

1. Require valid UTF-8 and normalize the display value to Unicode NFC.
2. Reject an empty value, `.` or `..`, NUL, ASCII control characters, `/`, `\`,
   `<`, `>`, `:`, `"`, `|`, `?`, or `*`.
3. Reject a trailing space or dot.
4. Reject the case-insensitive Windows device basenames `CON`, `PRN`, `AUX`,
   `NUL`, `COM1` through `COM9`, and `LPT1` through `LPT9`, including those
   basenames followed by an extension.
5. Derive the sibling comparison key with full, non-Turkic Unicode default case
   folding of the NFC value. Enforce one active key per tenant, drive, and
   parent, and reject a normalization or case-fold collision without rewriting
   the requested display value.

After normalization, a component is limited to 255 UTF-8 bytes. A complete
absolute logical path is limited to 4,096 UTF-8 bytes and 128 components below
the root. Protocols with stricter limits reject the write before persistence.
Rename and move stay within one drive; cross-drive move is unsupported rather
than an implicit copy-and-delete.

The root is a real authorization resource, not an implicit ancestor outside
the tree. An exact-node grant applies only to that node; a recursive grant is
evaluated continuously against every descendant that it would affect. Tree
integrity permits neither a root parent nor a self-parent, and a move rejects a
destination in the moved node's transitive descendant set. Those root, exact,
and transitive cycle rules are enforced before persistence and remain bounded
by the 128-component/4,096-byte logical-path limits.

The normalization and case-fold Unicode data versions are pinned by the domain
dependencies. Updating either version requires collision analysis, a
data-preserving migration, compatibility and rollback documentation, and an
update to this specification.

## OIDC identity and administration

Each deployment configures one standards-compliant OIDC issuer. An external
identity is the exact `(issuer, subject)` pair; FileBelt does not link accounts
by email, display name, or OIDC group claim. Each user has one external identity,
and aliases and account merging are unavailable.

Login uses authorization code flow with PKCE, state, and nonce. Only an
`email_verified=true` claim may update the normalized email used to resolve a
direct share. The confidential client prefers `client_secret_basic`, accepts
`client_secret_post`, uses `client_secret_basic` when discovery omits the field,
and fails startup if discovery advertises neither supported method.

Tenant administrators are selected by a configured exact `(issuer, subject)`
allowlist; the first user receives no implicit administrator authority. The
administrator role controls users, local groups, shared drives, sessions, and
quotas, but does not bypass Virtual ACL or confer private-drive content access.
Local suspension is authoritative: it prevents login, revokes local sessions,
and blocks identity linkage even if IdP disablement is not observable.

The current public API exposes user-owned session management but no
tenant-administrator mutation endpoints. UI administration controls that lack a
server contract remain unavailable; their presence must not be mistaken for an
implemented authority path.

Local groups are flat. A membership is either `member` or `manager`. Managers
maintain membership and exercise the fixed owner authority of a group-owned
drive; members receive only rights from applicable ACL grants.

## Browser sessions

FileBelt issues a 256-bit opaque session secret and persists only its
domain-separated keyed digest. The session cookie is host-only, `Secure`,
`HttpOnly`, `SameSite=Lax`, scoped to `/api/v1`, and bounded by a 12-hour idle
limit and seven-day absolute limit. Authentication rotates the session, and
users may list their sessions and revoke one or all of them. FileBelt stores no
OIDC refresh token, so an issuer outage does not silently extend or revoke an
already-issued local session.

Unsafe requests require the response-delivered CSRF value, its matching
`SameSite=Strict` cookie, the configured exact `Origin`, and same-origin Fetch
Metadata. Tenant-administrator mutations, permanent purge, global session
revocation, and key-sensitive operations require an OIDC authentication no
more than ten minutes old; deployments may additionally require an ACR.

OIDC discovery and JWKS freshness is bounded to 24 hours. Previously known keys
may be used during an issuer outage for at most one additional 24-hour window.
An unknown key ID, newly required discovery, signature uncertainty, or failed
issuer, audience, nonce, or time validation fails closed.

## Virtual ACL

The stable action vocabulary independently represents metadata and child
listing, content reads, child creation, content writes, version creation,
rename, move, delete, restore, attribute changes, sharing, ACL management,
drive management, transcode, external editing, MCP use, mounts, and export.
`WRITE_CONTENT` does not imply `CREATE_VERSION`; `SHARE` does not imply
`MANAGE_ACL`.

Drive-owner authority is fixed outside the ACL entry set. A user,
organization, or service owner, and a manager of a group-owned drive, receives
owner authority that an ACL entry cannot target, deny, delegate, or remove. For
all other evaluations:

1. Resolve authenticated input to a tenant-scoped internal principal.
2. Collect applicable direct, group, and inherited entries along authoritative
   resource ancestry.
3. Apply inheritance as `this resource`, `children`, or `descendants`.
4. Make any applicable deny override every applicable allow; a child allow
   cannot override an inherited deny.
5. Default to deny when no grant applies.
6. Reject a delegated action unless the actor currently holds every requested
   action and the required `SHARE` or `MANAGE_ACL` authority. Never trim a
   requested grant and never delegate ownership.
7. Evaluate historical versions against the current node ACL.
8. Return the same existence-hiding `404` used for a missing object when an
   object lookup is unauthorized.

The permission presets expand before persistence:

- Viewer: `READ_METADATA`, `LIST_CHILDREN`, and `READ_CONTENT`.
- Contributor: Viewer plus `CREATE_CHILD`, `WRITE_CONTENT`, `CREATE_VERSION`,
  `RENAME`, `MOVE`, `DELETE`, `RESTORE`, and `SET_ATTRIBUTES`.
- Manager: Contributor plus `SHARE` and `MANAGE_ACL`.

`MANAGE_DRIVE` is not part of the Manager preset. Advanced per-action editing
requires `MANAGE_ACL` and remains subject to strict attenuation. An exact
advanced-ACL replacement requires the actor to hold `MANAGE_ACL` and every
action in both its submitted rows and any existing non-share advanced rows it
removes by omission, regardless of effect or inheritance. An empty replacement
therefore clears advanced rows only when the actor holds every removed action.

ACL, membership, namespace, resource, and session generations qualify an
authorization result. Relevant changes advance generations in the same
PostgreSQL transaction, and mutations revalidate authority in their
transaction. Capabilities and open byte streams recheck their narrow generation
projection no less often than every 60 seconds. Iggy may prompt an earlier
check, but database uncertainty or missing notification delivery never permits
access.

Direct-share attenuation is equally continuous. Creation of a recursive
(`self_and_descendants`) direct share checks `SHARE` and every preset action at
the share root. Each later recipient authorization independently requires the
creator to hold both `SHARE` and that requested action at the exact resource
being accessed; the drive root is not an exception. Losing only one action
suppresses only that action, and access automatically resumes if the creator's
authority returns; the configured share row is not rewritten. Exact-node
(`self`) shares remain durable independent roots and never grant descendant
access. Owner and group-owner-manager rights, advanced ACL grants, and
exact-node shares are independent proof roots. A transitive recursive-share
chain is valid only when it reaches such a root, so a rootless cycle confers
nothing while a rooted cycle may succeed. Evaluation is bounded to 128
delegation levels and 4,096 relevant recursive edges; either overflow fails
authorization closed and emits only a low-cardinality reason.

## SMB and explicit-FTPS mount authorization

Mount access is an optional, read-only projection of the same logical
namespace and Virtual ACL. It introduces no filesystem user, ownership rule,
or parallel permission model. Every gateway authentication resolves a random,
protocol-specific credential to one internal user principal. Every path
component is then resolved through the VFS below one selected drive root, and
each list, metadata, open, read, lock, and close operation revalidates the
current credential, policy, device, session, drive, namespace, membership,
resource, and ACL generation fences in PostgreSQL. Unauthorized and missing
objects use the same existence-hiding result.

A principal owns one policy revision per protocol. A policy is disabled by
default, selects at most 256 currently accessible drives, and is read-only in
this release. Enabling or replacing a policy advances its authorization
generation and revokes every credential and active session issued under the
previous revision. Credential creation requires a browser session with OIDC
authentication no more than ten minutes old. FileBelt returns the random
username and password exactly once, stores only an envelope-encrypted verifier,
and never accepts the principal's FileBelt or OIDC password at a gateway.

A credential may optionally bind to one current Headscale device. Device
identity is the exact OIDC issuer and subject resolved to an already active
FileBelt user; email, display name, Headscale tags, service nodes, and host
UID/GID never establish ownership. The synchronization role validates a whole
Headscale node snapshot before replacing device observations atomically.
Malformed, duplicate, expired, tagged, service, or unresolvable nodes cannot
partially refresh authority. A device disappearance or ownership change
advances its fence and closes dependent access on the next operation.

Gateway instances identify themselves over mTLS and hold a PostgreSQL-backed
epoch. Restarting or retiring a gateway advances that epoch so an opaque
adapter session cannot be replayed at another instance. Open handles are
session-scoped, share-mode conflicts and byte-range locks are authoritative in
PostgreSQL, and session idle/absolute expiry is checked on every operation.
No mount authorization depends on Headscale packet delivery, Iggy delivery, or
an adapter-local path or UUID cache.

## Markdown editing and collaboration authorization

Markdown editing introduces no Virtual ACL action. Opening or participating in
a collaboration room requires both `READ_CONTENT` and `WRITE_CONTENT`; there
is no read-only spectator membership. Saving the room as an immutable version
also requires `CREATE_VERSION`. Discarding dirty room state requires `DELETE`
and `WRITE_CONTENT`, and copying a document requires `CREATE_CHILD` on the
destination parent. These checks are made from the current ACL, rather than
from a browser tab, transport connection, or possession of a collaboration
grant.

A room grant is a one-use, opaque 60-second credential bound to tenant,
principal, session, drive, node, room epoch, and the ACL, membership, and
namespace generations observed at issuance. It is presented only as the first
Protobuf frame over WebSocket; neither a grant nor a session value is placed in
a URL. WebTransport is not deployed in Phase 5. The collaboration role
revalidates this binding on admission and at least every 60 seconds thereafter.
Any authorization or namespace change freezes the room before it can accept a
further update. The final object, manifest/checkpoint, and explicit discard
transactions lock the participant session and exact generation projection; the
discard route also requires matching `DELETE` and `WRITE_CONTENT` grants. A
revalidation race therefore cannot create an acknowledged update or discard
dirty state. Iggy can shorten detection latency but is never authorization or
revocation authority.

An external committed head change freezes rather than merges a dirty room.
Participants review the preserved dirty document against the immutable base
and new head using a deterministic diff3 workflow, then explicitly save a new
expected-head version or discard it. Offline state is local to a live tab only:
the service does not persist, synchronize, or authorize an offline draft until
the tab reconnects and passes current authorization.

## External document-session authorization

`document_session` is a non-human principal kind used only to fence an active
external-editor session. It never owns a drive, authenticates at OxiBelt, or
inherits the authority of a user. A session is shared for one provider, node,
and exact immutable base version; each browser tab is represented by its own
participant bound to the initiating user and API session.

All modes require `READ_CONTENT` and `USE_EXTERNAL_EDITOR`. `comment`,
`review`, and `edit` also require `WRITE_CONTENT` and `CREATE_VERSION`, while
`comment` and `review` additionally require their matching stable `COMMENT`
or `REVIEW` action. These actions participate in the ordinary deny-precedence,
inheritance, delegation-attenuation, and generation rules. A preset expansion
materializes the new action rows in one statement and advances each affected
resource generation once.

The document service records the membership, drive ACL, namespace, and
resource ACL generations for every participant. Admission, each capability
issue, and the final version transaction re-evaluate the initiating principal
and API session against PostgreSQL. A disabled user, revoked API session,
changed ACL or membership, deleted or quarantined node, expired session, or
uncertain database result denies new byte access and commits within 60 seconds.
One-use launch grants are opaque, stored only as keyed digests, expire after 60
seconds, and cannot be exchanged by another principal or reused.

The initial release admits authenticated users only. Anonymous links and
guests are not document participants. Presence uses an opaque principal ID and
display name; emails and provider account identifiers are not disclosed.
Twenty active or reconnecting participants is the fixed provider-wide ceiling.
An owner may revoke their own participant; a fixed drive owner or a principal
with `MANAGE_ACL` may list or force-close all sessions for a node. Closing a
session revokes future capabilities but never deletes an immutable version.

Document saves use optimistic expected-head semantics. A provider revision may
commit exactly one immutable version when the current node head still matches
the session expectation. If another Web, Markdown, SMB, FTPS, or document path
advanced the head, the session becomes conflicted and the produced bytes are
retained for seven days. They never overwrite or merge the newer head. The
owner may explicitly create a separately named sibling after independent
`CREATE_CHILD` authorization, or discard the retained output.

## MCP principals, approvals, and data grants

An MCP registration is owned by exactly one internal user or service principal
within the tenant. A personal registration belongs only to its user. A managed
registration is derived from one administrator-owned template assigned to an
exact user, group, or service principal; assignment never gives a tenant
administrator implicit access to that principal's private-drive content.
Service identities bind one internal service principal to an exact SPIFFE URI
within an operator-configured trust domain. Deleting or suspending the service
revokes its grants, disables its registrations, and advances authoritative
generations.

Discovery creates an immutable capability snapshot. Approval decisions bind to
the snapshot and each exact capability fingerprint; tool names, remote
annotations, and descriptions are untrusted display data. A registration is
usable only when validation, authentication, capability review, quarantine,
enablement, and revocation state all allow it. Registration, template, service,
capability, or global-block changes invalidate affected authority in
PostgreSQL; Iggy is not involved in that decision. Every administrator block
mutation advances a tenant block generation and cancels active MCP invocations
in the same transaction. Every registration credential or configuration
generation change also revokes registration-bound data grants and pending
approvals, supersedes capability snapshots, revokes their reviews, deletes
pending OAuth attempts, and requires fresh discovery/review before enablement.

Interactive invocation uses a five-minute intent whose server-held digest binds
the current principal and session, application ID, registration, primitive,
capability fingerprint, canonical arguments, and attachments. The user then
creates an approval from that intent. The browser never supplies a keyed digest
or silently approves. A one-shot approval is consumed atomically; a saved
session approval is allowed only within its exact binding and expires within
one hour. Replaying an intent, changing its request, using another session, or
encountering stale authority fails closed.

MCP data access is separate from server authentication. An exact node data
grant binds the destination registration, current principal, drive, node,
immutable version, permitted `READ_METADATA` and/or `READ_CONTENT` disclosure,
ACL and namespace generations, and an expiry of no more than 30 days. The
broker re-evaluates current Virtual ACL and generations before transfer. A new
file head is not implied by a grant to an older version, and MCP output cannot
write payload storage directly. Attachments are explicit, non-recursive, and
limited to four; filenames, media types, sizes, and bytes are disclosed only
when separately selected.

Service invocation grants additionally bind the service identity, registration,
application ID, exact capability fingerprint, argument constraints, named MCP
data-grant IDs, an hourly quota, and a maximum 30-day expiry. They do not confer
drive ownership or bypass Virtual ACL. Revocation, suspension, expiry, quota
uncertainty, or a missing referenced data grant denies the operation.

## Phase 8 NFS and media authorization

NFSv4 access is an opt-in read-write projection of the same tenant, drive,
namespace, immutable-version, and Virtual ACL model. The stable action
vocabulary adds `TRAVERSE`. Every NFS lookup evaluates `TRAVERSE` on each
ancestor without implying `LIST_CHILDREN`; regular-file execute is represented
by `READ_CONTENT`. Phase 8 activation creates only managed traversal
projections needed to preserve previously reachable objects. It does not
weaken an existing deny or disclose an otherwise hidden sibling.

NFS authenticates with RPCSEC_GSS `krb5p` against an operator-managed external
KDC. A tenant administrator explicitly maps each Kerberos principal to one
FileBelt user. One user may retain multiple Kerberos aliases, but all aliases
share one append-only tenant-unique POSIX name, non-zero UID, primary group,
and GID; revoking an alias does not release or reassign that identity. The
forward migration rejects an existing user's inconsistent alias identities
with an actionable inventory instead of choosing one silently. Flat local
groups remain explicit. `AUTH_SYS`, host ownership, Kerberos root, and numeric
ID zero confer no authority. The immutable NFS `other` projection contains all
mapped NFS users in the tenant. Mapping mutations require recent OIDC
authentication, advance their generation, audit the exact change, and close
affected sessions.

One export represents one selected drive at `/filebelt/<drive_uuid>`. Mode and
NFSv4 ACL changes replace only tagged NFS-managed ACL rows and are rejected
when the requested projection would remove or rewrite owner, inherited,
share-native, or deny entries. `chown` additionally requires current
`SET_ATTRIBUTES` and `MANAGE_ACL`, an existing mapped target, and ordinary
delegation attenuation. Hard links, devices, sockets, FIFOs, setuid, setgid,
and sticky bits are unsupported. Logical symlinks and `user.*` attributes are
stored as metadata; other `system.*`, `security.*`, and `trusted.*` attributes
are rejected except synthesized POSIX ACL views.

Create, mkdir, and symlink requests may carry ordinary permission bits only;
Core applies `0644`, `0755`, and `0777` respectively when mode is omitted.
Ownership always comes from the authenticated mapped session. Client-supplied
owner/group attributes, special bits, and any unsupported initial attribute
are rejected rather than ignored.

NFS holds at most one active staged writer per node, but it never blocks a Web,
MCP, Markdown, document, SMB, or FTPS version commit. `COMMIT` and final dirty
`CLOSE` attempt an immutable version with the head captured when staging began.
A changed head yields a retained seven-day conflict rather than overwrite.
Dirty state abandoned without COMMIT or final CLOSE never becomes a version.
Open-unlinked objects remain readable through existing handles; a dirty final
close is retained as conflict data and cannot resurrect the removed name.
The owning principal may list an unexpired retained conflict, copy its bytes
to a newly authorized parent as a new immutable file, or discard it into the
fenced cleanup state machine. Copy requires current `CREATE_CHILD` and exact
parent generations; neither operation exposes a physical locator.

Media cache access never grants content authority. A READY cache hit requires
current `READ_CONTENT`; creating a missing derivative also requires
`TRANSCODE` and explicit browser confirmation. The initiating API session and
both actions are rechecked no less often than every 60 seconds and before each
manifest publication. Revocation cancels the attempt and fences unpublished
output. Drive managers may inspect and evict rebuildable cache entries but do
not thereby gain access to source or derivative bytes.

## Sharing, trash, audit, and availability

Direct sharing resolves only an already-linked principal by its current
verified normalized email. The stored grant targets the immutable principal ID,
and failed resolution discloses no account detail. There are no pending
invitations.

Only direct shares are available. `group` and `link` remain reserved public
schema values and fail with `share.kind_unsupported`; the authenticated UI does
not offer them. `/public/share` is a reserved, fail-closed browser shell: it
removes a fragment token from browser history, but the production client has no
anonymous exchange or download implementation and reports the feature as
unavailable. No `/public/v1` application contract is implemented, and public
routes must never receive an authenticated session cookie.

Following the descendant-share security cutover, each tenant has a durable
admission gate. It starts blocked, rejects all new direct-share creation and
new MCP data-grant creation, and returns the stable API problem codes
`share.remediation_in_progress` and
`mcp.data_grant.remediation_in_progress` while closed.
The repair revokes every active recursive direct share and every active MCP data
grant created before that tenant's repair fence, retaining a per-row reason and
operation identifier. It deletes linked direct-share ACL rows, advances their
authorization generations, records transactional invalidations and audit
evidence, and is idempotent/resumable in batches of at most 1,000 total rows.
Only an explicitly verified repair run and a tenant-admin activation reopen the
gate; neither Helm rollback nor an older API image changes that state.

Trash retention defaults to 30 days. A private-drive user may choose 1 through
90 days; a shared-drive owner or tenant administrator chooses one drive policy.
Deletion snapshots the effective period and original parent/name. Restore
fails on a live-name collision, and permanent purge records deletion intent
before garbage collection.

Sensitive audit records are durable for 365 days by default, configurable from
30 through 3,650 days. The user-visible Privacy subset covers 90 days and
includes local suspension, forced session revocation, forced group-membership
changes, and quota reductions. Notifications are best effort and never replace
the audit record.

Raw session, CSRF, OIDC-attempt, share, password, and capability material must
not enter URLs, logs, traces, metrics, audit descriptions, or diagnostics. See
the [Threat Model](ThreatModel.md) for the security objectives and required
evidence.
