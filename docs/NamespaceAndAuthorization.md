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
requires `MANAGE_ACL` and remains subject to strict attenuation.

ACL, membership, namespace, resource, and session generations qualify an
authorization result. Relevant changes advance generations in the same
PostgreSQL transaction, and mutations revalidate authority in their
transaction. Capabilities and open byte streams recheck their narrow generation
projection no less often than every 60 seconds. Iggy may prompt an earlier
check, but database uncertainty or missing notification delivery never permits
access.

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
