<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0008: Identity, sessions, and Virtual ACL

- Status: Accepted
- Date: 2026-08-06
- Owners: `@PiQuark6046`
- Reviewers: none
- Supersedes: none
- Affected license regions: Apache-2.0 and protocol consumers

## Context

Phase 2 introduces persisted users, groups, browser sessions, shares, and the
first enforcement of FileBelt's common Virtual ACL. Host identities, OIDC
claims, email addresses, cookies, share tokens, and adapter credentials are
untrusted until they resolve to an internal tenant-scoped principal. A
different rule at any entry point would create an authorization bypass.

## Decision drivers

- Preserve one policy model for browser, API, worker, and future adapter paths.
- Make revocation bounded even when Iggy or a process-local cache is down.
- Avoid account takeover through mutable OIDC claims or email addresses.
- Give administrators control-plane capabilities without implicit access to
  user content.

## Decision

### Identity and administration

Phase 2 supports one tenant and one standards-compliant OIDC issuer per
deployment. Every persisted identifier and relationship is tenant-scoped.
External identities are keyed by the exact `(issuer, subject)` pair and each
user has one external identity; aliases and account merging are deferred.

OIDC uses authorization code with PKCE, state, and nonce. A successful first
login idempotently creates the internal user, principal, private drive, and
root. Only `email_verified=true` may update a user's normalized share-resolution
email. OIDC group claims do not create membership or rights.

The confidential client negotiates token-endpoint authentication from provider
metadata. It prefers `client_secret_basic`, accepts `client_secret_post`, and
fails startup when neither is advertised. An omitted metadata field uses the
OIDC Discovery default, `client_secret_basic`.

An operator configures the exact `(issuer, subject)` tenant-administrator
allowlist before bootstrap. There is no first-user administrator rule. Tenant
administrators may manage users, local groups, shared drives, sessions, and
quotas, but do not bypass Virtual ACL, grant themselves private-drive access,
or gain break-glass content access.

IdP disablement is not assumed to be observable. FileBelt therefore provides
an authoritative local suspend/resume state. Suspension revokes local sessions
and prevents login or identity linkage. Local groups are flat. Membership has
`member` and `manager` roles; managers maintain membership and exercise the
non-removable owner rights of a group-owned drive, while ordinary members gain
only explicitly applicable grants.

### Browser sessions

FileBelt issues an opaque 256-bit session token and stores only a domain-
separated keyed digest. The cookie is `Secure`, `HttpOnly`, `SameSite=Lax`,
host-only, and scoped to authenticated application routes. Unsafe requests
also require an in-memory or response-delivered CSRF token and valid
`Origin`/Fetch Metadata checks. Session identifiers rotate after login and
privilege changes.

The defaults are a 12-hour idle limit and a seven-day absolute limit. Users
can list and revoke an individual session or all sessions. FileBelt stores no
OIDC refresh token. Existing local sessions remain valid according to their
own state and expiry when the issuer is unavailable.

OIDC discovery and JWKS follow issuer freshness up to 24 hours. During an
outage, already known keys may remain usable for no more than an additional
24 hours. An unknown `kid`, a newly required discovery result, signature
uncertainty, or issuer/audience/time validation failure fails closed.

Tenant-admin mutations, permanent purge, global session revocation, and
key-sensitive operations require an OIDC authentication whose `auth_time` is
no more than ten minutes old. Operators may additionally require an ACR; Phase
2 does not require a particular MFA claim.

### Virtual ACL

The authorization action set keeps reading metadata/listing/content, creating
children, writing content, creating versions, renaming, moving, deleting,
restoring, changing attributes, sharing, managing ACLs, and managing a drive
independent. In particular, `WRITE_CONTENT` does not imply `CREATE_VERSION`,
and `SHARE` does not imply `MANAGE_ACL`.

Owner authority is an invariant outside the ACL entry set: an ACL entry cannot
target, deny, delegate, or remove the ownership actions of a user owner or a
manager acting for a group-owned drive. For every other evaluated action, the
evaluator applies these rules:

1. resolve the authenticated input to an internal principal;
2. collect direct, group, and inherited entries for the resource ancestry;
3. make any applicable deny override every applicable allow;
4. never allow a child entry to override an inherited deny;
5. reject a grant unless every delegated action is currently held by the
   actor; never silently trim a grant and never delegate owner status;
6. evaluate historical versions using the current node ACL; and
7. return an existence-hiding `404` for an unauthorized object lookup.

The UI presets are:

- Viewer: metadata, list, and content read;
- Contributor: Viewer plus create, write, create-version, rename, move,
  delete, restore, and attributes; and
- Manager: Contributor plus share and manage-ACL.

`MANAGE_DRIVE` is never included in the Manager preset. An actor with
`MANAGE_ACL` may use an advanced per-action editor, subject to attenuation.

ACL and group membership changes advance tenant/resource generation values in
the same PostgreSQL transaction. Mutations revalidate authorization inside
their transaction. Capability admission and open streams compare their
generation projection at intervals no longer than 60 seconds; Iggy may prompt
an earlier check but is never required for correctness. Database uncertainty
fails closed.

Recursive operations authorize each affected node against one captured
generation snapshot. At most 1,000 nodes commit atomically in the request.
Larger operations use a fenced durable job, revalidate before commit, and make
one all-or-nothing metadata transaction.

### Sharing, trash, and privacy

A direct share resolves only an already-linked principal using the current
verified normalized email. The resulting grant is bound to the principal ID;
failures disclose no account details and Phase 2 creates no pending invite.

Phase 2 enables direct shares to linked principals only. Group and anonymous
link kinds are reserved in the public schema but fail closed as unsupported;
the production UI does not offer them. Before anonymous links can be enabled,
an accepted follow-up must define metadata/listing scope, expiry, password
handling, keyed token digests, rate limiting, immediate revocation, isolated
fragment exchange, path-scoped cookies, CSP, referrer policy, and redacted
logging. Public-share routes must never receive an authenticated session
cookie.

Trash defaults to 30 days. A user may choose 1--90 days for a private drive; a
shared-drive owner or tenant administrator chooses one drive policy. The
effective period and original parent/name are snapshotted at deletion. Restore
fails on a live-name conflict. Permanent purge records deletion intent before
garbage collection.

Sensitive audit records are durable for 365 days by default and configurable
from 30 to 3,650 days. The user's Privacy view shows the applicable subset for
90 days, including local suspension, forced session revocation, forced group
membership changes, and quota reductions. In-app notification is best effort
and does not replace the audit record.

## Alternatives considered

Trusting email as the external identity was rejected because it is mutable.
OIDC refresh-token storage was rejected to reduce credential exposure. OIDC
group synchronization, nested groups, ACL conditions, and first-user
administration were deferred because each adds an independent authority or
recovery policy. Tenant-admin content bypass was rejected because it silently
collapses the control-plane/content-plane boundary.

## Consequences

Every service and future adapter must provide the same internal principal,
resource ancestry, and generation inputs to `filebelt-authz`. Revocation may
take up to the configured 60-second bound for an already open byte stream, but
new mutations are immediately protected by transactional revalidation.

Ownership transfer, multiple issuers, identity aliases/merge, nested and
dynamic groups, ACL conditions, and automatic IdP deprovisioning require later
decisions.

## Security, data, and license analysis

Session, CSRF, OIDC-attempt, share, and password material are secrets. Logs,
traces, metrics, audit descriptions, URLs, and proxy access logs must not
contain raw values. Argon2id is used only for low-entropy share passwords;
high-entropy tokens use domain-separated keyed digests.

The model is implemented in Apache-2.0 domain and authorization packages and
contains no provider SDK, SQL, HTTP, browser, adapter, or Iggy types.

## Verification

- Table/property tests cover deny precedence, inheritance, owner invariants,
  attenuation, group managers, presets, and reason codes.
- PostgreSQL tests cover tenant isolation, generation increments, concurrent
  grants, suspension, and append-only audit.
- OIDC/session tests cover PKCE, state, nonce, callback allowlists, claim and
  JWKS validation, CSRF, rotation, expiry, and revocation.
- Browser and API tests prove direct/group/link sharing, privacy visibility,
  existence hiding, and bounded revocation of an active download.

## Rollout and rollback

Apply additive identity and ACL migrations, bootstrap the tenant, configure
the administrator allowlist, and only then admit interactive login. Roll back
within the schema compatibility window by disabling new login and writes,
revoking active sessions and capabilities, and deploying the previous
compatible binary. Persisted data is never reset; incompatible repair moves
forward under ADR-0005.

## Open questions

None.
