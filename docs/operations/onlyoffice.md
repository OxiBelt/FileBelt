<!-- SPDX-License-Identifier: Apache-2.0 -->

# ONLYOFFICE integration operations

## Support boundary

The integration is optional and disabled by default. The Apache
`filebelt-document` coordinator and the separately released AGPL
`filebelt-onlyoffice-adapter` are supported only with an operator-supplied
ONLYOFFICE Docs Community `9.4.0` instance. FileBelt does not install,
redistribute, cluster, back up, or upgrade DocumentServer or its database. The
operator must preserve upstream branding, publish the provider's corresponding
source and notices, record its exact image digest, and respect the Community
20-simultaneous-connection limit.

The initial format set is DOCX, XLSX, and PPTX, each at most 100 MiB. Sessions
last at most 24 hours, reconnect for at most 100 seconds, and reauthorize within
60 seconds. A conflict never overwrites the current FileBelt head.

## Preflight

1. Apply migrations through `000010_onlyoffice_origin_isolation.sql`, then the
   release-matched `grants.sql`; run `filebeltctl database verify-grants` while
   document admission remains disabled. If an
   earlier deployment exposed the editor shell on the FileBelt public origin,
   first stop every old API, coordinator, adapter, and edge binary that can
   admit or mint a document launch. Verify the migration's
   `onlyoffice_origin_isolation_v1` receipt and the corresponding privacy-visible
   audit rows before starting a replacement binary; a deployment with no prior
   document state records zero affected sessions. The cutover revokes affected
   live API sessions, so those users must authenticate again.
2. Generate a distinct `document-storage` Ed25519 purpose at local generation
   1. Mount its private/public pair only into `filebelt-document` and its
   public keyset into I/O. The strict v2 keyset carries
   `purpose=document-storage`; do not reuse API, collaboration, mount, media,
   OIDC, or provider JWT keys.
3. Provision distinct TLS 1.3 identities for API-to-document,
   adapter-to-document, adapter-to-I/O, OxiBelt-to-adapter, and
   adapter-to-egress-gateway traffic. Configure exact URI/DNS SAN allowlists.
4. Create and label the integration namespace separately. The adapter chart
   must not create it. Enforce the restricted Pod Security Standard and inspect
   the default-deny NetworkPolicies before creating any route.
5. Configure the provider at one exact HTTPS origin and set
   `.Values.documents.providerOrigin` to that same origin. It must contain no
   credentials, path, query, or fragment; FileBelt returns this non-secret
   value for pre-launch consent. The egress gateway must allow only that
   origin, reject all redirects and private/link-local/metadata addresses after
   every DNS lookup, and stream under the 100 MiB and timeout limits. Prove
   direct adapter Internet egress is denied.
6. Provision a second FileBelt-controlled DNS name for the editor shell and set
   `.Values.documents.launchAction` to exactly
   `https://<editor-host>/onlyoffice/launch`. Its hostname must differ from the
   FileBelt public and DocumentServer hostnames; a different port on either host
   is not acceptable isolation. Use the existing FileBelt public TLS Secret with
   one certificate whose SANs cover both FileBelt hostnames. Configure the
   adapter's `public_origin`, `launch_origin`, and `document_server_origin` to
   those same pairwise-distinct values.
7. Create separate current provider-outbox and browser-config JWT secrets of
   at least 32 random bytes. If rotating the outbox verifier, mount one retiring
   secret with an expiry no more than 30 minutes ahead. Never store any of these
   secrets in Helm values or a ConfigMap. Advance the chart's external
   provider-configuration generation whenever its ConfigMap content changes so
   every adapter replica rolls to the same reviewed configuration.
8. Verify the adapter image labels, SBOM, signature, provenance, AGPL license,
   immutable corresponding-source URL, build instructions, notices, and exact
   source/about endpoint response. Verify the operator-supplied provider
   independently.
9. Configure OxiBelt's two fixed adapter virtual hosts with write retries and
   caching disabled. The public host admits only input, callback, source/about,
   and health paths. The editor host admits only `POST /onlyoffice/launch` and
   `GET /onlyoffice/launcher.js`; it has no API route. Strip client-supplied
   identity, session, CSRF, and forwarding authority at the editor boundary
   while preserving external Host and Origin for the adapter's exact checks.

## Activation and acceptance

Enable the Apache document coordinator first, with no adapter route. Exercise
its contract fixture for exact-version range reads, one whole-revision write,
fsync/finalize, no-op save, expected-head commit, duplicate event, lost
response, restart reconciliation, participant capacity, ACL/session revoke,
and conflict retention. Then install the isolated adapter chart and enable its
route.

Before user traffic, exercise a real digest-pinned ONLYOFFICE Docs Community
`9.4.0` image in Chromium and Firefox. Record its digest, platform, upstream
source, notices, and vulnerability review outside FileBelt release subjects. A
contract-faithful fixture is useful negative evidence but does not satisfy this
compatibility gate. Verify all of the following:

- two authorized users co-edit one DOCX and produce one attributed immutable
  version;
- a read-only user cannot request comment/review/edit and receives no content
  beyond the exact authorized version;
- explicit user save, timer checkpoint, form submit, final save, close without
  changes, corruption, and force-save error map to their documented outcomes;
- duplicate, out-of-order, expired, cross-document, bad-algorithm, bad-key, and
  response-loss callbacks do not create a second version;
- advancing the FileBelt head through another client yields a seven-day
  conflict and leaves that newer head unchanged;
- private, link-local, metadata, DNS-rebinding, redirect, oversized, slow, and
  wrong-TLS output targets fail before bytes reach FileBelt storage;
- ACL removal, API-session revoke, account disable, and force-close deny new
  input capabilities and final commits within 60 seconds;
- `/onlyoffice/source` and `/onlyoffice/about` remain reachable without a
  FileBelt session and contain no secret or user data;
- the old public-host launch and launcher paths return `404`, the isolated
  editor hostname has no `/api/v1` route or API CORS authority, and a hostile
  provider-script fixture cannot read a FileBelt session or perform an API
  mutation;
- the launcher has no `Set-Cookie` or permissive CORS header, uses `no-store`,
  `no-referrer`, and framing denial, and its CSP contains exactly `sandbox
  allow-scripts allow-same-origin allow-forms allow-downloads allow-popups`
  without a broader sandbox token;
- real DOCX, XLSX, and PPTX editing plus provider download, print, and popup
  behavior work under that fixed CSP in both browsers; and
- removing every ONLYOFFICE component leaves login, Web files, Markdown, MCP,
  and ordinary upload/download behavior healthy.

## Rotation, drain, and rollback

Rotate provider JWT secrets by mounting a new current generation and at most
one retiring generation, restarting adapter replicas, verifying both during the
bounded overlap, then removing the retiring secret after 30 minutes. Rotate
mTLS and `document-storage` capability material with the ordinary overlapping-public-key
procedure; do not remove a public key while an unexpired capability or recovery
checkpoint references it.

For planned drain, stop new API handoffs, let active callbacks finish, force
close sessions that exceed the grace period, and inspect all `staging`,
`staged`, `committing`, and `conflict` revisions. Scale the adapter to zero
before the document coordinator. Maintenance must continue reclaiming expired
grants and retained outputs.

Rollback removes both OxiBelt adapter virtual-host route sets first and sets
`documents.enabled=false`.
Restore the previous verified adapter and coordinator digests only when they
understand migrations 000006 and 000010, the `document-storage` purpose, and the
isolated editor-origin contract. Never restore the public-host launcher or a
binary that can mint its action while documents are enabled. Do not run a down
migration, drop `filebelt_document`, delete retained conflict bytes, remove
source/notices, or repoint an immutable release tag. If compatibility is
uncertain, remain disabled and restore a coordinated PostgreSQL/payload
checkpoint into fresh targets before migrating forward.

This cutover assumes there is no known compromise of provider JavaScript. If a
provider-script compromise is suspected, keep reauthentication blocked and
rotate the FileBelt public origin and its browser credentials under a separately
reviewed incident procedure before admitting users; session revocation alone is
not evidence that previously exposed credentials were never copied.
