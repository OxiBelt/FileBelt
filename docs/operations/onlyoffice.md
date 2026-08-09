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

1. Apply migration `000006_phase7_documents.sql`, then the release-matched
   `grants.sql`; run `filebeltctl database verify-grants` while document
   admission remains disabled.
2. Generate a distinct Ed25519 generation-4 capability key. Mount the private
   key only into `filebelt-document` and add the public key to the I/O worker's
   verified keyset. Do not reuse API, collaboration, mount, OIDC, or provider
   JWT keys.
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
6. Create separate current provider-outbox and browser-config JWT secrets of
   at least 32 random bytes. If rotating the outbox verifier, mount one retiring
   secret with an expiry no more than 30 minutes ahead. Never store any of these
   secrets in Helm values or a ConfigMap. Advance the chart's external
   provider-configuration generation whenever its ConfigMap content changes so
   every adapter replica rolls to the same reviewed configuration.
7. Verify the adapter image labels, SBOM, signature, provenance, AGPL license,
   immutable corresponding-source URL, build instructions, notices, and exact
   source/about endpoint response. Verify the operator-supplied provider
   independently.
8. Configure OxiBelt's fixed adapter route with write retries and caching
   disabled. Admit only the expected launch, input, callback, source/about, and
   health paths; strip client-supplied internal identity headers.

## Activation and acceptance

Enable the Apache document coordinator first, with no adapter route. Exercise
its contract fixture for exact-version range reads, one whole-revision write,
fsync/finalize, no-op save, expected-head commit, duplicate event, lost
response, restart reconciliation, participant capacity, ACL/session revoke,
and conflict retention. Then install the isolated adapter chart and enable its
route.

Before user traffic, exercise a real or contract-faithful DocumentServer flow:

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
  FileBelt session and contain no secret or user data; and
- removing every ONLYOFFICE component leaves login, Web files, Markdown, MCP,
  and ordinary upload/download behavior healthy.

## Rotation, drain, and rollback

Rotate provider JWT secrets by mounting a new current generation and at most
one retiring generation, restarting adapter replicas, verifying both during the
bounded overlap, then removing the retiring secret after 30 minutes. Rotate
mTLS and generation-4 capability keys with the ordinary overlapping-public-key
procedure; do not remove a public key while an unexpired capability or recovery
checkpoint references it.

For planned drain, stop new API handoffs, let active callbacks finish, force
close sessions that exceed the grace period, and inspect all `staging`,
`staged`, `committing`, and `conflict` revisions. Scale the adapter to zero
before the document coordinator. Maintenance must continue reclaiming expired
grants and retained outputs.

Rollback removes the OxiBelt route first and sets `documents.enabled=false`.
Restore the previous verified adapter and coordinator digests only when they
understand migration 000006 and capability generation 4. Do not run a down
migration, drop `filebelt_document`, delete retained conflict bytes, remove
source/notices, or repoint an immutable release tag. If compatibility is
uncertain, remain disabled and restore a coordinated PostgreSQL/payload
checkpoint into fresh targets before migrating forward.
