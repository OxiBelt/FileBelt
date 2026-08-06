<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security Policy

## Supported versions

Before FileBelt 1.0, security fixes are provided for the latest released minor
line. Older lines should upgrade to that line. The repository currently has no
production release.

| Version | Supported |
| --- | --- |
| latest `0.x` minor | Yes |
| older `0.x` minors | No |
| unreleased source | Best effort |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository. Do not file a
public issue or pull request containing exploitable details. Include affected
versions, deployment assumptions, reproduction steps, impact, and any proposed
mitigation. The project does not promise a contractual response SLA.

The maintainer will validate the report, coordinate a fix and advisory when
appropriate, and credit reporters who request attribution. Security fixes must
include regression coverage and upgrade or mitigation guidance.

## Review scope

Security review covers repository and release supply chain, identity and
Virtual ACL, tenant separation, storage integrity, protocol adapters, browser
rendering, integrations, secrets, Kubernetes isolation, and recovery behavior.
The Phase 2 core exposes an OIDC-authenticated browser/API, authenticated
principal-to-principal shares, capability-limited payload streaming,
PostgreSQL state, and optional Iggy notifications through a Docker
development/integration topology.
See the [current threat model](docs/ThreatModel.md) and accepted
[architecture decisions](docs/adr/README.md).

Security-sensitive invariants include:

- every external identity resolves to a tenant-scoped internal principal;
- tenant administration grants no implicit access to user content;
- every content path enforces the common Virtual ACL and bounds stale access;
- the API has no payload mount and storage workers accept no browser session;
- PostgreSQL, not Iggy, is authoritative for metadata, policy, jobs, and audit;
- payload locators are UUIDs unrelated to user-controlled names; and
- build, runtime, and license evidence preserves the Apache/adapter boundary.

## Deployment expectations

Docker profiles are for development, integration, and fault verification. A
quiesced backup and restore procedure is documented for operator rehearsal,
but it is not an automated acceptance profile. The topology is not a supported
production deployment and makes no HA, online-backup, PITR, RPO, or RTO claim.
Kubernetes production is deferred until the Phase 3 workload, NetworkPolicy,
storage, migration, upgrade, and recovery contracts are accepted and
implemented.

Operators must use a standards-compliant OIDC issuer, configure exact
administrator issuer/subject pairs, provide trusted TLS and key material via
secret files, use PostgreSQL 18, and use a POSIX storage filesystem that passes
the startup fsync/rename/no-follow probes. Volume/provider encryption protects
data at rest; Phase 2 does not implement application-layer payload encryption.

OxiBelt is the public TLS edge. API and worker backend ports must remain on the
isolated application network. Never expose them directly or trust client
identity headers. Apache Iggy is optional; only its digest-pinned helper may
receive its documented `SYS_NICE`, memlock, and seccomp settings.

## Incident containment

- Suspected session or identity compromise: locally suspend the user or revoke
  individual/all sessions, then review the append-only audit trail.
- Suspected capability-signing compromise: stop write admission, rotate the
  capability key generation, retain only the overlap required to drain the
  60-second maximum capability lifetime, and reconcile operation state.
- Suspected session/share digest-key compromise: stop admission, rotate to a
  new generation, revoke affected credentials, and retain retiring material
  only for the documented validation window.
- Suspected payload corruption: quarantine rather than delete, stop affected
  reads, preserve evidence, identify every referencing version, and run an
  operator-directed scrub/recovery.
- Suspected database/storage inconsistency: quiesce writes, snapshot both
  planes, run read-only diagnostics, and follow the
  [Phase 2 rollback runbook](docs/operations/phase2-rollback.md).

Do not include raw cookies, OIDC codes, CSRF values, share tokens,
capabilities, signing/hash keys, database credentials, private payloads, or
unredacted backup artifacts in a vulnerability report sent through a public
channel.
