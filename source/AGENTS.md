<!-- SPDX-License-Identifier: Apache-2.0 -->

# Apache core automated-agent overlay

This file applies only to automated agents. Follow the
[root agent guidance](../AGENTS.md), [contributor workflow](../CONTRIBUTING.md),
and [living specifications](../docs/README.md).

Enter Plan Mode before changing persisted state, namespace or authorization
semantics, public interfaces, payload acknowledgement or deletion, worker
authority, migrations, runtime roles, or unsafe-code policy. Stop and ask the
maintainer whenever the applicable living specification does not resolve a
security, durability, compatibility, recovery, or license decision.

This tree is Apache-2.0.

- Keep domain and authorization crates free of SQLx, HTTP, OIDC, storage-path,
  Kubernetes, UI, Iggy, and adapter implementation types.
- Resolve protocol identities to tenant-scoped internal principals before
  authorization. Host UID/GID and filesystem ownership never represent a
  FileBelt user.
- PostgreSQL is authoritative for metadata, policy, generations, jobs, outbox,
  and audit. Iggy is an optional notification/wake-up path only.
- The API must not mount payload storage. Workers accept short-lived scoped
  capabilities and narrow repository projections, not browser sessions or user
  paths.
- Persist every filesystem/database transition and add deterministic failpoint
  and reconciliation coverage before changing acknowledgement or deletion
  behavior.
- SQL migrations are forward-only and immutable after release. Use the
  dedicated migrator command and expand/migrate/contract compatibility.
- Add the lowest-layer regression test and preserve `unsafe_code = "deny"`.
  Native or `unsafe` exceptions require explicit maintainer approval and
  supply-chain evidence in the same change.
