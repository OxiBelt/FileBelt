<!-- SPDX-License-Identifier: Apache-2.0 -->

# Apache core source guidance

This tree is Apache-2.0 and inherits the root `AGENTS.md` and accepted ADRs.

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
  Native or `unsafe` exceptions require accepted governance and supply-chain
  evidence.
