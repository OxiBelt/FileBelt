<!-- SPDX-License-Identifier: Apache-2.0 -->

# Dependency Boundaries

Dependencies flow from applications and adapters toward application services,
then domain/policy/protocol crates, then primitive types. The reverse direction
is forbidden.

- Domain types know nothing about SQL, HTTP, OIDC, Iggy, Kubernetes, storage
  paths, browser packages, or adapters.
- Authorization evaluates supplied policy; it does not fetch data or trust
  protocol-specific identity claims.
- Database code owns atomic mechanics, not authorization decisions.
- Storage workers accept capability-limited identifiers and never resolve user
  paths or expose physical locators.
- Apache core knows only generic protocol contracts; adapter implementations
  may depend inward on those contracts, never the reverse.
- UI packages consume documented APIs and do not implement authorization.

## Package direction

```text
role binaries / browser SPA
        │
        ├── application services ──> database repositories
        │             │
        │             ├──> domain and authorization
        │             └──> protocol contracts
        │
        └── generated public clients ──> protocol/OpenAPI contracts

adapters ──process boundary──> Apache protocol contract
```

- `filebelt-domain` owns IDs, normalized namespace values, action vocabulary,
  immutable-version state, and generation primitives. It contains no async
  runtime or implementation integration.
- `filebelt-authz` is a deterministic evaluator over supplied principals,
  ancestry, entries, membership, owner state, action, and generations. It does
  not load database rows, inspect cookies/OIDC claims, publish events, or open
  payload paths.
- `filebelt-database` owns SQLx queries, transactions, migration compatibility,
  outbox mechanics, idempotency storage, and lease fencing. It does not decide
  whether an actor is authorized.
- Application services resolve repository records, invoke `filebelt-authz`,
  enforce expected-generation/idempotency rules, and coordinate transactions.
  HTTP handlers translate wire types and do not contain a second policy model.
- Capability/event Protobuf schemas and the OpenAPI contract contain FileBelt
  IDs and stable wire enums. They expose no SQL row, OxiBelt, Iggy, host path,
  Kubernetes, or adapter implementation type.
- `filebelt-api` may use application services and database repositories but has
  no storage implementation dependency or payload mount.
- `filebelt-worker-io` may use capability/storage protocol packages and narrow
  operation/payload/generation repositories. It does not depend on HTTP session
  authentication or namespace/ACL write repositories.
- `filebelt-worker-maintenance` uses fenced job, payload, and reconciliation
  repositories. Iggy is an optional wake-up adapter outside its correctness
  path.
- `filebelt-vfs` consumes the generic VFS schema, mount database repository,
  mount verifier vault, and `fbcap2` signer. It does not depend on Samba,
  libunftp, host filesystem identity, storage implementation code, or payload
  paths.
- `filebelt-headscale-sync` consumes the external Headscale HTTP API and the
  narrow atomic device-observation repository. It cannot issue credentials,
  create sessions, evaluate filesystem ownership, or sign capabilities.
- `filebeltctl` composes explicit operator commands. It must not make a library
  package depend on CLI types or silently widen a service's database role.
- `filebelt-runtime` owns transport TLS, operations endpoints, bounded metrics,
  and telemetry export shared by serving roles. It may consume typed control
  configuration but does not contain domain policy, SQL, storage, Kubernetes,
  or service-specific application behavior.
- `@filebelt/web` and `@filebelt/admin` consume one generated OpenAPI client.
  Admin UI is a lazy route, not a separate authority; hiding a control is not
  authorization.
- OxiBelt, PostgreSQL, OIDC, Iggy, and Headscale are replaceable external processes.
  Apache packages may depend on reviewed generic clients or schemas, never on
  their internal source or deployment-specific row/config types.

## Data and trust direction

The edge resolves no FileBelt principal. The API resolves an OIDC/session input
to an internal principal and supplies policy facts to the authorization
evaluator. It may then issue a signed operation capability. A storage worker
accepts that capability, not the browser session, and resolves physical UUID
locators through its narrow repository. The filesystem never maps host
UID/GID ownership to a FileBelt user.

PostgreSQL is authoritative for metadata, policy, generations, operations,
jobs, outbox, and audit. Iggy consumers read PostgreSQL after a notification;
an event payload cannot overwrite committed truth. Payload bytes are
authoritative only in conjunction with their committed PostgreSQL version and
manifest state.

## Deployment direction

Kubernetes and Helm types remain in deployment templates, tests, and operator
documentation. They do not enter domain, authorization, database, storage, or
protocol types. Native applications consume the versioned generic runtime
configuration and TLS/telemetry libraries; they do not query the Kubernetes
API. OxiBelt remains a replaceable process boundary and its client-certificate
support is consumed only through generated configuration and HTTPS.

The chart mounts the existing payload claim only into I/O, maintenance, and
explicit storage recovery Jobs. API, web, VFS, Headscale sync, and protocol
gateways remain storage-library- and payload-mount-free. Database migration,
audit export, and recovery use separate group roles; adding an operator command
never widens a serving role. Prometheus and OTLP are output protocols and
cannot become policy or durability inputs.

The SMB and explicit-FTPS crates live in independent GPL workspaces and may
depend on the committed Apache VFS protocol through an ordinary replaceable
client boundary. They may not be root Cargo members or path dependencies of an
Apache package. Their adapter-local lockfiles, notices, source offers, build
roots, and image evidence remain separate. Helm may describe both processes,
but rendering a Pod neither changes dependency direction nor proves license or
release readiness.

## Change review

Adding a dependency edge across one of these layers requires an explicit
architecture and policy review in the same pull request when it changes public
contracts, policy, persistence, runtime trust, native linkage, or a license
boundary. Record rationale, alternatives, compatibility, security and license
effects, rollout, and rollback, and update the applicable living specification.
Review the resolved Cargo/pnpm graph rather than only direct manifest text.
Generated code follows the destination package's license and records its schema
and generator provenance.

Repository contract tests validate workspace membership, resolved path
dependencies, package license metadata, generated-code provenance, database
role use, image/mount contracts, and unsafe-code exceptions.

## Automated enforcement

The reviewed production graph and crate-root public surface live in
`supply-chain/cargo-boundaries-v1.toml`. The policy records every production
manifest, its allowed transitive first-party packages and activated features,
narrow forbidden dependency families, public root modules, and wildcard
re-exports. `tests/scripts/check-cargo-boundaries.sh` compares that policy with
locked `cargo metadata` and package-scoped `cargo tree` results. Unknown local
packages, path dependencies, features, or adapter manifests fail closed.

The source contract parses production Rust with `syn` so aliases, nested use
trees, relative imports, and public re-exports cannot bypass the documented
direction. It scans reserved adapter roots for Rust syntax even though adapters
remain outside the Apache workspace. Generated Rust is compiled through its
owning protocol crate and checked for deterministic regeneration; it is not
treated as a hand-authored module or public-surface declaration.

`tests/scripts/check-rust-module-size.sh --warn` reports files above 750
physical lines in `source/src`, `source/apps`, `source/crates`, and `adapters`.
The limit is an advisory decomposition signal, not permission to mix roles or
an automatic reason to split cohesive code. `--enforce` is available for a
focused cleanup once the affected responsibilities and compatibility tests are
under review.

Changing a reviewed graph or public-surface entry requires an explicit policy
diff. When the change also affects a public contract, runtime trust,
persistence, native linkage, or license boundary, the same pull request updates
the applicable [runtime](RuntimeAndDeployment.md),
[storage](StorageAndDurability.md), interface, authorization, license, and
supply-chain specifications. The checker does not provide an automatic
baseline-update mode.
