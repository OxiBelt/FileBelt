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

Repository contract tests validate workspace membership, resolved path
dependencies, package license metadata, and unsafe-code exceptions.
