<!-- SPDX-License-Identifier: Apache-2.0 -->

# WireGuard image automated-agent overlay

This directory is an Apache-2.0 first-party wrapper and a separately released
aggregate image containing unmodified GPL-2.0-only networking executables.
Follow the root `AGENTS.md`, `CONTRIBUTING.md`, `adapters/README.md`, and the
living specifications indexed by `docs/README.md`.

The wrapper must remain outside the root Cargo workspace. It may invoke the
separate `wg` and `ip` executables, but it must not copy, link, or import their
implementation. The image must be built only from checksum-verified staged
source, include exact license and corresponding-source evidence, and remain
publication-blocked until every declared platform passes native qualification.

Do not add `wg-quick`, a shell, DNS hooks, arbitrary commands, default routes,
route advertisement, or a general network configuration surface. Only the
fixed `fbwg0` interface, numeric peer endpoint, one tunnel address, and exact
host target routes are admitted.
