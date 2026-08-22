<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt WireGuard initialization image

This separately released aggregate image configures the fixed `fbwg0`
interface in a private-egress transport Pod. The Apache-2.0
`filebelt-wireguard-init` executable validates a closed command line and invokes
separate, unmodified `wg` and `ip` executables. No Apache core package imports
this workspace or either GPL implementation.

The initializer accepts exactly one numeric peer endpoint, one tunnel address,
and one through sixteen numeric host routes. Targets must be IPv4 `/32` or IPv6
`/128`; default routes, DNS, loopback, multicast, metadata endpoints,
`wg-quick`, scripts, and route advertisement are unavailable. Kubernetes gives
only this init container `CAP_NET_ADMIN`; it exits before the non-root relay
begins serving.

The source-first Dockerfile has no downloader or package manager. The adapter
source-bundle process must stage WireGuard tools `1.0.20260223`, iproute2
`7.1.0`, a versioned Cargo vendor closure, license texts, notices, and a source
manifest. The checked-in qualification state is blocked. Publication requires
native WireGuard handshake and fixed-route evidence for every advertised
platform, plus exact SBOM, vulnerability, provenance, and rebuild receipts.

```sh
cargo fmt --check --manifest-path adapters/wireguard/Cargo.toml
cargo test --locked --manifest-path adapters/wireguard/Cargo.toml
```
