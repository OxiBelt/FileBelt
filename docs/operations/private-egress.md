<!-- SPDX-License-Identifier: Apache-2.0 -->

# Private egress preview operations

Private egress is a Kubernetes-only, disabled-by-default preview for an MCP
server or ONLYOFFICE output endpoint reachable through WireGuard or Tailscale.
It is not a general proxy and does not put a tunnel sidecar in an application
Pod. Install `deploy/helm/filebelt-private-egress` into its configured,
pre-created namespace; the chart creates no Namespace, Secret, or PVC.

## Authority and traffic path

The MCP broker or ONLYOFFICE adapter connects by mTLS to a role-specific
protocol gateway. The gateway admits only the exact MCP root exchange or
`POST /v1/fetch`, then opens an ALPN-bound mTLS connection to a destination-free
relay. The relay selects only its configured numeric target addresses and one
fixed port. An inner TLS connection authenticates the configured target SNI
against the target CA. DNS, redirects, caller-selected destinations, direct
Internet fallback, and retry of unknown-outcome mutations are absent.

Use four distinct certificate identities per instance: application client,
gateway server, gateway-to-relay client, and relay server. Keep the MCP and
ONLYOFFICE instances distinct. A private MCP trust profile selects its named
`mcp.gateways` entry and must disable dynamic registration; only no-auth,
bearer, or API-key credentials are admitted. OAuth is unsupported because its
discovery and token endpoints would widen the one-target contract.

For ONLYOFFICE, enable `networkPolicy.privateEgress` in the integration chart
and point the existing provider ConfigMap at the role-specific gateway with
the separately mounted client identity:

```toml
[egress_gateway]
url = "https://filebelt-private-egress-onlyoffice.filebelt-private-egress.svc:8443/"
certificate_chain_file = "/run/secrets/private-egress-client-tls/tls.crt"
private_key_file = "/run/secrets/private-egress-client-tls/tls.key"
server_ca_file = "/run/secrets/private-egress-client-tls/server-ca.crt"
```

Do not retain the public egress endpoint as a fallback in that integration
profile. The ConfigMap, Secret, gateway instance, and NetworkPolicy selector
must be changed and rolled as one reviewed contract.

## Transport slots

Tailscale runs in userspace mode with a loopback-only SOCKS5 listener. Each of
one to three slots has a distinct auth-key Secret, hostname, and pre-created
RWO tailstate claim. It receives no application or relay mTLS Secret. The
operator-supplied outer `ipBlock` exceptions must cover cluster Pod, Service,
node, loopback, link-local/metadata, and target tailnet ranges. Tailscale slots
are limited to amd64 and arm64.

Standard Kubernetes NetworkPolicy applies to the whole relay Pod, so the
Tailscale outer-network allowances also apply to the co-located relay
container. Treat that shared-policy reach as an explicit preview qualification
gap: do not publish or activate Tailscale transport until live provider and CNI
evidence demonstrates the required isolation, or the topology is revised to
provide an equivalent narrower control.

WireGuard uses a separate mixed-license init image. The root init container has
only `NET_ADMIN`, creates `fbwg0`, installs one reviewed peer and exact `/32` or
`/128` target routes, then exits. The unprivileged relay has no key or
capability. Each slot uses distinct private and optional preshared-key Secrets.
The peer socket, NetworkPolicy peer CIDR/port, numeric targets, and target CIDRs
must be reviewed as one contract. No default route, DNS, hook, or `wg-quick`
configuration is accepted.

## Qualification and activation

Before first activation, record and retain:

1. digest, SBOM, provenance, vulnerability, license, and corresponding-source
   evidence for every image and architecture;
2. live provider login, exact target TLS/SNI/CA, disconnect/reconnect, expired
   credential, state restore, and one-to-three-slot failover results;
3. Calico and Cilium positive-path and denial tests proving direct application
   egress, gateway bypass, relay cross-instance access, DNS escape, metadata,
   cluster ranges, wrong ports, and caller-selected targets remain denied;
4. MCP none/bearer/API-key and OAuth/dynamic-registration denial tests, plus
   ONLYOFFICE redirect, oversized, slow, wrong-origin, and wrong-path tests; and
5. native amd64/arm64 results for both providers and native riscv64 WireGuard
   results before advertising those platforms.

Until every gate passes, leave image qualification/publication blocked and the
core/integration chart options disabled. Static Helm rendering, unit tests, or
a CNI without the real provider do not qualify this preview.

## Rotation, recovery, and rollback

Rotate one hop or transport slot at a time using a new Secret name/generation.
For mTLS, add the new verifier identity, roll the presenter, prove readiness,
then remove the retired identity. For Tailscale, provision a replacement slot
and RWO claim before revoking the old device. For WireGuard, provision a new
peer/key slot before removing the old peer; never reuse state or identity
between slots.

To fail closed immediately, disable the consuming role's private-egress option
and remove its NetworkPolicy path, then revoke the application client identity
and provider/WireGuard credential. Roll back by restoring the prior core or
adapter configuration and uninstalling the private-egress release. PVCs,
Secrets, peer devices, and the namespace remain operator-owned and must be
revoked or removed explicitly after evidence retention. There is no public or
direct fallback: requests assigned to the private integration fail while it is
unavailable.
