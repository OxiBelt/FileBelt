<!-- SPDX-License-Identifier: Apache-2.0 -->
# FileBelt private egress (preview)

This disabled-by-default chart installs dedicated protocol gateways and
destination-free tunnel relays for MCP or ONLYOFFICE output fetches. It never
creates a Namespace, Secret, or PersistentVolumeClaim. Application Pods mount
only their gateway client identity; tunnel credentials and state exist only in
the isolated relay Pods.

Each enabled instance requires four distinct mTLS identities (application
client, gateway server, gateway-to-relay client, and relay server), an exact
target TLS name and CA, one to sixteen numeric dial addresses on one port, and
one to three transport slots. The gateway understands only the MCP root route
or ONLYOFFICE `/v1/fetch`; the relay accepts no destination from its caller.

Tailscale slots use userspace networking and a loopback SOCKS5 endpoint. Each
slot must reference its own auth-key Secret and pre-created RWO tailstate claim.
The operator must make `outerNetwork` exclude cluster, node, service, metadata,
loopback, and tailnet target ranges. It is supported on amd64 and arm64 only.
Because standard NetworkPolicy selects the whole Pod, those outer-network
allowances also reach the co-located relay container. This remains a preview
qualification gate pending live provider/CNI evidence or an equivalent
narrower topology.

WireGuard slots run the separately distributed mixed-license init image once
with only `NET_ADMIN`. They install only exact `/32` or `/128` target routes;
the relay remains unprivileged and carries no WireGuard key. The peer endpoint,
NetworkPolicy peer CIDR/port, target CIDRs, and numeric dial addresses must be
the same reviewed contract.

`examples/qualification-values.yaml` is a non-production render fixture. Do
not enable this preview until image provenance, provider connectivity, CNI
enforcement, failover, revocation, backup/restore, and rollback gates in the
operator documentation have passed.
