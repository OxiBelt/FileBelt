<!-- SPDX-License-Identifier: Apache-2.0 -->

# Deployment assets

Phase 4 provides the supported [`filebelt` Helm chart](helm/filebelt/README.md),
a developer-only Compose integration topology, and portable observability
assets. MCP mediation and curated runners are explicit opt-ins: the default
render retains the core Phase 3 boundary, while enabled runners add only
namespace-scoped controller RBAC and one restricted Pod per invocation.
Everything under `deploy/` remains in the Apache-2.0 license region.

The bundled OIDC service is a deterministic, passwordless test issuer. Anyone
who can reach the development edge can choose its administrator identity. The
edge therefore binds to `127.0.0.1` by default. A non-loopback
`FILEBELT_HTTPS_BIND_ADDRESS` is rejected by the relay unless the operator also
sets
`FILEBELT_UNSAFE_NON_LOOPBACK_ACK=I_UNDERSTAND_PASSWORDLESS_OIDC_IS_PUBLIC`.
That acknowledgement does not make the topology suitable for production.

For fast browser and Markdown-editor development without creating server-side
state, start the Vite server and opt into the development-only in-memory
adapter:

```sh
pnpm --filter @filebelt/web dev
```

Open
`http://127.0.0.1:5173/drive?filebelt-development=mock`. The page displays a
persistent mock-data banner; edits live only for that page lifetime, live
collaboration falls back locally, and this mode does not qualify API,
PostgreSQL, OIDC, ACL-enforcement, mount, or storage behavior. Omit the query
parameter when using the Compose stack or another real development backend.
The command builds the isolated Markdown preview before Vite starts. Restart it
after changing preview-frame code so the sandbox uses the newly built artifact;
ordinary web and source-editor changes continue to use Vite hot reload.

For a disposable remote-MCP development stack, prepare a fresh state directory
and enable both profiles with the MCP-specific configuration:

```sh
FILEBELT_STATE_DIR=/absolute/disposable/path deploy/compose/prepare-state.sh
FILEBELT_STATE_DIR=/absolute/disposable/path \
docker compose -f deploy/compose/compose.yaml -f deploy/compose/compose.mcp.yaml \
  --profile core --profile mcp up --build
```

The development egress gateway is the only service attached to the
non-internal network; the broker has no host port or payload mount. The local
stdio runner remains Kubernetes-only and is never started by Compose. Run
`deploy/compose/cleanup.sh` to remove containers, networks, and named volumes;
the chosen state directory is retained. Re-running `prepare-state.sh` validates
required files and rejects a certificate that is invalid, expired, or expires
within 24 hours. To recreate invalid or expiring state, first run cleanup with
the same state directory, move the retained directory aside for recovery, and
prepare a fresh directory before restarting:

```sh
FILEBELT_STATE_DIR=/absolute/disposable/path deploy/compose/cleanup.sh
mv -- /absolute/disposable/path /absolute/disposable/path.expired
FILEBELT_STATE_DIR=/absolute/disposable/path deploy/compose/prepare-state.sh
```

The OIDC fixture, payload initializer, and acceptance relay use independent
`FILEBELT_OIDC_FIXTURE_IMAGE`, `FILEBELT_PAYLOAD_INIT_IMAGE`, and
`FILEBELT_ACCEPTANCE_RELAY_IMAGE` inputs. Replacing the OIDC image therefore
cannot silently replace either utility role.

An external development OIDC provider is an explicit override, not a drop-in
fixture image. Create a dedicated Docker network and supply format-9 FileBelt
configuration for every enabled role, an edge configuration with the matching
public origin/routes, the provider client secret, and optionally its CA. The
administrator entry must bind the exact provider issuer and subject; remove
`development_allow_insecure` when the issuer is HTTPS. Then include the generic
network override:

```sh
docker network create filebelt-development-oidc
FILEBELT_OIDC_EGRESS_NETWORK=filebelt-development-oidc \
FILEBELT_CONFIG_FILE=/absolute/filebelt.toml \
FILEBELT_MCP_CONFIG_FILE=/absolute/filebelt-mcp.toml \
FILEBELT_COLLABORATION_CONFIG_FILE=/absolute/filebelt-collaboration.toml \
FILEBELT_EDGE_CONFIG_FILE=/absolute/oxibelt.toml \
FILEBELT_OIDC_CLIENT_SECRET_FILE=/absolute/oidc-client-secret \
FILEBELT_OIDC_CA_FILE=/absolute/oidc-ca.crt \
docker compose -f deploy/compose/compose.yaml \
  -f deploy/compose/compose.external-oidc.yaml --profile core up --build
```

The external network is development egress and must contain only the intended
provider path. This repository does not provision or qualify a particular OIDC
product, and the unused passwordless fixture remains isolated inside the
Compose project.
