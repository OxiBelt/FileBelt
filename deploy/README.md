<!-- SPDX-License-Identifier: Apache-2.0 -->

# Deployment assets

Phase 4 provides the supported [`filebelt` Helm chart](helm/filebelt/README.md),
an operator-facing Compose development topology, and portable observability
assets. MCP mediation and curated runners are explicit opt-ins: the default
render retains the core Phase 3 boundary, while enabled runners add only
namespace-scoped controller RBAC and one restricted Pod per invocation.
Everything under `deploy/` remains in the Apache-2.0 license region.

For a disposable remote-MCP development stack, prepare a fresh state directory
and enable both profiles with the MCP-specific configuration:

```sh
FILEBELT_STATE_DIR=/absolute/disposable/path deploy/compose/prepare-state.sh
FILEBELT_STATE_DIR=/absolute/disposable/path \
FILEBELT_CONFIG_FILE=./filebelt-mcp.toml \
docker compose -f deploy/compose/compose.yaml --profile core --profile mcp up --build
```

The development egress gateway is the only service attached to the
non-internal network; the broker has no host port or payload mount. The local
stdio runner remains Kubernetes-only and is never started by Compose. Run
`deploy/compose/cleanup.sh` to remove containers, networks, and named volumes;
the chosen state directory is retained for explicit operator deletion.
