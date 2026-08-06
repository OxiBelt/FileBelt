<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt Helm chart

This Phase 1 chart is a machine-validated image configuration contract. It
intentionally renders no Kubernetes object and must not be treated as a
deployable FileBelt system. Workloads, services, probes, credentials, policy,
storage, and authorization configuration begin in later phases.

## Contract

The chart requires exactly these image keys:

- `filebelt-api`
- `filebelt-worker-io`
- `filebelt-worker-maintenance`
- `filebelt-media-controller`
- `filebelt-mcp-broker`
- `filebelt-tools`
- `filebelt-web`

Every repository is fixed under the `oxibelt/` namespace. Each role selects
exactly one immutable release SemVer tag, dry-run `0.1.0-build.<sha12>` tag, or
one `sha256:` digest. Because the defaults select a tag, set that value to
`null` and provide `digest` in an overriding values file:

```yaml
images:
  filebelt-api:
    repository: oxibelt/filebelt-api
    registryMirror: ""
    tag: null
    digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The effective registry authority is the first non-empty value in this order:

1. The role's `registryMirror`
2. `global.registryMirror`
3. `global.registry`

A mirror replaces only the registry authority. It does not change the fixed
repository name, role, tag or digest, platform intent, source identity, or
license. Registry values are authorities such as `registry.example.test:5000`;
they contain no URL scheme, path, or trailing slash.

All roles declare `linux/amd64`, `linux/arm64`, and `linux/riscv64` intent and
numeric user/group `10001:10001`. These are validation inputs only because the
chart creates no container or Pod.

## Validation

From the repository root, run:

```sh
tests/scripts/check-helm-chart.sh
```

The check requires Helm `4.2.3`, runs strict lint and positive/negative schema
cases, and requires empty manifest output. Rendering any Kubernetes object is a
contract violation in Phase 1.
