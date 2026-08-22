<!-- SPDX-License-Identifier: Apache-2.0 -->

# Local development deployment helper

`python3 tests/development/run.py` manages named, detached, disposable local
sessions for development and diagnosis. It is manual-only: CI tests its
contracts but never starts a helper deployment. Every successful session status
reports `accepted: false`; it is not production, release, Kubernetes/CNI,
provider, or security qualification.

Start with the strict schema-v1 template in
[`example.toml`](example.toml). Pass it to `up` with an absolute, non-symlink
path; every caller-owned file named by the configuration is likewise explicit
and absolute. The template contains no secret material.

```sh
python3 tests/development/run.py up --name local-compose --topology compose \
  --config /absolute/path/filebelt-development.toml
python3 tests/development/run.py list
python3 tests/development/run.py status --name local-compose --json
python3 tests/development/run.py logs --name local-compose --component filebelt-api --tail 200
python3 tests/development/run.py restart --name local-compose --component filebelt-api
python3 tests/development/run.py diagnose --name local-compose
python3 tests/development/run.py down --name local-compose
```

Compose `port-forward` verifies its loopback-only Docker-host publication and
serves the fixed `https://filebelt.localhost:8443` development origin. It runs
a foreground loopback bridge when the executor cannot reach that publication
directly; terminate it when finished. Minikube rejects forwarding while its
chart is quiesced.

```sh
python3 tests/development/run.py port-forward --name local-compose --port 8443
```

`prepare-state.sh` creates a fresh self-signed development certificate for each
session. Firefox therefore requires an explicit exception for
`filebelt.localhost:8443` (or a temporary import of that session's certificate)
before the first sign-in. Keep that trust local and temporary; the generated
certificate is not production identity evidence.

## Topologies and inputs

Compose requires Docker with the Compose plugin, OpenSSL, and the other tools
already required by `deploy/compose/prepare-state.sh`. Minikube additionally
requires `minikube`, `kubectl`, GNU `timeout`, and Docker. Source-mode Minikube
also requires `devops/dist/cli.js`; build that tracked tool with the repository
pnpm workflow before `up`. If no suitable installed Helm is found, the helper
downloads only the approved Linux `amd64` or `arm64` `v4.2.4` archive and
verifies its repository-pinned SHA-256 before extraction.

`compose` accepts only the checked-in `core`, `mcp`, `iggy`, and `fault`
profiles and a configurable unprivileged Docker-host publication port. The
browser-facing origin remains port 8443 so OIDC redirects and origin checks stay
coherent. It starts a run-owned Compose project and state directory. Source
images are the default. Artifact mode accepts only a caller-supplied exact
artifact directory and its `build` or `release` channel. It temporarily loads
the validated archive tag, creates an exact session tag, removes the temporary
archive tag, and never publishes or replaces an existing local tag.

`minikube` is a broader development preview. The helper owns only its named
Minikube profile, including the release and copied prerequisites inside it. It
defaults to Kubernetes
`v1.36.1` and Calico; its schema also permits the repository-supported current
versions and Cilium. Bootstrap is verified on Linux `amd64` and `arm64`, and
the Helm executable must be the repository-pinned `v4.2.4` binary. Minikube
source mode builds the five core chart images for the local Docker
architecture. Artifact mode accepts the repository's exact validated AMD64
evidence catalog.

The Minikube chart remains explicitly quiesced with `operation.type=none`.
This topology is for inspecting chart rendering, admission, object wiring, and
NetworkPolicy without claiming a serving deployment; use Compose for the
running web and API development stack. Every optional feature requires its
exact digest-pinned chart image roles and caller-supplied source/license
evidence. Values files cannot override the helper's final quiescence and image
settings. Values files remain caller-qualified non-secret input; the helper
rejects common credential markers but does not attempt to classify arbitrary
values as secrets.

The helper does not invent production dependencies. PostgreSQL, OIDC, Iggy,
providers, certificates, PVCs, and ConfigMaps must come from explicit
caller-owned prerequisite manifests or object references. Prerequisite
manifests are client-dry-run before apply, reject Secrets and every
cluster-scoped kind except a restricted Namespace, require an exact
`filebelt.dev/development-session` label, and may use only explicit
`filebelt-*` namespaces. Any prerequisite Namespace must enforce the
restricted Pod Security Standard, and Services must remain `ClusterIP`
without external addresses. Secret bytes come from absolute files,
are sent to immutable Kubernetes Secrets only over standard input, and are
copied into the private session directory solely so later diagnostics can
redact them. They never enter the configuration or session manifest.

The preview feature-to-image contract is exact:

| Feature | Required non-core image roles |
| --- | --- |
| `collaboration` | `filebelt-collaboration` |
| `documents` | `filebelt-document` |
| `mcp` | `filebelt-mcp-broker` |
| `mcp-runners` | `filebelt-controller`, `filebelt-mcp-runner`; also enable `mcp` |
| `mount-ftp-ftps` | `filebelt-ftp-ftps-gateway`, `filebelt-headscale-sync`, `filebelt-vfs`, `tailscaled` |
| `mount-nfs` | `filebelt-headscale-sync`, `filebelt-nfs-gateway`, `filebelt-nfs-relay`, `filebelt-vfs`, `tailscaled` |
| `mount-smb` | `filebelt-headscale-sync`, `filebelt-smb-gateway`, `filebelt-vfs`, `tailscaled` |
| `revisions` | `filebelt-revision` |

The default passwordless OIDC fixture is the simplest local browser path. A
caller-operated Authelia or other OIDC provider can instead use the strict
`compose.external_oidc` network and file inputs in `example.toml`; the helper
does not pull, configure, or own that provider.

Every helper-managed serving listener is Compose-only and binds to loopback.
The passwordless OIDC fixture remains development-only. Do not use the helper
to make a service reachable from another host.

## Diagnostics and cleanup

Sessions have bounded lower-case names and durably record their source revision,
configuration digest, topology, owned resources, and `accepted: false` state.
Ownership is written before external provisioning so interrupted setup remains
retry-cleanable.

Failure retention writes at most 1 MiB per private diagnostic and scrubs known
secret files and credentials. Diagnostic files never retain request bodies,
cookies, capability material, kubeconfigs, Helm values, or raw Secret data.
`logs` and `diagnose` print similarly scrubbed, bounded output.

`down` removes only resources proven to be owned by that session: its Compose
project/state/fixture and role tags, or its entire helper-created Minikube
profile. Deleting that isolated profile also deletes the release, namespaces,
and copied prerequisites inside it. It never deletes caller source files,
artifact directories, external clusters, external kubeconfigs, or external
dependencies. A failed cleanup remains a failure. If a caller-supplied
prerequisite touched forward-only external database state, follow the
production rollback guidance rather than trying to undo a migration or delete
durable records.

After Compose's bounded wait, the helper records `composeReady` and any
`degradedComponents`. A degraded long-lived service does not erase the detached
session: keeping the remaining stack available is intentional for diagnosis,
and `status` recomputes the readiness summary. Command or provisioning failure
still follows the failure-retention and exact-cleanup path.
