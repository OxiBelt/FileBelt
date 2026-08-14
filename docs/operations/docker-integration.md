<!-- SPDX-License-Identifier: Apache-2.0 -->

# Docker integration units

`tests/docker/units.toml` is the versioned catalog for the isolated `core`,
`collaboration`, and `mcp` Docker integration units. Docker Compose remains a
development and integration topology. These units do not qualify Kubernetes,
Helm rollout, CNI enforcement, NFS/Ganesha/Kerberos behavior, a provider, public
DNS, or a public MCP server's second-hop TLS.

Each run creates a unique Compose project, disposable state directory, network,
volumes, and uniquely tagged digest-pinned test fixtures. Exact-artifact mode
validates the image plan channel and current Git revision, AMD64 archive tag,
checksum, build/evidence metadata, validation, smoke result, vulnerability
decision, and nonempty build/runtime SBOMs before loading a role. It refuses to
replace a pre-existing archive or Compose image tag and never rebuilds a
FileBelt image. Cleanup removes only tags and resources owned by that run.

```sh
python3 tests/docker/units/run-unit.py --unit core --build
python3 tests/docker/units/run-unit.py --unit core --image-dir artifacts/phase1 --image-channel build --diagnostics-dir artifacts/docker/core
python3 tests/docker/units/run-unit.py --unit collaboration --image-dir artifacts/phase3 --image-channel release --diagnostics-dir artifacts/docker/collaboration
python3 tests/docker/units/run-unit.py --unit mcp --image-dir artifacts/phase3 --image-channel release --diagnostics-dir artifacts/docker/mcp
```

The runner's `--docker-topology` option controls how the acceptance client
reaches the real Compose TLS edge. `auto`, the local default, selects `host`
when the executor shares the Docker host and `outside` for a container using an
external Docker daemon. `host` uses the fixed loopback port published by
Compose. `outside` is also valid explicitly on a host executor: it assigns
Compose an ephemeral loopback port and starts a separately bounded loopback
bridge. A containerized executor is connected only to the web service's `edge`
network and bridges to its network address; a host executor bridges to the
ephemeral loopback publication. Backend services remain unpublished. Check and
signed-release workflows pin `outside` so CI behavior does not depend on
environment-detection heuristics. The client preserves
`https://filebelt.localhost:8443`, its Host header, and TLS server name. Before
the driver starts, the readiness probe validates that name against the
runner-generated CA and certificate.

The collaboration unit requires the frozen pnpm workspace plus the pinned
Playwright Chromium and Firefox binaries. It drives two users through the real
Compose TLS edge and covers convergence, durable save/checkpoint behavior,
one-use grants, restart/reconnect, revocation within 60 seconds, and dirty-room
freeze/conflict after an external head change.

The MCP unit covers two-user registration isolation, discovery, immutable
review, intent/approval/invocation, replay and argument mismatch, revocation,
credential redaction, and hostile response bounds. The exact synthetic host is
`filebelt-mcp-integration.example.test:443`. The mTLS egress fixture handles
that host before DNS and refuses every other integration-profile target; this
does not weaken the broker's public-WebPKI port-443 policy. Redirect, private
address, rebinding, malformed, oversized, slow, and session-confusion cases
fail closed. This fixture does not qualify public DNS or a second TLS hop.

On failure, the runner retains at most bounded scrubbed logs, a
`transport-status.txt` record of the selected topology and bridge lifecycle,
and synthetic browser screenshots. Successful runs discard transport
diagnostics. Playwright traces are disabled because they can contain session
cookies. Pull-request diagnostics expire after 7 days; other workflow
diagnostics expire after 30 days. Disposable tenant state and secrets are
destroyed before artifact upload. For local diagnosis, explicitly select
`--docker-topology host` or `--docker-topology outside`; a contradictory mode
fails before the acceptance driver runs. Rollback first removes the explicit
workflow arguments, then reverts the managed bridge and runner changes. It
does not require a migration or production deployment change.
