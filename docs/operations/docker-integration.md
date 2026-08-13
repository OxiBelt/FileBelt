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

On failure, the runner retains at most bounded scrubbed logs and synthetic
browser screenshots. Playwright traces are disabled because they can contain
session cookies. Pull-request core diagnostics expire after 7 days; other
workflow diagnostics expire after 30 days. Disposable tenant state and secrets
are destroyed before artifact upload. Rollback removes the new CI consumers
first and then the catalog/runner; it does not require a migration or a
production deployment change.
