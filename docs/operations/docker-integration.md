<!-- SPDX-License-Identifier: Apache-2.0 -->

# Docker integration units

`tests/docker/units.toml` is the versioned catalog for the isolated `core`,
`collaboration`, `mcp`, and manual `phase8-qualification` Docker integration
units. Docker Compose remains a
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
python3 tests/docker/units/run-unit.py --unit phase8-qualification --build --qualification-output artifacts/phase8-local-contract.json
```

The Phase 8 unit runs real operations, collaboration WebSocket, and tools
endpoints and records exact success/failure assertions and cleanup. Its default
`contract` mode is deliberately non-accepted. Add
`--phase8-mode qualification --phase8-cadence change-smoke` for the real
five-minute load window. Media-controller, VFS, NFS, media delivery, and
WebTransport remain prerequisite-bearing skips in this developer topology, so
even that result remains non-accepted until separate qualified fixtures replace
every skip. The output path must not already exist.

The runner's `--docker-topology` option controls how the acceptance client
reaches the real Compose TLS edge. `auto`, the local default, selects `host`
when the executor shares the Docker host and `outside` for a container using an
external Docker daemon. `host` uses the fixed loopback port published by
acceptance relay. `outside` is also valid explicitly on a host executor: it
assigns the relay one available loopback port from the IANA dynamic/private
range `49152-65535` and starts a separately bounded loopback bridge. The
nonempty published range is compatible with Docker runner versions that do not
create a mapping for an empty or zero-valued Compose publication. Before
selecting its bridge target, the runner requires Docker to report exactly one
mapping in that range on `127.0.0.1`.

The separately bounded bridge retains each admitted client while retrying only
its initial connection to that validated publication. Attempts use a one-second
timeout with 100-millisecond backoff and stop after five seconds. The bridge
never retries after forwarding begins, and an exhausted client does not stop
other acceptance connections. Each retrying client continues to count against
the 64-connection admission bound.

Docker does not publish ports for a service attached only to an internal
network. The raw TCP acceptance relay is therefore the only service attached to
the ordinary `acceptance-publication` bridge. It has no Secret, config, or
storage mount, runs read-only as the unprivileged fixture user with all
capabilities dropped, bounds concurrent connections, and can forward only to
`filebelt-web:8443` on the internal `edge` network. A containerized executor is
connected only to `edge` and bridges to the relay's internal address after
validating the host publication; a host executor bridges to the validated
loopback publication. FileBelt application services, including the web edge,
remain unpublished and on internal networks. Check and signed-release workflows
pin `outside` so CI behavior does not depend on environment-detection
heuristics. The client preserves
`https://filebelt.localhost:8443`, its Host header, and TLS server name. Before
the driver starts, the readiness probe validates that name against the
runner-generated CA and certificate.

The collaboration unit requires the frozen pnpm workspace plus the pinned
Playwright Chromium and Firefox binaries. It drives two users through the real
Compose TLS edge and covers convergence, durable save/checkpoint behavior,
one-use grants, restart/reconnect, revocation within 60 seconds, and dirty-room
freeze/conflict after an external head change. Docker interface changes during
the exercised restart can make Chromium report an exact
`net::ERR_NETWORK_CHANGED`. The acceptance driver retries the initial login
navigation once. When the signed-in workspace bootstrap shows `Failed to
fetch`, it keeps its failed-request listener active for one 250 ms settle
window before rechecking the workspace. It invokes the existing `Refresh`
action once only if that alert remains visible and Playwright observed the
exact failure. If the exact failure instead leaves neither the workspace nor
its alert visible until the bounded outcome wait expires, the synthetic login
fixture is replayed once from its login route. Refresh and login replay share a
single recovery budget; neither path recurses, and every other failure and any
failed retry remain visible. The
failure-only workspace-heading assertion receives a scrubbed disposition with
only the exact-network-change-observed, login-replayed, and refresh-clicked
booleans; the driver does not retain the failed request's URL, headers, body,
method, or resource type. To exercise a restart without racing past the browser
close event, the driver holds collaboration stopped until both browser
principals observe disconnection. It then starts the service, waits for the
internal operations endpoint and collaboration listener, and reconnects both
principals before revocation. The final revocation assertion therefore proves
a connected member transitions to disconnected rather than accepting the
restart state. The administrator's browser context submits that revocation
exactly once through its API request client, which shares the context's
authenticated cookies and traverses the same real TLS edge. It retains the
current CSRF and same-origin headers but does not retry the non-idempotent
mutation after an unknown outcome or follow a redirect that could replay its
method. Keeping this one-shot control request outside Chromium's page network
isolates it from the Docker interface change without weakening authentication
or the revocation deadline.

The MCP unit covers two-user registration isolation, discovery, immutable
review, intent/approval/invocation, replay and argument mismatch, revocation,
credential redaction, and hostile response bounds. The exact synthetic host is
`filebelt-mcp-integration.example.test:443`. The mTLS egress fixture handles
that host before DNS and refuses every other integration-profile target; this
does not weaken the broker's public-WebPKI port-443 policy. Redirect, private
address, rebinding, malformed, oversized, slow, and session-confusion cases
fail closed. This fixture does not qualify public DNS or a second TLS hop.

On failure, the runner retains at most bounded scrubbed logs, a
`transport-status.txt` record of the selected topology, resolved publication,
bridge target, bridge lifecycle, and aggregate admission, connection-attempt,
connection-failure, and retry-exhaustion counters, and synthetic browser
screenshots. These counters contain no client address or forwarded bytes.
Successful runs discard transport diagnostics. Playwright traces are disabled
because they can contain session
cookies. Pull-request diagnostics expire after 7 days; other workflow
diagnostics expire after 30 days. Disposable tenant state and secrets are
destroyed before artifact upload. For local diagnosis, explicitly select
`--docker-topology host` or `--docker-topology outside`; a contradictory mode
fails before the acceptance driver runs. If a local Docker installation cannot
allocate from the range on a host executor, use `--docker-topology host` after
confirming port 8443 is free. Reverting to an empty or zero-valued outside
publication is not a safe CI rollback because affected Docker runners omit the
host mapping; an alternative rollback must pin a qualified Docker toolchain
while preserving the three-unit outside matrix. Removing the relay also
requires replacing the host-executor route; attaching a FileBelt application
service to the publication network is not an equivalent rollback. This change
does not require a migration or production deployment change.
