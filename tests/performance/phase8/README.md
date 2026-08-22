<!-- SPDX-License-Identifier: Apache-2.0 -->

# Phase 8 executable qualification

Phase 8 compatibility is an executable evidence contract, not a version
sentinel. The exact role catalog is:

- `filebelt-api`;
- `filebelt-worker-io`;
- `filebelt-worker-maintenance`;
- `filebelt-collaboration`;
- `filebelt-media-controller`;
- `filebelt-vfs`; and
- `filebelt-tools`.

`run_local_qualification.py` runs inside the isolated Docker-unit lifecycle.
For API, I/O, and maintenance it repeatedly requests the real internal
`/health/ready` endpoint, requires `204`, and requires an unknown operations
route to return `404`. For collaboration it creates a synthetic Markdown file,
issues real one-use grants through the TLS edge, requires a fresh grant to
return sync frame `0x1a`, requires reuse to return rejection frame `0x4a`,
records fresh-grant latency, and moves the synthetic node to authoritative
trash in `finally`. For tools it executes exact and malformed build-identity
commands through disposable named Compose containers and proves `--rm`
cleanup. Every executed role is bound to the running image's exact build
revision and container-derived instance UUID.

The local development topology does not contain a media controller or VFS
service. Their role results are therefore `skipped`, carry the exact missing
prerequisite, contain no performance sample, and cannot be advertised as
compatible. NFS, media delivery, and WebTransport feature results are likewise
non-accepted until these prerequisites exist:

- NFS needs the qualified Ganesha/FSAL image, a native `krb5p` client, external
  KDC/keytab, administration driver, stable-handle recovery state, and cleanup
  verifier.
- Media needs scoped I/O transfer and callbacks, reconciled Jobs, a qualified
  transcoder image, playback delivery, and the malicious-input corpus.
- WebTransport needs the Kubernetes OxiBelt mTLS HTTP/3 route, operator TLS
  identity, UDP policy, and a WebTransport-capable client fixture.

Generate a quick non-accepted contract result from source-built local images:

```sh
python3 tests/docker/units/run-unit.py \
  --unit phase8-qualification \
  --build \
  --qualification-output artifacts/phase8-local-contract.json
```

Run the real five-minute change workload by adding
`--phase8-mode qualification --phase8-cadence change-smoke`. Longer supported
cadences are `nightly`, `weekly`, and `pre-release`. The runner refuses to
overwrite the evidence path and its ordinary lifecycle removes the unique
Compose project, volumes, networks, state, and fixture tags after the endpoint
driver completes. The output remains `accepted: false` while any reviewed skip
exists; successful harness execution is not release qualification.

Validate evidence separately:

```sh
python3 tests/performance/phase8/phase8_evidence.py \
  --input candidate.json \
  --output phase8-evidence-result.json
```

The validator requires schema `filebelt.phase8.qualification.v2`, configuration
format 9, one exact result per role and feature, source-revision binding,
positive latency samples, exact success and failure assertions, the full
observed cadence duration, and completed or explicitly unnecessary cleanup. A
skip must contain a prerequisite and is always non-accepted. Contract-mode
output is also always non-accepted. The collaboration client trusts only the
runner-generated acceptance CA; it does not disable TLS verification.

When all endpoints become executable, the required cadences remain
`change-smoke` (5 minutes), `nightly` (60 minutes), `weekly` (2 hours), and
`pre-release` (2.5 hours). Same-host/configuration NFS and media p99 regression
may not exceed ten percent; WebTransport must improve on WebSocket p99 by at
least fifteen percent; acknowledged loss and orphan counts must be zero;
memory growth may not exceed one percent per hour; and settled descriptor/task
growth may not exceed five percent.

`filebeltctl phase8 advertise` requires the generated evidence path. The
requested role, instance UUID, source revision, status, assertions, samples,
and cleanup must match. `--incompatible` accepts only `failed` evidence or a
prerequisite-bearing `skipped` result. It does not turn a skip into a pass.
