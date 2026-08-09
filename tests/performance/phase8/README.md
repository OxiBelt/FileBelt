<!-- SPDX-License-Identifier: Apache-2.0 -->

# Phase 8 delivery evidence

`phase8_evidence.py` validates a machine-readable result from the NFS, media,
and collaboration transport performance harnesses. It deliberately does not
generate load: each workload owns its functional fixture and records an
immutable configuration digest, same-host baseline, and the measurements below.

The required cadences are `change-smoke` (5 minutes), `nightly` (60 minutes),
`weekly` (2 hours), and `pre-release` (2.5 hours). The checker rejects a run
whose duration does not exactly match its cadence. It also rejects a baseline
from a different host or configuration, NFS or media p99 regression above ten
percent, WebTransport improvement below fifteen percent against WebSocket,
acknowledged loss/orphans, memory growth above one percent per hour, or settled
descriptor/task growth above five percent.

Run it after a workload has written `candidate.json`:

```sh
python3 tests/performance/phase8/phase8_evidence.py \
  --input candidate.json --output phase8-evidence.json
```

The output is an immutable release-gate input. The workflow retains both the
input and result; it does not publish an image, chart, or baseline.
