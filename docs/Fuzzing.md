<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fuzzing

FileBelt keeps one versioned fuzz catalog in `fuzz/targets.toml`. The catalog,
explicit Cargo bins, reviewed seed manifest, dictionaries, regression fixtures,
resource ceilings, runner, and CI matrices are checked together by repository
contract tests. Fuzz targets are Apache-2.0 test code and use only
side-effect-free, feature-gated exercise surfaces; they do not open files,
read environment configuration, start processes, use a database, or perform
network requests.

| Target | Boundary | Maximum input |
| --- | --- | ---: |
| `nfs_vfs_boundary` | NFS handle, principal, request digest, and VFS validation | 4 KiB |
| `mcp_runner_relay` | MCP invocation, runner hello, and relay framing | 128 KiB |
| `collaboration_wire` | Collaboration frame, awareness, and `yjs-v1` decoder boundary | 256 KiB |
| `revision_protocol` | Revision request and response framing and validation | 1 MiB |
| `runtime_config` | In-memory runtime TOML deserialization and validation | 64 KiB |

`tests/scripts/run-fuzz-target.sh` accepts a cataloged target, the `stable` or
`asan` profile, and the `smoke` or `campaign` mode. Both profiles enforce a
10-second per-input timeout, 3 GiB RSS ceiling, 512 MiB allocation ceiling, and
the target input maximum. Stable smoke uses Rust `1.97.1` without a sanitizer.
ASan uses `nightly-2026-08-04`; sustained campaigns enable leak detection.
ASan runs set runner-owned `ASAN_OPTIONS=allocator_may_return_null=1` so
explicitly fallible allocation attempts return an error to the decoder instead
of making the sanitizer abort before that error path is exercised. Stable runs
and every cataloged input, timeout, RSS, and allocation limit remain unchanged.
This runner-only behavior does not apply to production or mitigate an accepted
dependency risk. The exact runner dependency is `cargo-fuzz 0.13.2` with
`libfuzzer-sys 0.4.13`.

## Accepted collaboration decoder quarantine

`collaboration_wire` remains an active, single-target fuzz quarantine for the
accepted third-party `yrs` decoder risk tracked in
[issue 10](https://github.com/OxiBelt/FileBelt/issues/10). The catalog pins
the exact reviewed dependency identity: `yrs` `0.27.4` from crates.io with its
lockfile checksum. It also verifies that the named manifest binary still points
to the reviewed wrapper, then digest-binds that wrapper, shared fuzz dispatch,
collaboration containment, and checked decoder so the sustained-job exception
cannot outlive a semantic implementation change without explicit review. This
direct-source closure is not a claim about every transitive dependency. The
quarantine does not change the target's input ceiling, smoke coverage,
sanitizer coverage, production protocol, or deployment defaults.

Yrs `0.27.4` hardens several attacker-controlled length-prefixed decoder paths,
including `IdSet`, but the top-level update decoder retains the reviewed
`clients_len` and `blocks_len` reservation paths tracked by issue 10. This
partial hardening does not clear the accepted risk or the quarantine.

FileBelt additionally rejects decoded zero-length Yrs garbage-collection
blocks and contains Rust unwind panics across isolated snapshot/live-update
decode, apply, and full-state re-encode. The libFuzzer target replaces the
runner's aborting hook only while such a panic is inside that reviewed
containment boundary; every panic outside it is forwarded to libFuzzer's
original crash hook. Repository-constructed regressions cover zero-length and
overflowing block ranges plus valid sparse updates. This local containment does
not cover process-aborting allocation failure and therefore does not clear the
top-level reservation risk or issue 10.

Any change to the quarantined target, its digest-bound direct implementation,
or that dependency identity makes the dedicated sustained-matrix verifier fail
and requires review of the quarantine metadata and tracker. Clearance requires
a later upstream distribution whose
relevant decoder allocations have been reviewed, preservation of valid
`yjs-v1` inputs without a new FileBelt wire limit, sanitized snapshot-restore
and live-update regressions, a passing 900-second ASan campaign, and removal of
the quarantine and accepted-risk notices in the same change.

Every pull request, push, schedule, and manual workflow runs 256 iterations for
all five targets under both profiles. Pushes additionally run a blocking
15-minute ASan/LSan campaign per target, except that the exact quarantined
`collaboration_wire` job runs the fail-closed dependency sentinel instead. The
Monday schedule and manual workflow run 60 minutes for each non-quarantined
target and the same sentinel for `collaboration_wire`. Corpora, crash inputs,
coverage output, and raw engine logs are ephemeral. A failing runner prints
only bounded sanitizer summaries and SHA-256 digests of crash inputs. Never
upload an unreviewed crash input to a public workflow artifact or issue.

```sh
cargo install --locked cargo-fuzz --version 0.13.2
tests/scripts/run-fuzz-target.sh --target nfs_vfs_boundary --profile stable --mode smoke --runs 256
```

Before committing a minimized regression, reproduce it privately, determine
that it contains no user or production data, name the file by its SHA-256, add
it to `tests/fixtures/fuzz-regressions/manifest.toml`, and run the regression
and catalog contract tests. Rollback is removal of the target, its reviewed
inputs, and its exact catalog/bin/CI entries in one change; do not leave an
uncataloged target or retained corpus behind.
