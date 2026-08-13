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
| `collaboration_wire` | Collaboration frame and awareness decoding | 256 KiB |
| `revision_protocol` | Revision request and response framing and validation | 1 MiB |
| `runtime_config` | In-memory runtime TOML deserialization and validation | 64 KiB |

`tests/scripts/run-fuzz-target.sh` accepts a cataloged target, the `stable` or
`asan` profile, and the `smoke` or `campaign` mode. Both profiles enforce a
10-second per-input timeout, 3 GiB RSS ceiling, 512 MiB allocation ceiling, and
the target input maximum. Stable smoke uses Rust `1.97.1` without a sanitizer.
ASan uses `nightly-2026-08-04`; sustained campaigns enable leak detection.
The exact runner dependency is `cargo-fuzz 0.13.2` with
`libfuzzer-sys 0.4.13`.

Pull requests run 256 iterations for all five targets under both profiles.
Main pushes run a blocking 15-minute ASan/LSan campaign per target. The Monday
schedule and manual workflow run 60 minutes per target. Corpora, crash inputs,
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
