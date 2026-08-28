<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributing to FileBelt

This is the human-facing source of truth for FileBelt contribution workflow and
the shared contract for every contributor. Files named `AGENTS.md` add
instructions for automated coding agents; people do not need to read them.
Current engineering contracts are indexed in
[`docs/README.md`](docs/README.md).

## Contribution certification

FileBelt uses Developer Certificate of Origin 1.1 certification and does not
require a CLA. Sign every commit with:

```text
Signed-off-by: Your Name <your.email@example.com>
```

By adding that line, the contributor certifies the contribution under the
Developer Certificate of Origin 1.1 published at <https://developercertificate.org/>.

## Workflow

1. Read the applicable living specifications and component documentation.
2. Keep changes small and add the lowest-layer regression test.
3. Update affected specifications, threat models, operator guidance, license
   evidence, compatibility notes, and rollback instructions in the same pull
   request as the behavior change.
4. Run the required checks and report the exact commands and results.
5. Follow the [commit-message requirements](#commit-messages).

Pull requests must disclose affected license regions, migrations, images,
public contracts, threat-model changes, and any skipped check with its reason.

## Design and boundary review

A change to persisted state, namespace or authorization semantics, a public
interface, an external integration or dependency, unsafe-code policy, image or
deployment behavior, recovery, or a license boundary must carry its design
review in the same pull request. State the repository evidence, selected
behavior, credible alternatives, security and license effects, compatibility or
migration path, verification, rollout, and rollback. Update the applicable
living specifications:

- [`NamespaceAndAuthorization.md`](docs/NamespaceAndAuthorization.md);
- [`InterfacesAndCapabilities.md`](docs/InterfacesAndCapabilities.md);
- [`StorageAndDurability.md`](docs/StorageAndDurability.md); and
- [`RuntimeAndDeployment.md`](docs/RuntimeAndDeployment.md).

Do not leave a material security, durability, compatibility, public-contract,
or licensing choice implicit. Ask the maintainer to resolve it before the pull
request is ready to merge. Review history remains in Git and the pull request;
the living documents describe the current contract.

## Code style and repository boundaries

Rust uses the root `rustfmt.toml` policy and workspace lint configuration. Run
`cargo fmt --check` and the locked workspace Clippy command before committing.
The module-size checker reports production Rust files above 750 physical lines:

```sh
tests/scripts/check-rust-module-size.sh --warn
```

The CI check is advisory because dependency direction and module responsibility
are authoritative. Use `--enforce` only for focused decomposition work, and set
`FILEBELT_RUST_SOURCE_LINE_LIMIT` only when testing the checker itself.

Run `tests/scripts/check-cargo-boundaries.sh` after changing a Cargo manifest,
feature, import boundary, crate-root public module, or wildcard re-export. The
versioned policy in `supply-chain/cargo-boundaries-v1.toml` is reviewed by hand;
the checker deliberately has no command that automatically accepts a new
baseline. A new adapter manifest must first receive its component-specific
license, graph, formatting, lint, and test policy and must remain outside the
root workspace.

Hand-authored JavaScript and TypeScript use two-space indentation,
formatter-compatible preferred single quotes (including JSX attributes), and
omit safely removable semicolons. Hand-authored TypeScript uses PascalCase for
variable-like declarations, parameter properties, class and type properties,
methods, accessors, signatures, and type-like declarations. Constructors,
computed members, imports, and object-literal keys are outside the naming rule.
React custom hooks retain the required `useX` spelling through a filtered
exception; custom React callback props use PascalCase.

Names fixed by platform APIs, wire formats, persisted browser formats, or
third-party contracts retain their external spelling only at the relevant
boundary. Alias their local bindings to PascalCase and use a narrowly scoped,
rationale-bearing `filebelt/pascal-case` disable only when the declaration
itself must keep the external name. Run `pnpm format:check` and `pnpm lint`;
warnings fail the lint check. Use `pnpm format` to apply the repository
formatter. Files
registered as generated outputs retain semantic lint, typecheck, build, and
generation-drift coverage but are exempt from hand-authored naming and layout
rules. Never edit generated output directly.

## Required checks

Run the applicable repository checks from the root. The complete bootstrap
suite is:

```sh
python3 tests/scripts/check-source-structure.py --repo-root .
python3 tests/scripts/check-markdown-links.py --repo-root .
python3 tests/scripts/check-generated.py --repo-root .
tests/scripts/check-rust-module-size.sh --warn
tests/scripts/check-cargo-boundaries.sh
reuse lint
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo audit
cargo deny check
cargo vet --locked
corepack pnpm install --frozen-lockfile --ignore-scripts
pnpm licenses list --json | python3 tests/scripts/check-node-licenses.py --policy supply-chain/node-policy.toml
pnpm audit --audit-level high
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

Run targeted Docker, browser, Kubernetes, release, and integration commands
when the affected artifact exists. Do not substitute a placeholder check. A
pull request may omit an inapplicable or unavailable check only when it records
the reason.

The bounded fuzz runner and cataloged Docker units use these forms:

```sh
cargo install --locked cargo-fuzz --version 0.13.2
tests/scripts/run-fuzz-target.sh --target nfs_vfs_boundary --profile stable --mode smoke --runs 256
python3 tests/docker/units/run-unit.py --unit core --build
python3 tests/docker/units/run-unit.py --unit core --image-dir artifacts/phase1 --image-channel build --diagnostics-dir artifacts/docker/core
```

`--build` is local source-build integration. `--image-dir` is exact-artifact
integration and must use `--image-channel build` for CI archives or
`--image-channel release` for signed-tag archives. Collaboration additionally
requires the frozen pnpm workspace and installed pinned Playwright Chromium and
Firefox binaries. Fuzz crash inputs and Docker diagnostics can contain security
evidence; keep unreviewed inputs private and retain only the runner's scrubbed,
bounded synthetic diagnostics.

## Commit messages

Use Conventional Commits for commit messages:

```text
<type>(<scope>): <subject>
```

- `type` must be one of `feat`, `fix`, `chore`, `docs`, `ci`, `refactor`,
  `security`, `tests`, or `perf`.
- `scope` is the field, area, or responsibility touched by the change, such as
  `repository`, `authz`, `storage`, `protocol`, `adapters`, `ui`, `workflows`,
  or `docs`.
- `subject` is a short imperative summary. Use a present-tense verb. Do not use
  past-tense or past-perfect wording.
- In the commit title and detailed description, wrap code keywords, paths,
  commands, configuration keys, header names, function names, variable names,
  type names, module names, package names, and literal values in Markdown
  inline code spans with backticks.

Valid examples:

```text
docs(repository): document `AGENTS.md` precedence
fix(storage): reject `..` payload traversal
security(authz): require resolved principals for object access
ci(workflows): run adapter integration matrix
```

Avoid examples like `fixed payload validation`, `added ACL tests`, or
`has updated docs` because the subject is not imperative present tense. Also
avoid leaving identifiers unformatted, such as `update filebelt-authz`; write
``update `filebelt-authz``` instead.

## Licensing

Contributions inherit the license of their destination region. Never copy or
move code between regions without confirming relicensing authority. New source
files need an SPDX identifier; generated files must identify their source,
generator, regeneration command, and resulting license.

Dependencies use exact versions and reviewed registries. Package lifecycle
scripts, native libraries, non-permissive licenses, and Git dependencies require
explicit admission before use.
