<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributing to FileBelt

## Contribution certification

FileBelt uses Developer Certificate of Origin 1.1 certification and does not
require a CLA. Sign every commit with:

```text
Signed-off-by: Your Name <your.email@example.com>
```

By adding that line, the contributor certifies the contribution under the
Developer Certificate of Origin 1.1 published at <https://developercertificate.org/>.

## Workflow

1. Read root and component `AGENTS.md` files and accepted ADRs.
2. Enter Plan Mode for changes to persisted state, public protocols, security,
   authorization, images, deployments, or license boundaries.
3. Keep changes small and add the lowest-layer regression test.
4. Run the checks documented in `README.md` and report the exact commands.
5. Follow the [commit-message requirements](#commit-messages).

Pull requests must disclose affected license regions, migrations, images,
public contracts, threat-model changes, and any skipped check with its reason.

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

Hand-authored JavaScript and TypeScript use two-space indentation, double
quotes, semicolons, camelCase values, UPPER_CASE constants, and PascalCase
types and React components. Run `pnpm lint`; warnings fail the check. Files
registered as generated outputs retain semantic lint, typecheck, build, and
generation-drift coverage but are exempt from hand-authored naming and layout
rules. Never edit generated output directly.

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
