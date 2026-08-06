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
