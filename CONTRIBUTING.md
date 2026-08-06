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
5. Use a Conventional Commit subject: `<type>(<scope>): <imperative subject>`.

Pull requests must disclose affected license regions, migrations, images,
public contracts, threat-model changes, and any skipped check with its reason.

## Licensing

Contributions inherit the license of their destination region. Never copy or
move code between regions without confirming relicensing authority. New source
files need an SPDX identifier; generated files must identify their source,
generator, regeneration command, and resulting license.

Dependencies use exact versions and reviewed registries. Package lifecycle
scripts, native libraries, non-permissive licenses, and Git dependencies require
explicit admission before use.
