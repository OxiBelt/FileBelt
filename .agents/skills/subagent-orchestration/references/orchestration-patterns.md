# Detailed Orchestration Patterns

Use this reference when the primary `SKILL.md` needs more detail for a large feature, difficult bug, refactor, review, or unusual delegation edge case.

## Reconnaissance fan-out

At the beginning of a large task, assign non-overlapping questions such as:

- architecture and ownership map;
- existing implementation patterns;
- tests and fixtures;
- runtime/deployment surface;
- relevant documentation and contracts.

Each worker returns only evidence that affects the requested task. Do not ask every worker to understand the whole repository.

## Hypothesis fan-out for debugging

Assign one credible cause per investigator, such as:

- lifecycle/state management;
- persistence/transaction behavior;
- race/concurrency behavior;
- API/schema mismatch;
- environment/configuration;
- frontend/browser behavior.

Require each investigator to seek falsifying evidence. The primary agent compares results before changing code.

## Read/write separation

Default sequence:

1. several read-only workers map the problem;
2. primary agent chooses the design;
3. one implementer edits an isolated surface;
4. independent review/test workers validate it;
5. primary agent integrates or corrects the result.

Read-heavy parallelism is the default. Write-heavy parallelism requires explicit ownership boundaries.

## Partitioned implementation

Good partitions include:

- backend endpoint vs independent frontend component;
- implementation vs independent test-fixture package;
- separate adapters behind a fixed interface;
- independent migration tooling vs documentation after migration semantics are fixed;
- separate packages communicating through an existing stable contract.

Before parallel writers start, define exact ownership, stable shared interfaces, shared-file ownership, validation, and integration order.

## Implementer plus adversarial reviewer

The implementer produces the bounded patch and targeted tests. The reviewer assumes the patch may be wrong and checks regressions, missing cases, contract violations, and weak tests.

Do not give the reviewer the implementer's chain of reasoning. Give requirements, relevant policy, and resulting state/diff.

## Test-matrix fan-out

Useful independent slices include:

- unit tests;
- integration tests;
- browser/UI validation;
- protocol compatibility;
- container/image checks;
- Kubernetes/runtime smoke tests;
- lint/type/static analysis;
- migration/rollback checks.

Workers return exact command, status, relevant error excerpt, and likely ownership area. Avoid parallel tests that contend for the same mutable environment.

## Independent contract review

Specialized read-only workers may check:

- security and authorization;
- persistence/durability;
- public API compatibility;
- protocol compliance;
- accessibility;
- performance regressions;
- licensing/dependency boundaries;
- deployment/rollback behavior.

Workers identify issues and evidence; the primary agent retains unresolved semantic choices.

## Documentation/code consistency

After implementation, compare:

- code vs living specifications;
- CLI/API behavior vs documentation;
- configuration schema vs examples;
- tests vs documented guarantees;
- dependency changes vs notices/licenses;
- deployment changes vs operator instructions.

Return only inconsistencies requiring action.

## Large-input digestion

Partition large inputs by meaningful boundary and require a common output schema. Do not have every worker independently summarize the entire corpus unless intentional redundancy is the evaluation method.

## Redundant cross-check

Use two independent workers on the same narrow question only when a wrong answer is costly and the result is objectively checkable, for example:

- race-condition analysis;
- migration safety;
- protocol interpretation against fixed documentation;
- one high-risk security invariant;
- suspicious benchmark/test results.

Agreement without evidence is insufficient.

## Feature recipe

1. Forager maps architecture and ownership.
2. Test forager locates fixtures and expected behavior.
3. Policy auditor checks cross-cutting constraints when relevant.
4. Primary agent fixes design and write boundaries.
5. Isolated implementers work only where write sets separate cleanly.
6. Reviewer and targeted verifier inspect the result.
7. Primary agent integrates and performs final checks.

## Difficult-bug recipe

1. Primary agent states observable symptoms and constraints.
2. Spawn one investigator per credible independent hypothesis.
3. Require falsifying evidence.
4. Primary agent selects the supported root cause.
5. One bounded implementer fixes it.
6. Independent verifier reproduces before/after behavior.

## Large-refactor recipe

1. Readers map dependency direction, call sites, tests, and compatibility constraints.
2. Primary agent defines target abstraction and migration strategy.
3. One owner establishes the shared abstraction.
4. Fan out mechanical migrations by independent package/module.
5. Run parallel isolated validation slices.
6. Independent architectural reviewer checks missed legacy paths.
7. Primary agent resolves integration and cleanup.

## Pull-request review recipe

Use distinct read-only categories only when relevant:

- correctness/regressions;
- security/authorization;
- concurrency/state;
- tests/failure coverage;
- maintainability/architecture;
- compatibility/licensing.

Deduplicate and verify findings before reporting them.

## Incident recipe

Parallelize evidence gathering and verification instead of many writers racing to patch the same system:

`investigator fan-out -> primary root-cause decision -> single focused fix -> independent verification`

## Edge-case reminders

- Workers may be unable to receive fresh interactive approvals. Avoid critical unattended workflows that depend on them.
- Give each worker the minimum sensitive context required; never copy secrets into summaries.
- For generated files and lockfiles, assign one owner.
- For browser/device/database/Kubernetes resources, isolate deterministically or serialize.
- For mixed-license repositories, define package/directory write boundaries and validate dependency direction.
- For destructive actions, delegate analysis rather than authorization.
- For poorly specified product intent, gather evidence but do not manufacture a decision through worker consensus.
