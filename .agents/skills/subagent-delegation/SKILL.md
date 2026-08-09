---
name: subagent-delegation
description: Aggressively orchestrate Codex subagents for complex software-engineering work while keeping the primary agent focused on requirements, decisions, integration, and final validation. Use for codebase exploration, debugging, implementation decomposition, tests, reviews, documentation, research, and other work that can be split into bounded tasks. Do not trigger for trivial work, tightly sequential tasks with no useful independent branch, or when delegation would duplicate more context than it saves.
---

# Subagent Orchestration

Use subagents as disposable, bounded workers that reduce primary-thread context pollution and parallelize independent engineering work.

The primary agent remains the coordinator and final decision-maker. Subagents gather evidence, execute well-scoped work, challenge assumptions, validate results, or implement isolated changes. They should not become a second unbounded primary agent.

This skill intentionally does not prescribe the primary agent's Normal Mode or Plan Mode behavior. It only defines how to use subagents around those modes.

## Core policy

For non-trivial work, actively look for useful delegation before doing all work in the primary thread.

Prefer this split:

- **Primary agent:** requirements, architecture, decomposition, risk decisions, cross-cutting semantics, integration, final judgment, and user-facing synthesis.
- **Subagents:** repository reconnaissance, bounded implementation, hypothesis testing, test execution, log analysis, targeted research, independent review, documentation checks, and evidence collection.

The default question is not "Can a subagent do this?" but:

> "Which independent parts can be delegated without giving away final ownership or creating coordination debt?"

Do not delegate merely to maximize agent count. Delegate when a worker can return a useful result with substantially less context than the primary agent would otherwise accumulate.

## Default model policy

Treat model names as replaceable policy aliases. If a named model or reasoning level is unavailable, choose the nearest available model with the same role characteristics.

### Preferred worker tiers

Use `gpt-5.6-terra` at `medium` reasoning as the default high-throughput worker for:

- repository search and mapping;
- locating ownership and call paths;
- reading many files and returning distilled evidence;
- test discovery;
- documentation inventory;
- dependency or configuration reconnaissance;
- straightforward implementation in an isolated surface;
- mechanical or repetitive analysis.

Raise `gpt-5.6-terra` to `high` when the bounded task requires:

- tracing non-obvious control or data flow;
- comparing several plausible hypotheses;
- reasoning across a handful of interacting modules;
- reviewing concurrency, lifecycle, or state transitions;
- identifying meaningful edge cases;
- producing a stronger implementation or review within a clearly fixed scope.

Use `gpt-5.6-luna` for narrow, explicit, high-volume tasks where scope and success criteria are exceptionally clear. If `max` reasoning is available and cost-effective in the current environment, `gpt-5.6-luna max` can be used as a precision worker for a narrow but difficult check. Do not use a high-effort Luna worker as a substitute for the primary agent on an ambiguous or architecture-heavy problem.

### Escalation rule

Escalate a subtask to a stronger model, or return it to the primary agent, when any of these becomes true:

- the worker discovers that the task is materially broader than its packet;
- multiple repository-wide semantics must be chosen rather than merely observed;
- the result depends on unresolved product or architecture intent;
- security, authorization, persistence, compatibility, licensing, or public-contract meaning is ambiguous;
- the worker repeatedly fails to validate its own conclusion;
- the requested change crosses several ownership boundaries and cannot be safely isolated.

Do not keep increasing reasoning effort on a badly scoped task. Fix the task boundary first.

## Delegation threshold

Strongly prefer delegation when at least one of these applies:

- useful work can proceed independently in two or more branches;
- the primary agent would otherwise need to read a large amount of low-signal material;
- a task benefits from an independent second opinion;
- several hypotheses can be tested in parallel;
- several test families or runtime surfaces can be validated independently;
- implementation can be partitioned by non-overlapping ownership boundaries;
- a reviewer can inspect a completed change without needing to edit it;
- external documentation or supporting evidence can be collected independently;
- logs, traces, generated output, or large files would pollute the primary context.

Usually keep work in the primary thread when:

- the task is tiny and obvious;
- delegation requires nearly the same context as the whole task;
- every next step depends immediately on the previous step;
- all workers would edit the same hot files;
- only one short validation command is needed;
- the task is mostly a single semantic decision that the primary agent must own.

## The bounded-task rule

Every subagent must receive a bounded task packet.

A good packet contains only:

1. **Objective** — one concrete outcome.
2. **Scope** — files, modules, subsystem, hypothesis, or test surface to inspect.
3. **Constraints** — rules that cannot be violated.
4. **Expected output** — exactly what the worker should return.
5. **Validation** — checks the worker should run when applicable.
6. **Stop conditions** — conditions that require returning to the primary agent instead of guessing.

Avoid giving a subagent the entire conversation unless the entire conversation is truly required.

Do not make the worker rediscover known decisions. Include the minimum authoritative context needed to perform the assigned task.

### Recommended task packet

Use a packet shaped like this:

```text
Objective:
<one bounded objective>

Scope:
<files/modules/questions this worker owns>

Known context:
<only facts or decisions needed for this task>

Constraints:
- <constraint>
- <constraint>

Do:
- <specific work>
- <specific validation>

Do not:
- expand scope without reporting it;
- make unresolved architecture/product/security/licensing decisions;
- edit outside the assigned write set unless required for correctness and explicitly reported.

Return:
- concise conclusion;
- evidence with file paths and relevant symbols/lines where practical;
- commands/tests run and their outcomes;
- changed files, if any;
- uncertainties, risks, or blockers;
- recommended next action.
```

## Output contract

Subagents should return **distilled evidence**, not a transcript of their work.

Prefer:

- findings with paths and symbols;
- concrete failure causes;
- minimal reproduction steps;
- test results;
- patch summary;
- unresolved questions;
- confidence and caveats when appropriate.

Avoid:

- long narration;
- raw search output;
- huge logs unless specifically requested;
- repeating repository documentation the primary agent already has;
- speculative conclusions without evidence;
- broad redesign proposals when the task was narrow.

The primary agent should inspect evidence before accepting a consequential conclusion.

## High-value orchestration patterns

### 1. Reconnaissance fan-out

Use at the beginning of a large task when the repository shape is not yet clear.

Spawn a small set of read-oriented workers with non-overlapping questions, for example:

- architecture and ownership map;
- existing implementation patterns;
- tests and fixtures;
- runtime/deployment surface;
- relevant documentation and contracts.

Each worker returns only what affects the requested task.

After all results arrive, the primary agent reconciles contradictions and chooses the implementation path.

Do not ask every worker to "understand the whole repo."

### 2. Hypothesis fan-out for debugging

When a bug has several credible causes, assign one hypothesis per worker.

Examples:

- state-management/lifecycle cause;
- persistence or transaction cause;
- race or concurrency cause;
- API/schema mismatch;
- environment/configuration cause;
- frontend rendering or browser behavior.

Require each worker to attempt to falsify its own hypothesis and report evidence.

The primary agent compares the results before changing code.

This is often better than letting one long-running thread become anchored on its first theory.

### 3. Read/write separation

Use read-only workers aggressively even when parallel code editing would be unsafe.

A common pattern is:

1. several read-only workers map the problem;
2. the primary agent selects one design;
3. one implementation worker edits an isolated surface;
4. separate review/test workers validate the result;
5. the primary agent integrates or corrects the patch.

Read-heavy parallelism is the default. Write-heavy parallelism requires explicit ownership boundaries.

### 4. Partitioned implementation

Parallel implementation is appropriate only when write sets are genuinely separable.

Good partitions include:

- backend endpoint vs independent frontend client component;
- implementation vs test fixture package;
- separate adapters behind an already-fixed interface;
- independent migration tooling vs documentation, after migration semantics are fixed;
- separate packages that communicate through an existing stable contract.

Before spawning writers, define:

- exact ownership boundaries;
- shared interfaces that must not change independently;
- which worker, if any, owns shared files;
- validation each worker must run;
- integration order.

If two workers are likely to touch the same central files, prefer sequential implementation or make one worker read-only.

### 5. Implementer + adversarial reviewer

For meaningful code changes, consider using two different workers:

- **Implementer:** produces the bounded patch and targeted tests.
- **Reviewer:** assumes the patch may be wrong and searches for regressions, missing cases, contract violations, and weak tests.

Do not give the reviewer the implementer's chain of reasoning. Give it the task requirements, relevant policy, and resulting diff/state so it can form an independent judgment.

The primary agent decides which review findings are valid.

### 6. Test-matrix fan-out

When validation spans independent surfaces, delegate by surface rather than running everything serially in the main thread.

Examples:

- unit tests;
- integration tests;
- browser/UI validation;
- protocol compatibility tests;
- container/image checks;
- Kubernetes/runtime smoke tests;
- lint/type/static analysis;
- migration and rollback checks.

Workers should return the exact failing command, relevant error excerpt, and likely ownership area rather than full logs.

Do not parallelize tests that contend for the same mutable environment unless isolation is guaranteed.

### 7. Independent contract review

Use specialized review workers for cross-cutting constraints such as:

- security and authorization;
- persistence and durability;
- public API compatibility;
- protocol compliance;
- accessibility;
- performance regressions;
- licensing and dependency boundaries;
- deployment and rollback behavior.

These workers may identify issues and gather evidence. They must not silently choose unresolved semantics on behalf of the primary agent or maintainer.

### 8. Documentation and code consistency check

After implementation, use a read-oriented worker to compare:

- code vs living specifications;
- CLI/API behavior vs user documentation;
- configuration schema vs examples;
- tests vs documented guarantees;
- dependency changes vs notices/license records;
- deployment changes vs operator instructions.

Return only inconsistencies that require action.

### 9. Large-file or large-document digestion

For large inputs, partition by meaningful boundaries and assign one worker per section or question.

Require a common output schema so the primary agent can merge results reliably.

Do not have every worker summarize the entire corpus independently unless redundancy is intentionally being used as an evaluation technique.

### 10. Cross-check by redundancy

Use two independent workers on the same narrow question when the cost of a wrong answer is high and the result is objectively checkable.

Useful for:

- tricky algorithmic reasoning;
- race-condition analysis;
- migration safety analysis;
- protocol interpretation against fixed documentation;
- security review;
- suspicious benchmark or test results.

Ask each worker for evidence. Agreement without evidence is not sufficient.

Do not use redundant workers for routine mechanical tasks by default.

## Recommended agent roles

These are conceptual roles. They may be implemented as custom Codex agents when useful, or expressed directly in the delegation prompt.

### Forager

Default model: `gpt-5.6-terra medium`.

Responsibilities:

- fast repository search;
- identify relevant files and symbols;
- map call/data flow;
- locate tests, docs, and existing patterns;
- return evidence only.

Default permissions: read-only when possible.

### Investigator

Default model: `gpt-5.6-terra high`.

Responsibilities:

- test a bounded debugging hypothesis;
- trace a complex local behavior;
- analyze logs or failures;
- identify root-cause candidates and falsifying evidence.

Prefer no edits until a cause is supported.

### Implementer

Default model: `gpt-5.6-terra high` for a bounded implementation; use a stronger worker only when the implementation remains clearly scoped but requires more depth.

Responsibilities:

- edit only the assigned ownership surface;
- follow an already-decided contract;
- add or update targeted tests;
- report every touched file and validation result.

Must stop if implementation requires changing an unresolved shared contract.

### Precision worker

Default model: `gpt-5.6-luna` with an effort level appropriate to the task; `max` may be used for a narrow but difficult task when available.

Responsibilities:

- execute an extremely clear, constrained task;
- perform repetitive checks at high throughput;
- compare structured artifacts;
- validate a precise invariant;
- make a small mechanical change with explicit acceptance criteria.

Do not expand into architecture or broad debugging.

### Reviewer

Default model: `gpt-5.6-terra high` or a stronger model if the review is particularly consequential.

Responsibilities:

- review the resulting code or diff adversarially;
- check edge cases and failure paths;
- evaluate test quality;
- identify contract violations;
- report actionable findings with evidence.

Should normally be read-only.

### Test runner / verifier

Default model: `gpt-5.6-terra medium`.

Responsibilities:

- run an assigned validation slice;
- minimize or classify failures;
- return concise results;
- distinguish pre-existing failures from introduced failures when evidence allows.

Avoid unrelated fixes unless assigned separately.

### Policy auditor

Default model: `gpt-5.6-terra high`.

Responsibilities:

- compare a proposed or completed change against security, persistence, compatibility, licensing, accessibility, or deployment rules;
- cite repository evidence;
- flag unresolved semantic choices for the primary agent.

Normally read-only.

## Primary-agent workflow

For a complex task, the coordinator should normally follow this loop.

### Phase A — Identify delegation opportunities

Before deep exploration, identify:

- independent questions;
- noisy evidence-gathering work;
- separable implementation surfaces;
- independent validation surfaces;
- areas needing adversarial review.

Spawn only workers that have a concrete return value.

### Phase B — Gather and reconcile evidence

Wait for the workers needed for the next decision.

Compare their results rather than concatenating them.

Resolve:

- contradictory file ownership claims;
- inconsistent assumptions;
- duplicate proposed changes;
- findings unsupported by repository evidence.

If a contradiction matters, send a narrow follow-up to one worker or launch a tie-breaker rather than re-running the entire investigation.

### Phase C — Make the decision centrally

The primary agent owns:

- architecture choices;
- public behavior;
- data semantics;
- security boundaries;
- irreversible operations;
- scope changes;
- integration choices;
- final acceptance.

Subagent consensus does not transfer this responsibility.

### Phase D — Execute with controlled write ownership

Prefer one writer per ownership surface.

Keep shared contracts stable during parallel implementation. If a contract must change, pause dependent writers, change or decide the contract centrally, then resume with updated packets.

### Phase E — Validate independently

After meaningful changes, assign at least one independent validation path when useful:

- reviewer;
- targeted test worker;
- policy auditor;
- browser/runtime verifier;
- documentation consistency checker.

The validation worker should inspect the resulting state, not merely trust the implementer's summary.

### Phase F — Integrate and close

The primary agent should:

- inspect changed files or diff;
- resolve conflicting worker edits;
- run or confirm the critical final checks;
- ensure requirements are satisfied as a whole;
- report only the final integrated outcome to the user.

Close or stop workers whose results are no longer useful.

## Concurrency guidance

Favor a modest number of high-utility workers over an unbounded swarm.

A useful default shape for complex software tasks is:

- 2–4 reconnaissance workers for genuinely separate questions;
- 1 writer per independent write surface;
- 1–3 validation/review workers for materially different risks.

Increase concurrency when tasks are homogeneous, read-heavy, cheap to specify, and objectively mergeable.

Decrease concurrency when tasks share mutable state, edit common files, require scarce environments, or depend on rapidly evolving decisions.

Never spawn multiple workers whose packets are effectively identical unless intentional redundancy is the goal.

## Context-efficiency rules

Subagents are valuable partly because they isolate noisy intermediate work. Preserve that advantage.

The primary agent should not pull full worker transcripts into its own reasoning unless necessary.

Ask workers to summarize:

- what matters;
- evidence;
- changed state;
- validation;
- blockers.

Do not repeatedly resend the entire repository policy or full plan to every worker. Pass only applicable rules and direct references to authoritative files the worker can read.

When a worker needs substantial repository context, prefer instructing it which authoritative files to read rather than pasting their complete contents.

## Rate-limit and token-efficiency policy

Subagents are not free. Aggressive use means **high delegation leverage**, not indiscriminate fan-out.

Optimize for useful conclusions per worker:

- delegate noisy work that would otherwise consume primary-agent context;
- bundle closely related read-only questions when they need the same files;
- split tasks when the branches are actually independent;
- stop a worker after its objective is satisfied;
- avoid asking several workers to rediscover the same obvious fact;
- use lower-cost workers for scanning and mechanical checks;
- reserve high reasoning for bounded tasks that demonstrably need it;
- use independent high-effort review selectively for high-risk changes.

If a subagent repeatedly returns low-value summaries, reduce its scope or stop delegating that class of task.

## Exceptions and special cases

### Trivial changes

Do not delegate a one-line or obviously local change merely because subagents are available.

Examples:

- typo fixes;
- obvious import correction;
- small rename contained in one file;
- a single deterministic command with a known expected result.

The coordination overhead is larger than the context saved.

### Tightly sequential debugging

If each debugging step depends on a freshly observed result from the previous command and there are no credible independent hypotheses, keep the loop in one thread.

Introduce subagents only when the problem branches into independent hypotheses, logs, subsystems, or validation surfaces.

### Shared hot files

Avoid concurrent writers when most changes converge on the same central files, generated lockfiles, schema files, or configuration manifests.

Use readers in parallel, then one writer, then parallel reviewers.

### Migrations and persisted data

Subagents may:

- inspect existing schemas;
- identify affected code;
- analyze compatibility;
- propose migration options;
- review rollback behavior;
- run isolated migration tests.

They must not independently choose ambiguous durability, compatibility, data-loss, or rollback semantics. The primary agent must own that decision and follow repository escalation rules.

### Security and authorization

Subagents are strongly encouraged for threat-oriented review, permission-path tracing, and adversarial validation.

However, do not let a worker silently invent or weaken authentication, authorization, tenancy, principal, ACL, secret-handling, or trust-boundary semantics.

If repository policy and requested behavior do not resolve the choice, return the issue to the primary agent or maintainer.

### Public APIs and compatibility

Workers may inventory callers, schemas, protocol behavior, and compatibility risks.

The primary agent must own any unresolved decision that changes public behavior, compatibility guarantees, wire formats, or versioning semantics.

### Licensing and dependency boundaries

Workers may inspect licenses, dependency direction, notices, and package boundaries.

Do not let a subagent resolve a license-boundary ambiguity by convenience. Escalate unresolved choices and preserve repository policy.

### Irreversible or destructive operations

Use subagents to analyze and validate, not to independently authorize destructive actions.

Destructive database operations, history rewriting, deleting externally meaningful resources, publishing releases, rotating secrets, or similarly consequential actions require the same primary-agent/user approval discipline as if no subagent were present.

### External side effects and approvals

A worker may not be able to request a fresh approval in some execution contexts. Prefer read-only or non-destructive packets when approval behavior is uncertain.

Do not design a critical workflow that depends on an unattended subagent successfully receiving an interactive approval.

### Scarce or stateful test environments

If browser sessions, device farms, Docker resources, Kubernetes namespaces, databases, hardware, or other environments are shared and stateful, parallel test workers can interfere with each other.

Either allocate isolated resources with deterministic naming/cleanup or serialize the affected validation.

### Generated files and lockfiles

If several writers would regenerate the same lockfile, generated source, schema snapshot, or manifest, assign one owner for that artifact and have other workers avoid touching it.

### Large refactors

Do not partition a refactor solely by file count. Partition by stable architectural ownership boundaries.

If the refactor changes a central abstraction, first decide and land the abstraction shape, then fan out mechanical migrations to workers.

### Incident or emergency work

When speed matters but correctness is critical, parallelize evidence gathering and verification rather than letting many writers race to patch the same system.

A useful pattern is: investigator fan-out -> primary-agent root-cause decision -> single focused fix -> independent verification.

### Highly sensitive information

Give each worker the minimum secret or sensitive context necessary. Prefer references to protected tooling over copying secrets into prompts or summaries.

Do not reproduce secrets in worker return payloads.

### Poorly specified user intent

Subagents cannot compensate for an unresolved requirement that materially changes the solution.

They may gather evidence about existing behavior or enumerate options, but the primary agent should not manufacture user intent through subagent consensus.

## Anti-patterns

Avoid these behaviors.

### "Everyone inspect everything"

Multiple workers reading the whole repository with the same vague goal wastes tokens and produces redundant summaries.

### Delegating the final decision

Do not ask a subagent to "decide the architecture" or "pick the safest semantics" without a bounded decision framework. The primary agent owns consequential choices.

### Unbounded recursive delegation

A subagent should normally complete its task personally. Do not create deep trees of delegation unless the environment explicitly supports it and the decomposition genuinely benefits from hierarchy.

### Parallel edits without ownership

Never assume conflicting patches will be cheap to merge. Assign write ownership before spawning implementation workers.

### Reviewer priming

Do not feed a reviewer the implementer's full rationale and expected conclusion. Preserve enough independence to catch mistakes.

### Treating worker confidence as evidence

A confident summary without paths, tests, reproduction, or concrete reasoning is not validation.

### Retrying the same bad packet

If a worker fails twice because the scope is ambiguous, do not simply rerun it at higher effort. Re-scope the task or return it to the primary agent.

### Using expensive reasoning for mechanical scanning

Do not spend maximum reasoning on grep-like work, file inventories, or deterministic formatting checks unless there is an unusual reason.

### Blindly trusting passing tests

A verifier must check whether the tests meaningfully cover the requested behavior. A green test suite does not prove the change is correct if the relevant case is absent.

## Decision matrix

Use this matrix as a default, not an absolute rule.

| Work type | Delegate? | Suggested worker | Parallelism | Notes |
| --- | --- | --- | --- | --- |
| Repository exploration | Yes | Terra medium | High | Prefer read-only fan-out by question |
| Large-file review | Yes | Terra medium | High | Return distilled findings |
| Complex local logic trace | Yes | Terra high | Medium | Bound by subsystem/hypothesis |
| Ambiguous architecture choice | Supporting work only | Terra high readers | Medium | Primary agent decides |
| Narrow mechanical change | Sometimes | Luna or Terra medium | Medium | Only if coordination cost is justified |
| Bounded non-trivial implementation | Yes | Terra high | Medium | One writer per write surface |
| Multiple edits to same core files | Usually no parallel writers | One implementer | Low | Parallelize review instead |
| Unit/integration test slices | Yes | Terra medium | High if isolated | Avoid shared mutable environment |
| Security review | Yes | Terra high | Medium | Independent evidence; primary owns semantics |
| Migration safety review | Yes | Terra high | Medium | Primary owns persistence decisions |
| Documentation consistency | Yes | Terra medium | High | Best after implementation |
| Final integration judgment | No | Primary agent | N/A | Never outsource final ownership |

## Example orchestration recipes

### Feature spanning several layers

1. Spawn a forager for relevant architecture and ownership.
2. Spawn a test forager for existing fixtures and expected behavior.
3. Spawn a policy auditor if the feature touches a cross-cutting contract.
4. Primary agent fixes the design and write boundaries.
5. Spawn isolated implementers only where write sets are separable.
6. Spawn a reviewer and targeted verifier after the patch exists.
7. Primary agent integrates and performs final checks.

### Difficult bug

1. Primary agent states observable symptoms and known constraints.
2. Spawn one investigator per credible independent hypothesis.
3. Require falsifying evidence from each.
4. Primary agent selects the supported root cause.
5. Use one bounded implementer for the fix.
6. Use an independent verifier to reproduce before/after behavior.

### Large refactor

1. Spawn readers to map dependency direction, call sites, and tests.
2. Primary agent defines the target abstraction and compatibility strategy.
3. Land or establish the shared abstraction with a single owner.
4. Fan out mechanical migrations by independent package/module.
5. Run parallel test slices.
6. Run an independent architectural review for missed legacy paths.
7. Primary agent resolves integration issues and completes cleanup.

### Pull request review

Spawn separate read-only workers for materially different categories, such as:

- correctness and regressions;
- security/authorization;
- concurrency/state behavior;
- tests and failure coverage;
- maintainability/architecture;
- compatibility or licensing when relevant.

Wait for the relevant workers, deduplicate findings, verify evidence, and report only validated issues.

## Repository-policy interaction

Repository instructions always apply to delegated work.

When an applicable `AGENTS.md`, living specification, security policy, contribution guide, or component overlay defines escalation or validation rules:

- include the relevant path in the worker packet;
- require the worker to read it before acting within that boundary;
- do not let generic advice in this skill override repository-specific policy;
- stop delegation-based implementation when repository rules require a maintainer decision.

For mixed-license repositories, assign explicit package or directory boundaries to writers and verify that dependency direction remains legal and intentional.

## Completion criteria

A subagent-assisted task is not complete merely because all workers returned.

The primary agent must confirm that:

- required worker results were received;
- important claims are supported by evidence;
- contradictory findings were resolved;
- code edits respect ownership and repository policy;
- required tests or checks actually ran, or missing validation is clearly reported;
- unresolved high-risk semantics were not guessed;
- the integrated result satisfies the original request;
- worker-generated noise was distilled rather than copied wholesale into the final response.

## Compact operational rule

When in doubt, use this sequence:

> **Fan out evidence -> centralize decisions -> isolate writes -> fan out validation -> centralize integration.**

This is the default shape for aggressive, efficient subagent use.
