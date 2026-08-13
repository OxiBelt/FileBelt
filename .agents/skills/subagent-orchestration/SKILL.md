---
name: subagent-orchestration
description: Orchestrate bounded Codex subagents for complex software-engineering work while minimizing duplicated context and token usage. Use for repository exploration, debugging, implementation decomposition, tests, reviews, documentation, and security-supporting work that can be split into independent tasks. Avoid for trivial or tightly sequential work, duplicated full-repository reviews, and workflows such as Codex Security Deep Scan that already own their internal worker orchestration.
compatibility: Designed for OpenAI Codex clients with subagent support. Model names and reasoning levels are policy defaults and may be replaced by equivalent available configurations.
metadata:
  title: Subagent Orchestration
  version: "1.2"
---

# Subagent Orchestration

Use subagents as bounded workers that keep the primary thread focused on requirements, decisions, integration, and final validation.

This skill intentionally does not define the behavior of the primary agent's Normal Mode or Plan Mode. It defines how to delegate work around those modes, with an emphasis on useful work per token rather than maximum agent count.

## Core policy

For non-trivial work, actively look for delegation opportunities before doing all exploration, testing, and review in the primary thread.

Prefer this split:

- **Primary agent:** requirements, architecture, decomposition, risk decisions, cross-cutting semantics, integration, final judgment, and user-facing synthesis.
- **Subagents:** repository reconnaissance, bounded implementation, hypothesis testing, test execution, log analysis, targeted research, independent review, documentation checks, and evidence collection.

The primary agent remains the final decision-maker. Subagents may gather evidence, implement already-decided contracts, and challenge assumptions, but must not silently choose unresolved architecture, security, persistence, compatibility, licensing, or public-contract semantics.

Do not delegate merely to maximize parallelism. Delegate when a worker can return a useful conclusion with materially less context or coordination cost than keeping the same work in the primary thread.

## Token-budget principle

Optimize for **useful validated conclusions per token**, not work completed per agent.

Subagents each perform their own model and tool work. They can reduce primary-thread context pollution, but duplicated workers can increase total token usage. Therefore:

- fan out only independent questions;
- do not ask multiple workers to rediscover the same repository facts unless intentional redundancy is justified;
- prefer read-heavy workers over parallel writers;
- return distilled evidence instead of transcripts or full logs;
- stop workers as soon as their objective is satisfied;
- use the cheapest worker tier that can reliably complete the bounded task;
- reserve expensive reasoning for narrow high-risk decisions or adversarial review;
- avoid wrapping a tool or workflow that already performs its own multi-agent discovery in another generic subagent swarm.

When weekly or credit usage is under pressure, reduce **redundant context and duplicate review first**. Do not reduce required security or correctness coverage merely to save tokens.

## Default model policy

Treat model names as replaceable policy aliases. If a named model or effort level is unavailable, choose the nearest available configuration with the same role characteristics.

### `gpt-5.6-terra medium`

Default high-throughput worker for:

- repository search and mapping;
- locating ownership and call paths;
- large-file or documentation digestion;
- test discovery and test execution;
- configuration and dependency reconnaissance;
- deterministic checks;
- concise log classification;
- straightforward implementation in an isolated surface.

### `gpt-5.6-terra high`

Use when a bounded task requires:

- tracing non-obvious control or data flow;
- comparing plausible hypotheses;
- concurrency, lifecycle, or state reasoning;
- security-focused review;
- migration or compatibility analysis;
- non-trivial isolated implementation;
- adversarial review of a meaningful patch.

### `gpt-5.6-luna`

Use for narrow, explicit, high-volume tasks with objective success criteria, such as:

- classification or extraction;
- structured artifact comparison;
- repetitive contract checks;
- focused coding changes;
- mechanical validation;
- summarizing bounded command output.

Use high effort, including `max` where available, only when the task remains narrow enough that extra reasoning is useful without turning the worker into a second primary agent.

### `gpt-daybreak-blue-latest` for authorized defensive security work

When this model alias is available in the active Codex/Daybreak environment, it may be used as a security-focused subagent for **authorized defensive work**, including:

- vulnerability discovery and triage;
- secure code review and adversarial patch review;
- bounded authorization, trust-boundary, and data-flow analysis;
- malware analysis performed for defensive purposes;
- incident-response investigation;
- patch validation and regression review;
- scoped security assessments and finding verification.

For subagent orchestration under this skill, cap its reasoning level at **`xhigh` or lower**. Do not request a reasoning level above `xhigh`, even if the host later exposes one. Prefer the lowest level that is sufficient for the bounded security task; use `xhigh` for difficult exploitability, cross-boundary, or adversarial reasoning rather than as a universal default.

Treat `gpt-daybreak-blue-latest` as an optional security worker, not as a replacement for the primary agent's final security judgment or for Codex Security workflows that already own their worker orchestration. Do not create a parallel Daybreak swarm around an active Deep Security Scan over the same target.

Because Daybreak access is intended for approved defensive use with reduced safeguards, keep its task scope explicit and authorized. Prefer sandboxed or isolated environments, bounded permissions, and reviewed elevated actions. Do not infer authorization to test production systems, third-party systems, or unrelated targets merely because the model is available.

### Escalate instead of grinding

Escalate a subtask to a stronger worker or return it to the primary agent when:

- its true scope is materially broader than the task packet;
- repository-wide semantics must be chosen rather than observed;
- product or architecture intent is unresolved;
- authorization, persistence, compatibility, licensing, or public behavior is ambiguous;
- it repeatedly fails to validate its conclusion;
- the change crosses several ownership boundaries and cannot be safely isolated.

Do not keep increasing reasoning effort on a badly scoped task. Fix the boundary first.

## Delegation threshold

Strongly prefer delegation when at least one applies:

- two or more useful branches can proceed independently;
- the primary agent would otherwise read a large amount of low-signal material;
- several credible hypotheses can be tested separately;
- an independent second opinion materially reduces risk;
- test or runtime surfaces can be validated independently;
- implementation can be partitioned by non-overlapping ownership;
- a reviewer can inspect completed work without editing it;
- logs, traces, generated output, or large files would pollute the primary context.

Usually keep work in the primary thread when:

- the task is tiny and obvious;
- delegation requires almost the same context as the whole task;
- every next step depends immediately on the previous observation;
- workers would edit the same hot files;
- only one short validation command is needed;
- the task is primarily one semantic decision that the primary agent must own.

## Bounded task packet

Every subagent must receive a bounded packet containing:

1. **Objective** — one concrete outcome.
2. **Scope** — files, modules, subsystem, hypothesis, or validation surface.
3. **Known context** — only facts and already-made decisions required for the work.
4. **Constraints** — rules that cannot be violated.
5. **Expected output** — exactly what the worker should return.
6. **Validation** — checks to run when applicable.
7. **Stop conditions** — conditions requiring escalation instead of guessing.

Use this shape when helpful:

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
- commands/tests run and outcomes;
- changed files, if any;
- uncertainties, risks, or blockers;
- recommended next action.
```

Do not give every worker the entire conversation by default. Point workers at authoritative repository files instead of pasting large policy documents into every prompt.

## Output contract

Subagents return **distilled evidence**, not a transcript.

Prefer:

- findings with paths and symbols;
- concrete failure causes;
- minimal reproduction steps;
- test results and exact failing commands;
- patch summaries;
- unresolved questions;
- confidence and caveats when relevant.

Avoid:

- raw search dumps;
- huge logs;
- repeated repository documentation;
- speculative conclusions without evidence;
- broad redesign proposals for a narrow packet.

For large command output, redirect or capture the full log outside the primary conversation when possible and return only the exit status, relevant error excerpt, and artifact path. Do not stream successful build output into the main context merely to prove the command ran.

## Recommended roles

| Role | Default worker | Primary responsibility |
| --- | --- | --- |
| Forager | Terra medium | Fast read-only repository mapping and evidence collection |
| Investigator | Terra high | Test one bounded debugging or control-flow hypothesis |
| Implementer | Terra high | Modify one already-decided ownership surface and add targeted tests |
| Precision worker | Luna or Terra medium | Execute narrow, objective, repeatable work |
| Reviewer | Terra high | Adversarially inspect resulting code, diff, tests, and edge cases |
| Test runner / verifier | Terra medium | Run and classify one validation slice |
| Policy auditor | Terra high | Check security, persistence, compatibility, licensing, or deployment rules |

Reviewers and policy auditors should normally be read-only.

## Primary-agent workflow

### 1. Identify leverage

Before deep exploration, identify independent questions, noisy evidence-gathering work, separable write surfaces, independent validation surfaces, and areas needing adversarial review.

Spawn only workers with a concrete return value.

### 2. Gather and reconcile evidence

Wait only for workers needed for the next decision. Compare results rather than concatenating them.

Resolve contradictions centrally. If a contradiction matters, issue one narrow follow-up or a tie-breaker instead of rerunning the entire investigation.

### 3. Decide centrally

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

### 4. Isolate writes

Prefer one writer per ownership surface.

If a shared contract must change, pause dependent writers, make the contract decision centrally, then resume with updated task packets. Avoid concurrent writers on central files, lockfiles, schema snapshots, generated artifacts, or shared manifests.

### 5. Validate independently

After meaningful changes, use at least one independent validation path when useful: reviewer, targeted test worker, policy auditor, runtime verifier, or documentation consistency checker.

The validator inspects the resulting state, not merely the implementer's summary.

### 6. Integrate and close

The primary agent inspects the final diff/state, resolves conflicts, confirms critical checks, and reports the integrated result. Stop workers whose results are no longer useful.

## Concurrency guidance

Use modest, high-utility concurrency by default:

- 2–4 reconnaissance workers for genuinely separate questions;
- one writer per independent write surface;
- 1–3 validators for materially different risks.

Increase concurrency only when tasks are homogeneous, read-heavy, cheap to specify, and objectively mergeable.

Decrease concurrency when tasks share mutable state, edit common files, require scarce environments, or depend on rapidly evolving decisions.

Never spawn effectively identical workers unless intentional redundancy is the goal.

## Context and session hygiene

Long-lived primary sessions can repeatedly replay large context. Keep the primary thread small enough that its requirements and decisions remain prominent.

At natural phase boundaries such as **plan complete**, **implementation complete**, **security scan complete**, or **final validation pending**:

- produce a compact checkpoint containing decisions, changed files, outstanding checks, and authoritative artifact paths;
- prefer a fresh task/session for a substantially different next phase when the host and workflow allow it;
- do not carry raw logs, exploration transcripts, or superseded hypotheses into the next phase;
- when continuity is required, pass the checkpoint and repository state rather than the entire narrative history.

A fresh session is not appropriate when unresolved transient state, an active approval, or a stateful tool operation must remain attached to the current thread.

## Security-review routing

Security review is a special case because redundant repository-wide discovery is expensive and some Codex Security workflows already orchestrate their own workers.

Use this order:

1. **Git-backed change, PR, commit, or working tree:** prefer the Codex Security change-review / diff-scan workflow.
2. **Routine repository or component assessment:** prefer a standard Codex Security scan, scoped to a real component/security boundary when appropriate.
3. **Release preparation:** do **not** recommend a full-repository review merely because a release is approaching. Review the release delta, affected trust boundaries, shared security-critical dependencies, and selected high-risk surfaces first; add scoped standard or deep scans only where the release changes or assurance requirements justify them.
4. **Deep repository assessment:** use a Deep Security Scan only when repository-wide, lower-variance discovery is independently justified, such as an explicit whole-repository assurance requirement, a new baseline, an audit/compliance requirement, or a cross-cutting trust-boundary redesign whose affected scope cannot be bounded safely.

Treat **release readiness and repository-wide coverage as separate decisions**. A release milestone by itself is not evidence that every source-like file should be reread. Prefer risk-based, change-aware coverage even for major releases; full-repository review is an exception that needs a concrete assurance reason.

Do **not** wrap a Codex Security Deep Security Scan in a generic swarm of security subagents. The deep-scan workflow owns its repeated discovery workers and downstream validation. Generic subagents may still handle independent non-security work such as build verification, documentation checks, or unrelated test slices.

If equal security coverage is required, do not reduce deep-scan discovery caps merely to save tokens. Reduce repeated scans, legitimate scope, duplicated outer agents, prompt/context size, and log volume first.

For accepted findings, prefer the bounded fix-and-verify workflow and a targeted change review over rerunning a full or deep repository scan after every edit. Run the broader scan again only when the change or assurance goal justifies it.

For bounded authorized security-review subagents, `gpt-daybreak-blue-latest` may be selected when available, with reasoning **no higher than `xhigh`**. Use it for security judgment that benefits from Daybreak Blue access, while keeping deterministic validation on Terra/Luna where appropriate. It does not justify broadening scope, repeating an existing scan, or bypassing the normal primary-agent and Codex Security review boundaries.

When security review or token pressure is central to the task, read [references/security-review-budgeting.md](references/security-review-budgeting.md).

## High-value patterns

Prefer these patterns:

- **Reconnaissance fan-out:** different workers map architecture, tests, runtime, docs, or relevant policies.
- **Hypothesis fan-out:** one investigator per credible independent bug hypothesis; require falsifying evidence.
- **Read/write separation:** parallel readers first, centralized design, isolated writer, independent validators.
- **Partitioned implementation:** parallel writers only across stable, non-overlapping ownership boundaries.
- **Implementer + adversarial reviewer:** separate production and critique to reduce anchoring.
- **Test-matrix fan-out:** delegate isolated test families, not tests contending for one mutable environment.
- **Contract review:** specialized read-only workers check security, persistence, compatibility, licensing, accessibility, or deployment constraints.
- **Redundant cross-check:** two independent workers answer the same narrow, high-risk, objectively checkable question only when the risk justifies the duplication.

For detailed recipes and edge cases, read [references/orchestration-patterns.md](references/orchestration-patterns.md).

## Exceptions and special cases

### Trivial or tightly sequential work

Do not delegate one-line fixes, obvious local changes, or debugging loops where every step depends on the immediately preceding observation and there are no useful independent hypotheses.

### Shared hot files and generated artifacts

Use parallel readers, then one writer, then parallel reviewers. Assign exactly one owner for lockfiles, generated source, shared schemas, and common manifests.

### Migrations and persisted data

Workers may inspect schemas, callers, compatibility, rollback behavior, and isolated migration tests. The primary agent must own ambiguous durability, compatibility, data-loss, and rollback semantics.

### Security and authorization

Use workers for threat-oriented review, permission-path tracing, and adversarial validation. Do not let a worker invent or weaken authentication, authorization, tenancy, ACL, secret-handling, or trust-boundary semantics.

### Public APIs and compatibility

Workers may inventory callers and risks. The primary agent owns unresolved wire-format, versioning, compatibility, and public-behavior decisions.

### Licensing and dependency boundaries

Workers may inspect licenses and dependency direction. Escalate license-boundary ambiguity instead of resolving it by convenience.

### Irreversible or destructive actions

Subagents may analyze and validate but do not independently authorize destructive database operations, history rewrites, release publication, secret rotation, or externally meaningful deletion.

### Scarce or stateful environments

Serialize tests that share browser sessions, databases, Kubernetes namespaces, devices, or other mutable resources unless deterministic isolation is guaranteed.

### Large refactors

Define the new central abstraction first. Fan out mechanical migrations only after its contract is stable.

### Poorly specified intent

Subagents may gather evidence or enumerate options, but they cannot manufacture missing product intent through consensus.

## Anti-patterns

Avoid:

- everyone inspecting the whole repository;
- multiple full security reviews of the same unchanged surface;
- unbounded recursive delegation;
- parallel edits without ownership;
- giving reviewers the implementer's full rationale and expected conclusion;
- treating confidence as evidence;
- retrying the same bad packet at higher effort;
- maximum reasoning for grep-like work;
- trusting passing tests that do not exercise the required behavior;
- keeping one primary session alive indefinitely after its original phase is complete.

## Repository-policy interaction

Applicable `AGENTS.md`, `SECURITY.md`, living specifications, contribution guides, and component overlays always apply to delegated work.

When repository policy defines escalation or validation rules:

- include the relevant path in the worker packet;
- require the worker to read it before acting within that boundary;
- do not let generic advice in this skill override repository-specific policy;
- stop delegation-based implementation when repository rules require a maintainer decision.

For mixed-license repositories, assign explicit package or directory boundaries to writers and verify dependency direction remains legal and intentional.

## Completion criteria

A subagent-assisted task is complete only when the primary agent confirms that:

- required worker results were received;
- important claims are supported by evidence;
- contradictory findings were resolved;
- edits respect ownership and repository policy;
- required tests/checks ran or missing validation is clearly reported;
- unresolved high-risk semantics were not guessed;
- the integrated result satisfies the original task;
- worker-generated noise was distilled instead of copied into the final response.

## Compact operational rule

> **Fan out evidence -> centralize decisions -> isolate writes -> fan out validation -> centralize integration.**

Under token pressure, add one more rule:

> **Do not pay twice for the same evidence.**
