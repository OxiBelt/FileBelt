# Security Review Budgeting

Read this reference when a task involves Codex Security, security-review orchestration, unusually high token consumption, or a request to conserve weekly/credit usage without unnecessarily weakening assurance.

## Goal

Reduce duplicated model work and repeated context while preserving the security assurance appropriate to the task.

Do not claim that fewer discovery passes, fewer security workers, or lower reasoning effort preserve identical coverage. When the security workflow itself is reduced, treat that as an explicit quality/coverage tradeoff.

## First classify the security target

### A. Git-backed change

For an uncommitted working tree, commit, branch range, or pull request, use the Codex Security change-review workflow rather than a full repository scan.

The change-review workflow is intentionally bounded to changed source-like files and directly supporting code. It is the default security check during iterative development.

Use it:

- after implementing a security-sensitive fix;
- before merge;
- after a bounded refactor;
- after tests reveal a change in an authorization, filesystem, network, secret, parsing, or trust-boundary path.

Do not rerun a repository-wide deep scan after every edit unless the edit invalidates the previous repository-level assurance.

### B. Routine repository or component review

Use a standard Codex Security scan for first runs and routine review.

For a monorepo, scope the scan to one meaningful product, service, adapter, or security boundary when that boundary is real. Do not create an artificially narrow scope that excludes relevant callers, shared authorization layers, persistence paths, or other code required to reason about the control.

Prefer persistent `SECURITY.md` guidance over repeatedly pasting a threat model into prompts. Keep additional context focused on facts that materially change the review: attacker-controlled inputs, trust boundaries, sensitive actions, exclusions, or a specific area to prioritize.

### C. High-assurance repository review

Use Deep Security Scan when broader and lower-variance discovery is worth the extra resources. Typical triggers include:

- release or audit milestones;
- a major authentication/authorization redesign;
- multi-tenant boundary changes;
- sensitive persistence or secrets changes;
- a standard scan that exposed suspicious or incomplete coverage;
- an explicit requirement for repeated discovery to reduce run-to-run variance.

Deep scan is not the default loop for ordinary implementation iterations.

## Do not double-orchestrate Deep Security Scan

The Codex Security deep-scan workflow already owns repeated independent discovery workers and then centralizes validation and attack-path analysis.

Therefore, while a deep scan is active:

- do not spawn a second generic swarm to scan the same repository for the same vulnerability classes;
- do not start a standard security scan in parallel over the same target merely for redundancy;
- do not ask general review subagents to re-read every source-like file that the deep scan is already reviewing;
- do not repeatedly read live worker artifacts into the primary thread.

Generic subagents remain useful for **independent non-duplicative work**, for example:

- running build and test slices;
- checking Markdown links or generated files;
- validating Helm or packaging contracts;
- reviewing documentation consistency;
- reproducing a specific already-identified behavior;
- checking a policy boundary not covered by the active scan target.

## Accuracy-preserving savings hierarchy

When assurance should remain unchanged, apply savings in this order.

### 1. Reduce scan frequency, not scan quality

Use change reviews continuously and run broad scans at meaningful milestones.

A common loop is:

1. implement a bounded change;
2. run targeted tests;
3. run a security diff scan;
4. repeat as needed;
5. run one standard scan at the component/release boundary;
6. run one deep scan only when the assurance goal requires it.

This removes repeated full-repository discovery without weakening the broad scan that still occurs at the milestone.

### 2. Use a legitimate narrower boundary

If only one service or component is in scope and it has a clear security boundary, scan that component. Include shared dependencies necessary to reason about the security property.

Do not scope away cross-cutting authorization, tenancy, persistence, protocol, or secret-handling code merely to reduce tokens.

### 3. Keep the primary security thread short

Avoid performing planning, implementation, huge build logs, deep scanning, remediation, and final packaging in one unbounded primary conversation when natural phase boundaries exist.

At each boundary, keep a compact checkpoint containing:

- repository revision or worktree state;
- threat/security objective;
- changed files or diff range;
- accepted findings or no-findings artifact path;
- validation already completed;
- explicit deferred checks;
- next required action.

When the host/workflow permits, start the next distinct phase from that checkpoint and the repository state instead of replaying a long narrative transcript.

### 4. Keep logs out of model context

For successful builds and scanners, return exit status and artifact path rather than thousands of lines of normal output.

For failures, return:

- exact command;
- exit code;
- the minimal relevant error block;
- path to the complete log;
- suspected ownership area only when evidence supports it.

### 5. Use cheaper agents for non-security validation

Do not spend Sol/xhigh on deterministic checks that do not require deep semantic judgment.

Examples suitable for Terra medium or Luna include:

- formatting;
- lint command execution;
- Markdown link checks;
- generated-file drift checks;
- package manifest checks;
- test command execution and concise failure classification;
- documentation inventory;
- structured diff comparison.

Keep a stronger reviewer for the actual high-risk security reasoning.

### 6. Avoid repeated policy injection

Store stable threat model and security invariants in `SECURITY.md` and build/validation guidance in `AGENTS.md`. Use nested files when only one subtree needs detailed guidance.

Do not paste the same long policy text into every worker prompt.

### 7. Disable irrelevant MCP/context providers

When possible, run the security review with only the MCP servers and integrations required for that review. Extra tool schemas and connected context increase prompt size even when unused.

## Deep-scan configuration tradeoffs

Deep-scan runtime can be configured with settings such as worker concurrency, nested subagents, the no-new-candidate stop threshold, and the maximum discovery-run count.

Important distinction:

- lowering **concurrency** may reduce peak parallel activity and make the scan take longer, but it is not a reliable way to reduce total weekly token consumption at the same discovery depth;
- lowering **nested subagents**, **stop thresholds**, or **maximum discovery runs** can reduce token use, but it may also miss findings;
- if equal coverage is required, keep the discovery-depth settings appropriate to that assurance goal and save tokens outside the deep scan first.

A low-budget deep-scan profile is a deliberate coverage tradeoff, not an accuracy-preserving optimization. Label it as such.

## Accepted finding workflow

After a finding is accepted:

1. use a bounded fix workflow for that finding;
2. add targeted regression tests;
3. validate the exact source-to-sink or authorization path that was fixed;
4. run a security diff scan over the resulting change;
5. rerun a broader standard/deep scan only when the change materially affects the previous scan's scope or when milestone assurance requires it.

Do not repeatedly ask independent agents to rediscover the same already-validated finding.

## Security reviewer model policy

Use high reasoning where it changes security judgment, not everywhere around the scan.

A practical split is:

- repository/file discovery supporting security: Terra medium;
- bounded permission/data-flow tracing: Terra high, or `gpt-daybreak-blue-latest` when available and useful;
- adversarial review of a high-risk path: Terra high or `gpt-daybreak-blue-latest`, escalating within the allowed effort ceiling when justified;
- vulnerability discovery, secure code review, incident-response analysis, malware analysis for defensive purposes, patch validation, or finding verification: `gpt-daybreak-blue-latest` is permitted for an authorized bounded subtask when available;
- deterministic validation/test execution: Terra medium or Luna;
- final unresolved security-boundary decision: primary agent with the strongest configuration appropriate to the risk.

### Daybreak Blue subagent constraints

Treat `gpt-daybreak-blue-latest` as an optional alias supplied by the active Daybreak/Codex environment. The public Daybreak documentation describes Daybreak Blue as the recommended starting point for most approved defenders and lists vulnerability discovery, secure code review, malware analysis, incident response, patch validation, and security assessments among its intended defensive uses. Do not assume the alias exists in every environment merely because Daybreak Blue exists as an access tier.

For every `gpt-daybreak-blue-latest` subagent launched under this skill:

- set reasoning to **`xhigh` or lower**; never request an effort level above `xhigh`;
- choose the lowest sufficient reasoning level for the bounded task rather than defaulting every security worker to `xhigh`;
- give it an explicit authorized target, objective, scope, and stop condition;
- keep production, third-party, destructive, or externally consequential actions out of scope unless the surrounding workflow separately establishes authorization and the required review controls;
- prefer sandboxed/isolated execution and reviewed elevated actions;
- require concise evidence and validation output rather than an unbounded security narrative;
- do not use it to duplicate an active Codex Security Deep Scan over the same target;
- do not let its confidence override the primary agent's final security-boundary judgment.

Daybreak Blue availability is a model/access choice, not a reason to widen the review from a diff or scoped boundary to the whole repository. The same change-aware and release-review scoping rules still apply.

Do not lower the final security judgment model solely because a cheaper or specialized worker produced a confident summary.

## When a deep scan should remain expensive

Do not optimize away repeated discovery merely to conserve usage when the user explicitly requires exhaustive review, variance reduction, high-assurance release evidence, or comparable repository-wide security coverage.

In those cases, the correct optimization target is the surrounding workflow:

- shorter primary context;
- no duplicate generic security fan-out;
- no redundant repeated broad scans;
- clean scope;
- concise artifacts;
- cheaper non-security validation.

## Recommended security cadence

For a long-running project, a reasonable default policy is:

- **per meaningful change:** targeted tests + security diff scan when the change is security-relevant;
- **per component milestone:** standard scoped security scan;
- **before major release / after major trust-boundary redesign:** deep security scan if the assurance requirement justifies it;
- **after fixing an accepted finding:** bounded fix verification + diff scan, with broad rescan only when warranted.

Adjust cadence upward for high-risk systems and downward only when the security policy explicitly allows it.
