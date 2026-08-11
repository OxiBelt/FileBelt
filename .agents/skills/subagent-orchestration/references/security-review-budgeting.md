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

### C. Release preparation is not a full-repository trigger

Do **not** recommend a full-repository security review merely because a release is being prepared, including a major release. Release readiness should normally be established from the actual release delta and the security boundaries that delta can affect.

Prefer this release-oriented scope:

- the release diff or bounded range since the last trusted security baseline;
- authentication, authorization, tenancy, secret, persistence, parser, filesystem, network, and privilege boundaries touched by that diff;
- shared security-critical dependencies and callers needed to reason about those changes;
- high-risk surfaces selected from the threat model even if they were not directly edited, when the release can change their behavior through configuration, dependency, schema, or integration changes;
- targeted regression and contract tests for the affected controls.

A release milestone by itself does **not** justify rereading every source-like file. Prefer risk-based, change-aware, scoped review even during release preparation.

### D. High-assurance repository review

Use a full-repository or Deep Security Scan only when repository-wide, lower-variance discovery has a concrete assurance reason independent of the release date. Examples include:

- an explicit whole-repository audit, compliance, or assurance requirement;
- establishing or re-establishing a trusted repository-wide security baseline;
- a major authentication/authorization or multi-tenant redesign whose affected scope cannot be bounded safely;
- cross-cutting persistence, secrets, build, dependency, or deployment changes with genuinely repository-wide reach;
- a scoped or standard scan that exposed suspicious gaps indicating the true affected surface is broader than expected;
- an explicit requirement for repeated discovery to reduce run-to-run variance.

Deep scan is not the default loop for ordinary implementation iterations **or for ordinary release preparation**.

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
5. at a component or release boundary, run a **scoped** standard scan over the affected security boundary when useful;
6. run a full-repository or deep scan only when a separate assurance reason requires repository-wide coverage.

This avoids turning release milestones into automatic full-repository rescans while preserving broad review where the actual change or assurance requirement warrants it.

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
- bounded permission/data-flow tracing: Terra high;
- adversarial review of a high-risk path: Terra high or stronger when justified;
- deterministic validation/test execution: Terra medium or Luna;
- final unresolved security-boundary decision: primary agent with the strongest configuration appropriate to the risk.

Do not lower the final security judgment model solely because a cheaper worker produced a confident summary.

## When a deep scan should remain expensive

Do not optimize away repeated discovery merely to conserve usage when the user explicitly requires exhaustive review, variance reduction, or comparable repository-wide security coverage. A release milestone alone does not create that requirement; repository-wide review should be justified separately.

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
- **before a release:** diff/change review plus scoped review of affected and threat-model-selected high-risk surfaces; do not default to a full-repository scan;
- **after a repository-wide trust-boundary redesign or when an explicit whole-repository assurance requirement exists:** deep security scan if that broader scope is actually justified;
- **after fixing an accepted finding:** bounded fix verification + diff scan, with broad rescan only when warranted.

Adjust cadence upward for high-risk systems and downward only when the security policy explicitly allows it.
