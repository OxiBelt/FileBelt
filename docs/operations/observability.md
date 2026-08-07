<!-- SPDX-License-Identifier: Apache-2.0 -->

# Kubernetes observability

## Collection boundary

Each role exposes low-information liveness/readiness and Prometheus metrics on
its private operations listener. NetworkPolicy permits only kubelet traffic and
configured monitoring peers. OxiBelt remains the only public Service; never
publish an operations port through the L4 frontend.

Logs use JSON in Kubernetes. Traces use fresh local context and optional
OTLP/HTTP to a configured in-cluster collector. Public `traceparent` and
`tracestate` values are not trusted as parents and cannot select the trace ID
or override the configured sampling ratio. Collector failure is bounded and
does not change request correctness or readiness. The main chart installs no
Prometheus, Grafana, or collector. `ServiceMonitor` and `PrometheusRule` are
optional integrations and are disabled by default.

## Privacy and cardinality

Metrics may label only stable role, route class, HTTP method/status class,
bounded outcome/reason category, and job kind. They must not contain a tenant,
principal, resource, filename/path, request/job UUID, physical locator,
capability, token, credential, raw error, or payload content.

Structured logs may use request/operation/job and trace IDs for correlation but
must not emit raw cookies, OIDC codes/tokens, CSRF values, share tokens,
capabilities, keys, database URLs, private certificate material, payload
content, or general physical paths. Audit export is a separate protected CLI
stream, not a logging mode.

## Initial questions and signals

- Can the edge, API, I/O, and maintenance Pods accept their assigned work?
- Is PostgreSQL reachable, and are connection/transaction failures rising?
- Is OIDC metadata approaching the 48-hour fail-closed bound?
- Does the payload provider have sufficient bytes/inodes and a fresh capacity
  observation?
- Are active operations draining during rollout?
- Are jobs old, retrying, blocked, or repeatedly taken over?
- Is Iggy publication behind while PostgreSQL polling remains healthy?
- Did a scrub quarantine data or detect a BLAKE3 mismatch?
- Are backend/public certificates approaching expiry?

The shipped dashboard answers these questions without a user-content or
tenant selector.

## Alerts

- Backend or PostgreSQL unavailable for five minutes: critical.
- API 5xx ratio above five percent with at least twenty requests in ten
  minutes: warning.
- OIDC metadata older than 36 hours: warning; 48 hours: critical.
- Storage below fifteen percent: warning; below five percent: critical.
- Stale capacity observation, operator-blocked job, old ready job/outbox,
  repeated lease takeovers, or Iggy publish failure: warning with role-specific
  runbook links.
- Quarantine or digest mismatch: critical.
- Certificate lifetime below fourteen days: warning; below three days:
  critical.

There is no backup-freshness alert because Phase 3 has no persisted backup
schedule or numeric recovery objective. External backup automation must alert
on its own schedule; FileBelt alerts only on a failed recovery verification
when such a run is executed.

## Audit export

Use the dedicated audit-export database Secret and a bounded
`filebeltctl audit export` Job or protected operator invocation. Persist the
final cursor only after the `filebelt.audit.export.v1` checkpoint record is
received. External tooling owns encryption, transport, retention, replay, and
deduplication by audit event ID. Never configure an always-running FileBelt
Internet exporter.
