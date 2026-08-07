<!-- SPDX-License-Identifier: Apache-2.0 -->

# FileBelt observability assets

These portable Phase 4 examples do not install a monitoring stack. Import
`grafana-dashboard.json`, load `prometheus-rules.yaml` into the operator's
Prometheus, and adapt `otel-collector.yaml` to a trusted trace backend. The
Helm chart can render equivalent `ServiceMonitor` and `PrometheusRule` objects
only when its optional Prometheus Operator integration is enabled.

Metrics and health listeners are private. Configure NetworkPolicy monitoring
peers before scraping them. Dashboard and alert queries use bounded role/target
labels and never require a tenant, user, resource, path, or request identifier.

See [the operator observability guide](../../docs/operations/observability.md)
for privacy rules, alert interpretation, and runbooks.
