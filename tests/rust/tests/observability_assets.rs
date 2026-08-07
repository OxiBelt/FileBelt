// SPDX-License-Identifier: Apache-2.0

use std::fs;

use serde_json::Value;

fn repository_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn dashboard_is_bounded_and_contains_operator_signals() {
    let root = repository_root();
    let source = fs::read_to_string(root.join("deploy/observability/grafana-dashboard.json"))
        .expect("dashboard");
    let dashboard: Value = serde_json::from_str(&source).expect("valid dashboard JSON");
    assert_eq!(dashboard["spdxLicense"], "Apache-2.0");
    assert_eq!(dashboard["uid"], "filebelt-operations-v1");
    let serialized = dashboard.to_string();
    for required in [
        "filebelt_ready",
        "filebelt_oidc_metadata_age_seconds",
        "filebelt_storage_capacity_bytes",
        "filebelt_http_failures_total",
        "filebelt_maintenance_scrub_jobs_created_total",
    ] {
        assert!(serialized.contains(required), "dashboard omits {required}");
    }
    for forbidden in [
        "tenant_id",
        "principal_id",
        "resource_id",
        "request_id",
        "physical_path",
        "capability",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "dashboard contains sensitive/high-cardinality field {forbidden}"
        );
    }
}

#[test]
fn portable_rules_cover_fail_closed_boundaries() {
    let root = repository_root();
    let rules = fs::read_to_string(root.join("deploy/observability/prometheus-rules.yaml"))
        .expect("Prometheus rules");
    for required in [
        "FileBeltRoleUnavailable",
        "FileBeltDatabaseUnavailable",
        "FileBeltOidcMetadataRejected",
        "FileBeltStorageCritical",
        "FileBeltBackendCertificateCritical",
        "FileBeltMaintenanceJobCycleFailing",
        "runbook_url:",
    ] {
        assert!(rules.contains(required), "rules omit {required}");
    }
    for forbidden in ["tenant_id", "principal_id", "resource_id", "0.0.0.0/0"] {
        assert!(!rules.contains(forbidden), "rules contain {forbidden}");
    }
}

#[test]
fn collector_example_is_bounded_and_does_not_claim_a_backend() {
    let root = repository_root();
    let collector = fs::read_to_string(root.join("deploy/observability/otel-collector.yaml"))
        .expect("collector example");
    for required in ["otlp:", "http:", "memory_limiter:", "batch:", "traces:"] {
        assert!(collector.contains(required));
    }
    for forbidden in ["authorization:", "password:", "token:", "0.0.0.0/0"] {
        assert!(!collector.contains(forbidden));
    }
}
