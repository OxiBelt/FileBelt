// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fs;

use filebelt_repository_tests::repository_root;

#[test]
fn phase3_chart_has_the_production_assets_and_exact_role_contract() {
    let root = repository_root();
    let chart = root.join("deploy/helm/filebelt");
    let metadata = fs::read_to_string(chart.join("Chart.yaml")).expect("chart metadata");
    let schema_source =
        fs::read_to_string(chart.join("values.schema.json")).expect("values schema");
    let schema: serde_json::Value =
        serde_json::from_str(&schema_source).expect("valid schema JSON");
    let values = fs::read_to_string(chart.join("values.yaml")).expect("values");
    let templates = fs::read_dir(chart.join("templates"))
        .expect("templates")
        .map(|entry| {
            entry
                .expect("template entry")
                .file_name()
                .into_string()
                .expect("UTF-8 template name")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        templates,
        [
            "NOTES.txt",
            "_helpers.tpl",
            "configmaps.yaml",
            "deployments.yaml",
            "monitoring.yaml",
            "networkpolicies.yaml",
            "operation-job.yaml",
            "pdbs.yaml",
            "serviceaccounts.yaml",
            "services.yaml",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    assert!(metadata.contains("filebelt.dev/phase: \"3\""));
    assert!(metadata.contains("kubeVersion: \">=1.34.0-0 <1.37.0-0\""));
    for role in [
        "filebelt-api",
        "filebelt-worker-io",
        "filebelt-worker-maintenance",
        "filebelt-tools",
        "filebelt-web",
    ] {
        assert!(
            schema["properties"]["images"]["properties"]
                .get(role)
                .is_some()
        );
        assert!(values.contains(&format!("  {role}:")));
    }
    for inactive_role in ["filebelt-media-controller", "filebelt-mcp-broker"] {
        assert!(
            schema["properties"]["images"]["properties"]
                .get(inactive_role)
                .is_none()
        );
        assert!(!values.contains(&format!("  {inactive_role}:")));
    }
    assert_eq!(
        schema["properties"]["global"]["properties"]["runAsUser"]["const"],
        10001
    );
    assert!(
        schema["properties"]["operation"]["properties"]["type"]["enum"]
            .as_array()
            .is_some_and(|operations| operations.len() == 11)
    );
    assert!(values.contains("linux/riscv64"));
}
