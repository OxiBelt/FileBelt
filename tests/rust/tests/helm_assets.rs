// SPDX-License-Identifier: Apache-2.0

use std::fs;

use filebelt_repository_tests::repository_root;

#[test]
fn phase1_chart_is_schema_only_and_has_the_exact_role_contract() {
    let root = repository_root();
    let chart = root.join("deploy/helm/filebelt");
    let schema = fs::read_to_string(chart.join("values.schema.json")).expect("values schema");
    let values = fs::read_to_string(chart.join("values.yaml")).expect("values");
    let templates = fs::read_dir(chart.join("templates"))
        .expect("templates")
        .map(|entry| entry.expect("template entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(templates, [std::ffi::OsString::from("NOTES.txt")]);
    for role in [
        "filebelt-api",
        "filebelt-worker-io",
        "filebelt-worker-maintenance",
        "filebelt-media-controller",
        "filebelt-mcp-broker",
        "filebelt-tools",
        "filebelt-web",
    ] {
        assert!(schema.contains(&format!("\"{role}\"")));
        assert!(values.contains(&format!("  {role}:")));
    }
    assert!(schema.contains("\"oneOf\""));
    assert!(schema.contains("\"const\": 10001"));
    assert!(values.contains("linux/riscv64"));
}
