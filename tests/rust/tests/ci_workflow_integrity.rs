// SPDX-License-Identifier: Apache-2.0

use std::fs;

use filebelt_repository_tests::repository_root;

#[test]
fn bootstrap_workflow_is_least_privileged_and_complete() {
    let root = repository_root();
    let workflow = fs::read_to_string(root.join(".github/workflows/check-filebelt.yml"))
        .expect("bootstrap workflow");
    assert!(workflow.contains("permissions:\n  contents: read"));
    assert!(!workflow.contains("pull_request_target:"));
    assert!(!workflow.contains("packages: write"));
    for job in [
        "source-structure:",
        "rust:",
        "supply-chain:",
        "node:",
        "protocol:",
        "dco:",
        "bootstrap-gate:",
    ] {
        assert!(workflow.contains(job), "workflow is missing {job}");
    }
}
