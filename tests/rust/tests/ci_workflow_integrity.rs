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
        "phase1-images-native:",
        "phase1-images-riscv64:",
        "phase1-gate:",
    ] {
        assert!(workflow.contains(job), "workflow is missing {job}");
    }
}

#[test]
fn phase1_workflows_are_read_only_and_cover_the_image_matrix() {
    let root = repository_root();
    let checks = fs::read_to_string(root.join(".github/workflows/check-filebelt.yml"))
        .expect("check workflow");
    let dry_run = fs::read_to_string(root.join(".github/workflows/release-dry-run.yml"))
        .expect("release dry-run workflow");
    for workflow in [&checks, &dry_run] {
        assert!(workflow.contains("permissions:\n  contents: read"));
        for forbidden in [
            "packages: write",
            "contents: write",
            "id-token: write",
            "attestations: write",
            "pull_request_target:",
            "docker push",
        ] {
            assert!(
                !workflow.contains(forbidden),
                "workflow contains {forbidden}"
            );
        }
    }
    assert!(checks.contains("ubuntu-24.04-arm"));
    assert!(checks.contains("linux/amd64"));
    assert!(checks.contains("linux/arm64"));
    assert!(checks.contains("linux/riscv64"));
    assert!(checks.contains("--qemu-mode rootless"));
    assert!(checks.contains("azure/setup-helm@1a275c3b69536ee54be43f2070a358922e12c8d4"));
    assert!(checks.contains("version: v4.2.3"));
    assert!(checks.contains("tests/scripts/check-helm-chart.sh"));
    assert!(checks.contains("tests/scripts/verify-release-tag.sh --check-trust"));
    assert!(checks.contains("python3 -m unittest discover -s tests/scripts -p 'test_*.py'"));
    assert!(dry_run.contains("normalized-rebuild:"));
    assert!(dry_run.contains("retention-days: 30"));
}
