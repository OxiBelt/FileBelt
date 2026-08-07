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
        "rust-boundaries:",
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
fn rust_boundary_job_is_advisory_for_size_and_blocks_the_bootstrap_gate() {
    let root = repository_root();
    let workflow = fs::read_to_string(root.join(".github/workflows/check-filebelt.yml"))
        .expect("bootstrap workflow");
    let boundary_start = workflow
        .find("\n  rust-boundaries:\n")
        .expect("Rust boundary job");
    let boundary_end = workflow[boundary_start..]
        .find("\n  supply-chain:\n")
        .map(|offset| boundary_start + offset)
        .expect("job after Rust boundaries");
    let boundary = &workflow[boundary_start..boundary_end];

    let script_tests = boundary
        .find("python3 tests/scripts/test_check_rust_module_size.py")
        .expect("module-size checker tests");
    let advisory = boundary
        .find("tests/scripts/check-rust-module-size.sh --warn")
        .expect("advisory module-size check");
    let cargo_graph = boundary
        .find("tests/scripts/check-cargo-boundaries.sh")
        .expect("Cargo boundary check");
    let source_contract = boundary
        .find("--test module_decomposition_contract")
        .expect("source-boundary contract");

    assert!(!boundary.contains("check-rust-module-size.sh --enforce"));
    assert!(script_tests < advisory);
    assert!(advisory < cargo_graph);
    assert!(cargo_graph < source_contract);
    assert!(workflow.contains(
        "needs: [source-structure, rust, rust-boundaries, supply-chain, node, protocol, dco]"
    ));
    assert!(workflow.contains("RUST_BOUNDARIES: ${{ needs.rust-boundaries.result }}"));
    assert!(workflow.contains("test \"$RUST_BOUNDARIES\" = success"));
}

#[test]
fn validation_is_read_only_and_release_promotion_is_tag_only() {
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
    assert!(dry_run.contains("on:\n  workflow_dispatch:"));
    assert!(!dry_run.contains("tags:"));

    let release =
        fs::read_to_string(root.join(".github/workflows/release.yml")).expect("release workflow");
    assert!(release.contains("tags:\n      - \"[0-9]*.[0-9]*.[0-9]*\""));
    assert!(!release.contains("workflow_dispatch:"));
    assert!(!release.contains("pull_request:"));
    assert_eq!(release.matches("packages: write").count(), 1);
    assert_eq!(release.matches("contents: write").count(), 1);
    assert_eq!(release.matches("id-token: write").count(), 1);
    assert_eq!(release.matches("attestations: write").count(), 1);
    let promote = release.find("\n  promote:\n").expect("promotion job");
    for permission in [
        "packages: write",
        "contents: write",
        "id-token: write",
        "attestations: write",
    ] {
        assert!(
            release
                .find(permission)
                .is_some_and(|index| index > promote)
        );
    }
    assert!(release.contains("tests/scripts/promote-release-artifacts.sh"));
    assert!(release.contains("tests/scripts/run-kubernetes-release-gate.sh"));
    assert!(release.contains("tests/scripts/run-kubernetes-kind-compatibility.sh"));
    assert!(release.contains("helm/kind-action@ef37e7f390d99f746eb8b610417061a60e82a6cc"));
    for node_image in [
        "kindest/node:v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256",
        "kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95",
        "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5",
    ] {
        assert!(release.contains(node_image));
    }
    assert!(release.contains("oci://ghcr.io/oxibelt/charts"));
    assert!(release.contains("actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d"));
    assert!(release.contains("sha256sum --check SHA256SUMS"));
    assert!(release.contains("refusing to replace existing Helm release"));
    assert!(release.contains("--verify-tag"));

    let exact_artifact =
        fs::read_to_string(root.join("tests/scripts/run-kubernetes-release-gate.sh"))
            .expect("release acceptance script");
    assert!(exact_artifact.contains("docker load --input"));
    assert!(exact_artifact.contains("FILEBELT_ACCEPTANCE_SKIP_BUILD=1"));
    assert!(exact_artifact.contains("tests/docker/phase2/run-acceptance.sh"));
    assert!(!exact_artifact.contains("run-image-matrix.sh"));
    let active_start = exact_artifact
        .find("active_roles=(")
        .expect("release active-role allowlist");
    let active_end = exact_artifact[active_start..]
        .find("\n)")
        .map(|offset| active_start + offset)
        .expect("release active-role allowlist end");
    let active_roles = &exact_artifact[active_start..active_end];
    for active in [
        "filebelt-api",
        "filebelt-worker-io",
        "filebelt-worker-maintenance",
        "filebelt-tools",
        "filebelt-web",
    ] {
        assert!(active_roles.contains(active));
    }
    assert!(!active_roles.contains("filebelt-media-controller"));
    assert!(!active_roles.contains("filebelt-mcp-broker"));
}

#[test]
fn protocol_job_provisions_pinned_node_dependencies_before_generation() {
    let root = repository_root();
    let workflow = fs::read_to_string(root.join(".github/workflows/check-filebelt.yml"))
        .expect("bootstrap workflow");
    let protocol_start = workflow.find("\n  protocol:\n").expect("protocol job");
    let protocol_end = workflow[protocol_start..]
        .find("\n  dco:\n")
        .map(|offset| protocol_start + offset)
        .expect("job after protocol");
    let protocol = &workflow[protocol_start..protocol_end];

    let setup = protocol
        .find("actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020")
        .expect("pinned Node setup");
    let activation = protocol
        .find("corepack prepare pnpm@11.20.0 --activate")
        .expect("pinned pnpm activation");
    let install = protocol
        .find("pnpm install --frozen-lockfile --ignore-scripts")
        .expect("frozen dependency install");
    let generation = protocol
        .find("python3 tests/scripts/check-generated.py --repo-root .")
        .expect("generated-client check");

    assert!(protocol.contains("node-version: \"24.19.0\""));
    assert!(setup < activation);
    assert!(activation < install);
    assert!(install < generation);
}
