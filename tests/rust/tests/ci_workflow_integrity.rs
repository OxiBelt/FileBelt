// SPDX-License-Identifier: Apache-2.0

use std::fs;

use filebelt_repository_tests::repository_root;

fn workflow_job<'a>(workflow: &'a str, job: &str, next_job: &str) -> &'a str {
    let job_marker = format!("\n  {job}:\n");
    let next_job_marker = format!("\n  {next_job}:\n");
    let start = workflow.find(&job_marker).expect("workflow job");
    let end = workflow[start..]
        .find(&next_job_marker)
        .map(|offset| start + offset)
        .expect("job after workflow job");
    &workflow[start..end]
}

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
        "fuzz-smoke:",
        "rust-boundaries:",
        "supply-chain:",
        "node:",
        "protocol:",
        "dco:",
        "bootstrap-gate:",
        "phase1-images-native:",
        "phase1-images-riscv64:",
        "phase1-gate:",
        "fuzz-sustained:",
        "docker-core:",
        "docker-collaboration:",
        "docker-mcp:",
        "docker-integration-gate:",
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
        "needs: [source-structure, rust, fuzz-smoke, rust-boundaries, supply-chain, node, protocol, dco]"
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
    let onlyoffice = fs::read_to_string(root.join(".github/workflows/onlyoffice-release.yml"))
        .expect("ONLYOFFICE release scaffold workflow");
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
    assert!(checks.contains("ubuntu-26.04-arm"));
    assert!(checks.contains("linux/amd64"));
    assert!(checks.contains("linux/arm64"));
    assert!(checks.contains("linux/riscv64"));
    assert!(checks.contains("--qemu-mode rootless"));
    assert!(checks.contains("azure/setup-helm@9bc31f4ebc9c6b171d7bfbaa5d006ae7abdb4310"));
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
    for job in [
        "docker-core-acceptance:",
        "docker-collaboration-acceptance:",
        "docker-mcp-acceptance:",
    ] {
        assert!(release.contains(job), "release workflow is missing {job}");
    }
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
    assert!(release.contains("actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"));
    assert!(release.contains("sha256sum --check SHA256SUMS"));
    assert!(release.contains("refusing to replace existing Helm release"));
    assert!(release.contains("--verify-tag"));
    for release_role in [
        "filebelt-vfs",
        "filebelt-headscale-sync",
        "filebelt-nfs-relay",
        "filebelt-revision",
    ] {
        assert!(
            release.contains(release_role),
            "release promotion must carry {release_role}"
        );
        assert!(
            dry_run.contains("Build all fifteen Apache roles"),
            "dry-run must build the complete Apache image plan"
        );
    }
    for output in [
        "steps.subjects.outputs.vfs",
        "steps.subjects.outputs.headscale_sync",
        "steps.subjects.outputs.nfs_relay",
        "steps.subjects.outputs.revision",
    ] {
        assert!(release.contains(output), "release must attest {output}");
    }

    let exact_artifact =
        fs::read_to_string(root.join("tests/scripts/run-kubernetes-release-gate.sh"))
            .expect("release acceptance script");
    assert!(exact_artifact.contains("tests/docker/units/run-unit.py"));
    assert!(exact_artifact.contains("--image-channel release"));
    assert!(exact_artifact.contains("core|collaboration|mcp"));
    assert!(!exact_artifact.contains("run-image-matrix.sh"));
    for required in [
        "permissions:\n  contents: read",
        "cargo check --locked --manifest-path adapters/onlyoffice/Cargo.toml --target riscv64gc-unknown-linux-musl",
        "pnpm --filter @filebelt/devops test",
        "check-onlyoffice-helm-chart.sh",
        "riscv64Policy: \"compile-and-probe-only\"",
    ] {
        assert!(
            onlyoffice.contains(required),
            "ONLYOFFICE workflow is missing {required}"
        );
    }
    for forbidden in ["packages: write", "docker push", "helm push"] {
        assert!(
            !onlyoffice.contains(forbidden),
            "ONLYOFFICE workflow contains {forbidden}"
        );
    }
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
        .find("actions/setup-node@820762786026740c76f36085b0efc47a31fe5020")
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

#[test]
fn phase3_workloads_bypass_transitive_skips_and_require_successful_bootstrap() {
    let root = repository_root();
    let workflow = fs::read_to_string(root.join(".github/workflows/check-filebelt.yml"))
        .expect("check workflow");

    for (job, next_job, expected_condition) in [
        (
            "phase3-kind-current",
            "phase3-kind-supported",
            "if: ${{ !cancelled() && needs.bootstrap-gate.result == 'success' && github.event_name == 'pull_request' }}",
        ),
        (
            "phase3-kind-supported",
            "phase3-network-calico",
            "if: ${{ !cancelled() && needs.bootstrap-gate.result == 'success' && github.event_name != 'pull_request' }}",
        ),
        (
            "phase3-network-calico",
            "phase3-network-cilium",
            "if: ${{ !cancelled() && needs.bootstrap-gate.result == 'success' }}",
        ),
        (
            "phase3-network-cilium",
            "phase3-gate",
            "if: ${{ !cancelled() && needs.bootstrap-gate.result == 'success' && github.event_name != 'pull_request' }}",
        ),
    ] {
        let job = workflow_job(&workflow, job, next_job);
        assert!(job.contains(expected_condition));
        assert!(job.contains("needs: bootstrap-gate"));
        assert!(!job.contains("always()"));
    }
}

#[test]
fn fuzz_matrices_are_bounded_pinned_and_blocking() {
    let root = repository_root();
    let workflow = fs::read_to_string(root.join(".github/workflows/check-filebelt.yml"))
        .expect("check workflow");
    let smoke = workflow_job(&workflow, "fuzz-smoke", "rust-boundaries");
    let sustained = workflow_job(&workflow, "fuzz-sustained", "phase1-images-native");
    let targets = [
        "nfs_vfs_boundary",
        "mcp_runner_relay",
        "collaboration_wire",
        "revision_protocol",
        "runtime_config",
    ];
    for target in targets {
        assert!(smoke.contains(target));
        assert!(sustained.contains(target));
    }
    for required in [
        "if: github.event_name == 'pull_request'",
        "profile: [stable, asan]",
        "max-parallel: 5",
        "cargo install --locked cargo-fuzz --version 0.13.2",
        "rustup toolchain install nightly-2026-08-04 --profile minimal",
        "--mode smoke",
        "--runs 256",
    ] {
        assert!(
            smoke.contains(required),
            "smoke matrix is missing {required}"
        );
    }
    for required in [
        "needs.bootstrap-gate.result == 'success'",
        "github.event_name != 'pull_request'",
        "max-parallel: 3",
        "--profile asan",
        "--mode campaign",
        "github.event_name == 'push' && '900' || '3600'",
    ] {
        assert!(
            sustained.contains(required),
            "sustained matrix is missing {required}"
        );
    }
    assert!(!workflow.contains("actions/cache"));
    assert!(workflow.contains("FUZZ_SMOKE: ${{ needs.fuzz-smoke.result }}"));
    assert!(workflow.contains("FUZZ_SUSTAINED: ${{ needs.fuzz-sustained.result }}"));
}

#[test]
fn docker_units_consume_exact_amd64_archives_in_event_tiers() {
    let root = repository_root();
    let workflow = fs::read_to_string(root.join(".github/workflows/check-filebelt.yml"))
        .expect("check workflow");
    for (job, next, unit, non_pr_only) in [
        ("docker-core", "docker-collaboration", "core", false),
        ("docker-collaboration", "docker-mcp", "collaboration", true),
        ("docker-mcp", "docker-integration-gate", "mcp", true),
    ] {
        let body = workflow_job(&workflow, job, next);
        assert!(body.contains("needs: [bootstrap-gate, phase1-images-native]"));
        assert!(body.contains("!cancelled()"));
        assert!(body.contains("needs.bootstrap-gate.result == 'success'"));
        assert!(body.contains("needs.phase1-images-native.result == 'success'"));
        assert!(body.contains("name: filebelt-phase1-amd64"));
        assert!(body.contains(&format!("--unit {unit}")));
        assert!(body.contains("--image-channel build"));
        assert!(!body.contains("--build"));
        assert_eq!(
            body.contains("github.event_name != 'pull_request'"),
            non_pr_only
        );
    }
    let gate = workflow_job(&workflow, "docker-integration-gate", "phase3-kind-current");
    assert!(gate.contains("needs: [docker-core, docker-collaboration, docker-mcp]"));
    assert!(gate.contains("test \"$CORE\" = success"));
    assert!(gate.contains("test \"$COLLABORATION\" = skipped"));
    assert!(gate.contains("test \"$MCP\" = success"));

    let release =
        fs::read_to_string(root.join(".github/workflows/release.yml")).expect("release workflow");
    for (job, next, unit) in [
        (
            "docker-core-acceptance",
            "docker-collaboration-acceptance",
            "core",
        ),
        (
            "docker-collaboration-acceptance",
            "docker-mcp-acceptance",
            "collaboration",
        ),
        ("docker-mcp-acceptance", "kubernetes-compatibility", "mcp"),
    ] {
        let body = workflow_job(&release, job, next);
        assert!(body.contains("!cancelled() && needs.image-platforms.result == 'success'"));
        assert!(body.contains("name: filebelt-release-amd64"));
        assert!(body.contains(&format!("--unit {unit}")));
    }
    assert!(release.contains("DOCKER_CORE: ${{ needs.docker-core-acceptance.result }}"));
    assert!(
        release
            .contains("DOCKER_COLLABORATION: ${{ needs.docker-collaboration-acceptance.result }}")
    );
    assert!(release.contains("DOCKER_MCP: ${{ needs.docker-mcp-acceptance.result }}"));
}
