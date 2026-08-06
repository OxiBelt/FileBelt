// SPDX-License-Identifier: Apache-2.0

use std::fs;

use filebelt_repository_tests::repository_root;

const ROLES: [&str; 7] = [
    "filebelt-api",
    "filebelt-worker-io",
    "filebelt-worker-maintenance",
    "filebelt-media-controller",
    "filebelt-mcp-broker",
    "filebelt-tools",
    "filebelt-web",
];

#[test]
fn image_plan_contract_fixes_roles_platforms_and_registry() {
    let root = repository_root();
    let plan = fs::read_to_string(root.join("devops/source/image-plan.ts")).expect("image plan");
    for role in ROLES {
        assert!(
            plan.contains(&format!("\"{role}\"")),
            "missing image role {role}"
        );
    }
    assert!(
        plan.contains("ghcr.io/oxibelt/${ImageRole}"),
        "registry mapping must stay fixed"
    );
    for platform in ["linux/amd64", "linux/arm64", "linux/riscv64"] {
        assert!(plan.contains(&format!("\"{platform}\"")));
    }
    assert!(plan.contains("uid: 10001, gid: 10001"));
    assert!(plan.contains("Apache-2.0 AND MIT"));
    assert!(plan.contains("WEB_IMAGE_LICENSE = \"Apache-2.0\""));
    assert!(plan.contains("PlatformComponentInventory"));
    for component in ["rust-std", "musl", "rustc", "gcc", "binutils"] {
        assert!(plan.contains(&format!("\"{component}\"")));
    }
    assert!(plan.contains("`pkg:cargo/${packageName}@${FILEBELT_PACKAGE_VERSION}`"));
    assert!(plan.contains("`Cargo.lock#${packageName}@${FILEBELT_PACKAGE_VERSION}`"));
}

#[test]
fn role_dockerfiles_use_scratch_non_root_and_complete_oci_labels() {
    let root = repository_root();
    let rust =
        fs::read_to_string(root.join("source/ops/Dockerfile.roles")).expect("Rust role Dockerfile");
    let web = fs::read_to_string(root.join("ui/web/Dockerfile")).expect("web Dockerfile");
    for dockerfile in [&rust, &web] {
        assert!(dockerfile.contains("FROM scratch"));
        assert!(dockerfile.contains("USER 10001:10001"));
        assert!(dockerfile.contains("LICENSES/Apache-2.0.txt"));
        assert!(!dockerfile.contains("COPY adapters"));
        for label in [
            "org.opencontainers.image.title",
            "org.opencontainers.image.description",
            "org.opencontainers.image.source",
            "org.opencontainers.image.url",
            "org.opencontainers.image.version",
            "org.opencontainers.image.revision",
            "org.opencontainers.image.created",
            "org.opencontainers.image.licenses",
            "io.filebelt.image.role",
            "io.filebelt.build.source-ref",
            "io.filebelt.build.dirty",
            "io.filebelt.build.kind",
        ] {
            assert!(dockerfile.contains(label), "missing OCI label {label}");
        }
    }
    assert!(rust.contains("riscv64gc-unknown-linux-musl"));
    assert!(rust.contains("LICENSES/MIT.txt"));
    assert!(rust.contains("Apache-2.0 AND MIT"));
    assert!(rust.contains("snapshot.debian.org/archive/debian/20260713T000000Z"));
    assert!(rust.contains("binutils=2.44-3"));
    assert!(rust.contains("musl-tools=1.2.5-3.1~deb13u1"));
    assert!(rust.contains("Rust-COPYRIGHT-library.html"));
    assert!(rust.contains("musl-COPYRIGHT"));
    assert!(!rust.contains("apt-get install -y --no-install-recommends binutils musl-tools"));
    assert!(web.contains("org.opencontainers.image.licenses=\"Apache-2.0\""));
    assert!(!web.contains("LICENSES/MIT.txt"));
    assert!(!web.contains("THIRD_PARTY_NOTICES.md"));
    assert!(!web.contains("ENTRYPOINT"));
    assert!(!web.contains("CMD "));
}

#[test]
fn evidence_pipeline_is_archive_only_and_fail_closed() {
    let root = repository_root();
    let builder = fs::read_to_string(root.join("tests/scripts/build-docker-image-artifact.sh"))
        .expect("image artifact builder");
    let matrix =
        fs::read_to_string(root.join("tests/scripts/run-image-matrix.sh")).expect("image matrix");
    let validator =
        fs::read_to_string(root.join("tests/scripts/validate-image.py")).expect("validator");
    assert!(builder.contains("type=docker,dest="));
    assert!(!builder.contains("--push"));
    assert!(!builder.contains("docker push"));
    assert!(matrix.contains("--format cyclonedx"));
    assert!(matrix.contains("trivy sbom --format json"));
    assert!(!matrix.contains("trivy image --input \"${archive}\" --format json"));
    assert!(matrix.contains("evaluate-vulnerabilities"));
    assert!(validator.contains("role executable contains a dynamic interpreter"));
    assert!(validator.contains("image runtime user must be 10001:10001"));
    assert!(validator.contains(".wh..wh..opq"));
    assert!(validator.contains("unsupported special archive entry"));
    let normalizer = fs::read_to_string(root.join("tests/scripts/normalize-cyclonedx.py"))
        .expect("CycloneDX normalizer");
    assert!(normalizer.contains("Rust image component inventory must be nonempty"));
    assert!(normalizer.contains("runtime and build-tool components"));
    assert!(normalizer.contains("\"scope\": \"required\""));
    assert!(normalizer.contains("else \"excluded\""));
}
