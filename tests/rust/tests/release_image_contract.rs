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
    assert!(plan.contains("Apache-2.0 AND MIT AND CDLA-Permissive-2.0"));
    assert!(plan.contains("Apache-2.0 AND MIT AND MPL-2.0 AND CDLA-Permissive-2.0"));
    assert!(plan.contains("WEB_IMAGE_LICENSE = \"Apache-2.0 AND MIT AND ISC AND 0BSD\""));
    assert!(plan.contains(
        "ghcr.io/oxibelt/oxibelt@sha256:e8556a0103feff47bf6135062e70e980e000176598fd438959ea55d99c844030"
    ));
    assert!(plan.contains("kind: \"oxibelt-edge\""));
    assert!(plan.contains("PlatformComponentInventory"));
    for component in ["rust-std", "musl", "rustc", "gcc", "binutils"] {
        assert!(plan.contains(&format!("\"{component}\"")));
    }
    assert!(plan.contains("`pkg:cargo/${packageName}@${FILEBELT_PACKAGE_VERSION}`"));
    assert!(plan.contains("`Cargo.lock#${packageName}@${FILEBELT_PACKAGE_VERSION}`"));
}

#[test]
fn role_dockerfiles_use_non_root_runtimes_and_complete_oci_labels() {
    let root = repository_root();
    let rust =
        fs::read_to_string(root.join("source/ops/Dockerfile.roles")).expect("Rust role Dockerfile");
    let web = fs::read_to_string(root.join("ui/web/Dockerfile")).expect("web Dockerfile");
    for dockerfile in [&rust, &web] {
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
    assert!(rust.contains("FROM scratch"));
    assert!(rust.contains("riscv64gc-unknown-linux-musl"));
    assert!(rust.contains("LICENSES/MIT.txt"));
    assert!(rust.contains("LICENSES/CDLA-Permissive-2.0.txt"));
    assert!(rust.contains("LICENSES/MPL-2.0.txt"));
    assert!(rust.contains("webpki-roots-SOURCE.txt"));
    assert!(rust.contains("option-ext-SOURCE.txt"));
    assert!(rust.contains(
        "org.opencontainers.image.licenses=\"Apache-2.0 AND MIT AND CDLA-Permissive-2.0\""
    ));
    assert!(rust.contains(
        "org.opencontainers.image.licenses=\"Apache-2.0 AND MIT AND MPL-2.0 AND CDLA-Permissive-2.0\""
    ));
    assert!(rust.contains("snapshot.debian.org/archive/debian/20260713T000000Z"));
    assert!(rust.contains("binutils=2.44-3"));
    assert!(rust.contains("musl-tools=1.2.5-3.1~deb13u1"));
    assert!(rust.contains("Rust-COPYRIGHT-library.html"));
    assert!(rust.contains("musl-COPYRIGHT"));
    assert!(!rust.contains("apt-get install -y --no-install-recommends binutils musl-tools"));
    assert!(web.contains("FROM ${OXIBELT_IMAGE} AS filebelt-web"));
    assert!(web.contains(
        "ghcr.io/oxibelt/oxibelt@sha256:e8556a0103feff47bf6135062e70e980e000176598fd438959ea55d99c844030"
    ));
    assert!(
        web.contains("org.opencontainers.image.licenses=\"Apache-2.0 AND MIT AND ISC AND 0BSD\"")
    );
    assert!(web.contains("LICENSES/MIT.txt"));
    assert!(web.contains("THIRD_PARTY_NOTICES.md"));
    assert!(web.contains("lucide-ISC.txt"));
    assert!(web.contains("tslib-0BSD.txt"));
    assert!(web.contains("OXIBELT_NOTICE.md"));
    assert!(web.contains(
        "ENTRYPOINT [\"/usr/local/bin/oxibelt\", \"--config\", \"/etc/oxibelt/config/oxibelt.toml\"]"
    ));
    assert!(!web.contains("COPY adapters"));
}

#[test]
fn oxibelt_edge_profile_keeps_routes_and_browser_security_explicit() {
    let root = repository_root();
    let edge =
        fs::read_to_string(root.join("ui/web/edge/oxibelt.toml")).expect("OxiBelt edge profile");
    let acceptance = fs::read_to_string(root.join("ui/web/edge/oxibelt.acceptance.toml"))
        .expect("OxiBelt acceptance edge profile");
    for route in ["/api/v1", "/io/v1", "/public/v1"] {
        assert!(edge.contains(&format!("path_prefix = \"{route}\"")));
    }
    assert!(edge.contains("mode = \"overwrite\""));
    assert!(edge.contains("fail_on_untrusted_forwarded_headers = true"));
    for header in ["x-user", "x-group", "x-principal", "x-tenant"] {
        assert!(edge.contains(&format!("\"{header}\"")));
    }
    assert!(edge.contains("retry_non_idempotent = false"));
    assert!(edge.matches("[routes.retry]").count() >= 3);
    assert!(edge.matches("value = \"no-store\"").count() >= 3);
    assert!(edge.contains("spa_fallback = \"/index.html\""));
    assert!(edge.contains("script-src 'self'"));
    assert!(edge.contains("frame-ancestors 'none'"));
    assert!(edge.contains("html = \"no-store\""));
    assert!(edge.contains("js = \"no-store\""));
    assert!(!edge.contains("filebelt-development-oidc"));
    assert!(!edge.contains("/_filebelt-test-oidc/authorize"));
    assert!(acceptance.contains("filebelt-development-oidc"));
    assert!(acceptance.contains("/_filebelt-test-oidc/authorize"));
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
