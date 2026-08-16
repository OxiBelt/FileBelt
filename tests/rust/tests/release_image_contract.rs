// SPDX-License-Identifier: Apache-2.0

use std::fs;

use filebelt_repository_tests::repository_root;

const ROLES: [&str; 15] = [
    "filebelt-api",
    "filebelt-worker-io",
    "filebelt-worker-maintenance",
    "filebelt-media-controller",
    "filebelt-document",
    "filebelt-revision",
    "filebelt-collaboration",
    "filebelt-mcp-broker",
    "filebelt-controller",
    "filebelt-mcp-runner",
    "filebelt-tools",
    "filebelt-vfs",
    "filebelt-headscale-sync",
    "filebelt-nfs-relay",
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
    assert!(plan.contains("WebImageLicense = \"Apache-2.0 AND MIT AND ISC AND 0BSD\""));
    assert!(plan.contains(
        "ghcr.io/oxibelt/oxibelt@sha256:e8556a0103feff47bf6135062e70e980e000176598fd438959ea55d99c844030"
    ));
    assert!(plan.contains("kind: \"oxibelt-edge\""));
    assert!(plan.contains("PlatformComponentInventory"));
    for component in [
        "rust-std",
        "musl",
        "rustc",
        "gcc",
        "binutils",
        "cmake",
        "clang",
        "libclang-dev",
        "ninja-build",
    ] {
        assert!(plan.contains(&format!("\"{component}\"")));
    }
    assert!(plan.contains("`pkg:cargo/${PackageName}@${FileBeltPackageVersion}`"));
    assert!(plan.contains("`Cargo.lock#${PackageName}@${FileBeltPackageVersion}`"));
}

#[test]
fn role_dockerfiles_use_non_root_runtimes_and_complete_oci_labels() {
    let root = repository_root();
    let rust =
        fs::read_to_string(root.join("source/ops/Dockerfile.roles")).expect("Rust role Dockerfile");
    let riscv64_toolchain =
        fs::read_to_string(root.join("source/ops/riscv64-musl-toolchain.cmake"))
            .expect("RISC-V CMake toolchain");
    let web = fs::read_to_string(root.join("ui/web/Dockerfile")).expect("web Dockerfile");
    for workspace in ["admin", "design-system", "markdown", "mcp-settings", "web"] {
        assert!(
            web.contains(&format!("COPY ui/{workspace} ui/{workspace}")),
            "web image must copy the {workspace} workspace before building"
        );
    }
    assert!(
        web.contains("COPY ui/vitest-fluent-icons-resolver.ts ui/vitest-fluent-icons-resolver.ts"),
        "web image must copy shared Vite configuration dependencies before building"
    );
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
            "io.filebelt.build.target-cpu",
        ] {
            assert!(dockerfile.contains(label), "missing OCI label {label}");
        }
    }
    assert!(rust.contains("FROM scratch"));
    assert!(rust.contains("test \"${FILEBELT_TARGET_CPU}\" = x86-64-v3"));
    assert!(rust.contains("-Ctarget-cpu=${FILEBELT_TARGET_CPU}"));
    assert!(rust.contains("-Clink-arg=-Wl,-z,${FILEBELT_TARGET_CPU}"));
    assert!(rust.contains("CFLAGS=\"-march=${FILEBELT_TARGET_CPU}\""));
    assert!(rust.contains("CXXFLAGS=\"${CFLAGS}\""));
    assert!(web.contains("FILEBELT_TARGET_CPU"));
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
    for tool in [
        "clang=1:19.0-63",
        "cmake=3.31.6-2",
        "libclang-dev=1:19.0-63",
        "ninja-build=1.12.1-1",
    ] {
        assert!(
            rust.contains(tool),
            "missing pinned RISC-V build tool {tool}"
        );
    }
    for target_variable in [
        "AWS_LC_SYS_USE_SYSTEM_riscv64gc_unknown_linux_musl=\"0\"",
        "BINDGEN_EXTRA_CLANG_ARGS_riscv64gc_unknown_linux_musl",
        "CMAKE_GENERATOR_riscv64gc_unknown_linux_musl=\"Ninja\"",
        "CMAKE_TOOLCHAIN_FILE_riscv64gc_unknown_linux_musl",
    ] {
        assert!(
            rust.contains(target_variable),
            "missing RISC-V target input {target_variable}"
        );
    }
    for identity in [
        "14.3.0",
        "riscv64-unknown-linux-musl",
        "GNU ld (crosstool-NG UNKNOWN) 2.45",
        "3fe20d705129f8ba4ae6be393fd4c484479f688f576af78c0ff2bb10e59d5f86",
    ] {
        assert!(
            rust.contains(identity),
            "missing RISC-V identity {identity}"
        );
    }
    assert!(rust.contains("COPY --from=riscv64-toolchain /x-tools /x-tools"));
    assert!(!rust.contains("CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_MUSL_RUNNER"));
    for setting in [
        "set(CMAKE_SYSTEM_NAME Linux)",
        "set(CMAKE_SYSTEM_PROCESSOR riscv64)",
        "set(CMAKE_SYSROOT",
        "set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)",
        "-march=rv64gc -mabi=lp64d -mcmodel=medany",
    ] {
        assert!(
            riscv64_toolchain.contains(setting),
            "missing RISC-V CMake setting {setting}"
        );
    }
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
fn onlyoffice_source_recipe_includes_its_protocol_build_inputs() {
    let root = repository_root();
    let dockerfile = fs::read_to_string(root.join("adapters/onlyoffice/Dockerfile"))
        .expect("ONLYOFFICE adapter Dockerfile");
    let dockerignore = fs::read_to_string(root.join("adapters/onlyoffice/Dockerfile.dockerignore"))
        .expect("ONLYOFFICE adapter Docker ignore file");
    assert!(dockerfile.contains("WORKDIR /src\n"));
    assert!(dockerfile.contains("COPY . ."));
    for contract in [
        "cargo build --locked --offline --release",
        "--features qualified-release",
        "--target \"${RUST_TARGET}\"",
        "--manifest-path adapters/onlyoffice/Cargo.toml",
        "! readelf -d /filebelt-onlyoffice-adapter",
    ] {
        assert!(dockerfile.contains(contract), "missing {contract}");
    }
    assert!(dockerignore.contains("!adapters/onlyoffice/**"));
    assert!(!dockerignore.lines().any(|line| line == "source"));
}

#[test]
fn oxibelt_edge_profile_keeps_routes_and_browser_security_explicit() {
    let root = repository_root();
    let edge =
        fs::read_to_string(root.join("ui/web/edge/oxibelt.toml")).expect("OxiBelt edge profile");
    let acceptance = fs::read_to_string(root.join("ui/web/edge/oxibelt.acceptance.toml"))
        .expect("OxiBelt acceptance edge profile");
    let chart = fs::read_to_string(root.join("deploy/helm/filebelt/values.yaml"))
        .expect("Helm chart values");
    let vite = fs::read_to_string(root.join("ui/web/vite.config.ts"))
        .expect("Vite browser security headers");
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
    assert!(edge.contains("require-trusted-types-for 'script'"));
    assert!(edge.contains("trusted-types 'none'"));
    assert!(edge.contains("name = \"filebelt-markdown-preview\""));
    assert!(edge.contains("path_prefix = \"/markdown-preview/\""));
    assert!(edge.contains("static_root = \"/srv/filebelt/markdown-preview\""));
    assert!(edge.contains("trusted-types filebelt-markdown-generated"));
    assert!(edge.contains("name = \"Access-Control-Allow-Origin\""));
    assert!(edge.contains("style-src 'self' 'unsafe-inline'; worker-src 'self' blob:"));
    assert!(
        edge.find("name = \"filebelt-markdown-preview\"") < edge.find("name = \"filebelt-spa\""),
        "the opaque preview route must precede the SPA catch-all"
    );
    assert!(edge.contains("path_prefix = \"/collaboration/v1/ws\""));
    assert!(edge.contains("protocols = [\"websocket\"]"));
    assert!(!edge.contains("/collaboration/v1/wt"));
    assert!(edge.contains("name = \"origin\""));
    assert!(edge.contains("exact = \"https://filebelt.localhost:8443\""));
    assert!(edge.contains("\"authorization\""));
    assert!(edge.contains("\"cookie\""));
    assert!(edge.contains("html = \"no-store\""));
    assert!(edge.contains("js = \"no-store\""));
    assert!(!edge.contains("filebelt-development-oidc"));
    assert!(!edge.contains("/_filebelt-test-oidc/authorize"));
    assert!(acceptance.contains("filebelt-development-oidc"));
    assert!(acceptance.contains("/_filebelt-test-oidc/authorize"));
    assert!(acceptance.contains("trusted-types filebelt-markdown-generated"));
    assert!(acceptance.contains("name = \"Access-Control-Allow-Origin\""));
    assert!(acceptance.contains("style-src 'self' 'unsafe-inline'; worker-src 'self' blob:"));
    assert!(acceptance.contains("path_prefix = \"/collaboration/v1/ws\""));
    assert!(!acceptance.contains("/collaboration/v1/wt"));
    assert!(chart.contains("trusted-types filebelt-markdown-generated"));
    assert!(chart.contains("name = \"Access-Control-Allow-Origin\""));
    assert!(chart.contains("style-src 'self' 'unsafe-inline'; worker-src 'self' blob:"));
    assert!(chart.contains("{{ if .Values.collaboration.webtransport.enabled }}"));
    assert!(chart.contains("path_prefix = \"/collaboration/v1/wt\""));
    assert!(chart.contains("max_http_version = \"h3\""));
    assert!(vite.contains("MarkdownPreviewContentSecurityPolicy"));
    assert!(vite.contains("trusted-types filebelt-markdown-generated"));
    assert!(vite.contains("Access-Control-Allow-Origin"));
    assert!(vite.contains("style-src 'self' 'unsafe-inline'; worker-src 'self' blob:"));
    assert!(
        acceptance.find("name = \"filebelt-markdown-preview\"")
            < acceptance.find("name = \"filebelt-spa\""),
        "the acceptance preview route must precede the SPA catch-all"
    );
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
