// SPDX-License-Identifier: Apache-2.0

#[test]
fn image_keeps_network_tools_as_separate_executables() {
    let manifest = include_str!("../Cargo.toml");
    assert!(manifest.contains("license = \"Apache-2.0\""));

    let policy = include_str!("../supply-chain.toml");
    for required in [
        "version = \"1.0.20260223\"",
        "version = \"7.1.0\"",
        "license = \"GPL-2.0-only\"",
        "boundary = \"separate-executable\"",
        "state = \"blocked\"",
    ] {
        assert!(policy.contains(required), "missing {required}");
    }
}

#[test]
fn image_build_is_offline_and_excludes_wg_quick() {
    let dockerfile = include_str!("../Dockerfile");
    for forbidden in [
        "curl ",
        "wget ",
        "apt-get",
        "apk add",
        "dnf install",
        "/wg-quick",
    ] {
        assert!(
            !dockerfile.contains(forbidden),
            "forbidden build input {forbidden}"
        );
    }
    for required in [
        "--network=none",
        "WIREGUARD_TOOLS_SHA256",
        "IPROUTE2_SHA256",
        "WITH_WGQUICK=no",
        "FROM scratch",
        "USER 0:0",
        "io.filebelt.first-party-license=\"Apache-2.0\"",
        "io.filebelt.corresponding-source.sha256",
    ] {
        assert!(
            dockerfile.contains(required),
            "missing build contract {required}"
        );
    }
}
