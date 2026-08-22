// SPDX-License-Identifier: Apache-2.0

use std::fs;

use filebelt_repository_tests::repository_root;
use toml::Value;

fn compatibility_policy() -> Value {
    let root = repository_root();
    let source = fs::read_to_string(root.join("supply-chain/license-compatibility-v1.toml"))
        .expect("license compatibility policy");
    toml::from_str(&source).expect("valid license compatibility policy")
}

#[test]
fn canonical_license_files_are_vendored() {
    let root = repository_root();
    for license in [
        "Apache-2.0",
        "GPL-2.0-only",
        "GPL-3.0-or-later",
        "LGPL-3.0-or-later",
        "AGPL-3.0-only",
        "MIT",
    ] {
        assert!(
            root.join(format!("LICENSES/{license}.txt")).is_file(),
            "missing canonical {license} text"
        );
    }
}

#[test]
fn machine_maps_separate_first_party_regions_from_image_components() {
    let root = repository_root();
    let regions = fs::read_to_string(root.join("supply-chain/license-regions.toml"))
        .expect("license regions");
    let regions: Value = toml::from_str(&regions).expect("valid license regions");
    let git = regions["regions"]
        .as_array()
        .expect("license regions array")
        .iter()
        .find(|region| region["path"].as_str() == Some("adapters/git"))
        .expect("Git adapter region");
    assert_eq!(git["license"].as_str(), Some("Apache-2.0"));

    let compatibility = compatibility_policy();
    let git_artifact = compatibility["artifacts"]
        .as_array()
        .expect("adapter artifacts")
        .iter()
        .find(|artifact| artifact["id"].as_str() == Some("filebelt-git-adapter"))
        .expect("Git adapter artifact");
    assert!(
        git_artifact["components"]
            .as_array()
            .expect("Git components")
            .iter()
            .any(|component| component["license"].as_str() == Some("GPL-2.0-only")),
        "Git image must preserve its separate GPL component",
    );
}

#[test]
fn compatibility_policy_covers_all_adapter_artifacts_and_relationships() {
    let policy = compatibility_policy();
    assert_eq!(policy["schema_version"].as_integer(), Some(1));
    let repository = policy["repository"]
        .as_table()
        .expect("repository compatibility policy");
    let relationship_types = repository["relationship_types"]
        .as_array()
        .expect("relationship types")
        .iter()
        .map(|value| value.as_str().expect("relationship string"))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        relationship_types,
        std::collections::BTreeSet::from([
            "build-only",
            "copied",
            "external",
            "linked",
            "separate-executable",
        ])
    );
    let artifacts = policy["artifacts"].as_array().expect("adapter artifacts");
    let artifact_ids = artifacts
        .iter()
        .map(|artifact| artifact["id"].as_str().expect("artifact id"))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        artifact_ids,
        std::collections::BTreeSet::from([
            "filebelt-directory-repository-adapter",
            "filebelt-ftp-ftps-gateway",
            "filebelt-git-adapter",
            "filebelt-nfs-gateway",
            "filebelt-onlyoffice-adapter",
            "filebelt-smb-gateway",
            "filebelt-transcoder",
            "filebelt-wireguard-init",
        ])
    );
    for artifact in artifacts {
        for component in artifact["components"]
            .as_array()
            .expect("artifact components")
        {
            let relationship = component["relationship"]
                .as_str()
                .expect("component relationship");
            let source_required = component["source_required"]
                .as_bool()
                .expect("source requirement");
            assert!(
                relationship == "external" || source_required,
                "distributed component must require source: {component:?}"
            );
        }
    }
}

#[test]
fn git_wrapper_is_apache_and_git_is_a_separate_gpl_executable() {
    let root = repository_root();
    let manifest =
        fs::read_to_string(root.join("adapters/git/Cargo.toml")).expect("Git adapter manifest");
    assert!(manifest.contains("license = \"Apache-2.0\""));

    let policy = compatibility_policy();
    let git = policy["artifacts"]
        .as_array()
        .expect("adapter artifacts")
        .iter()
        .find(|artifact| artifact["id"].as_str() == Some("filebelt-git-adapter"))
        .expect("Git artifact");
    let components = git["components"].as_array().expect("Git components");
    assert!(components.iter().any(|component| {
        component["id"].as_str() == Some("filebelt-git-adapter")
            && component["license"].as_str() == Some("Apache-2.0")
            && component["relationship"].as_str() == Some("linked")
    }));
    assert!(components.iter().any(|component| {
        component["id"].as_str() == Some("git-2.55.0")
            && component["license"].as_str() == Some("GPL-2.0-only")
            && component["relationship"].as_str() == Some("separate-executable")
            && component["path"].as_str() == Some("/opt/filebelt-git/bin/git")
    }));
}

#[test]
fn cargo_deny_admits_mpl_only_for_exact_root_package_version() {
    let root = repository_root();
    let root_deny = fs::read_to_string(root.join("deny.toml")).expect("root deny policy");
    assert!(root_deny.contains("unused-allowed-license = \"deny\""));
    assert!(!root_deny.contains("\n  \"MPL-2.0\","));
    assert!(root_deny.contains("{ crate = \"option-ext@0.2.0\", allow = [\"MPL-2.0\"] }"));
    for adapter in ["smb", "ftp-ftps", "onlyoffice", "git", "nfs", "transcode"] {
        let deny = fs::read_to_string(root.join(format!("adapters/{adapter}/deny.toml")))
            .expect("adapter deny policy");
        assert!(deny.contains("unused-allowed-license = \"deny\""));
        assert!(
            !deny.contains("MPL-2.0"),
            "broad MPL admission in {adapter}"
        );
    }
}

#[test]
fn pre_image_policy_is_fail_closed() {
    let policy = compatibility_policy();
    let preconditions = policy["repository"]["image_build_preconditions"]
        .as_array()
        .expect("image build preconditions")
        .iter()
        .map(|value| value.as_str().expect("precondition"))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        preconditions,
        std::collections::BTreeSet::from([
            "build-context",
            "build-inputs",
            "component-policy",
            "dependency-compatibility",
            "immutable-source",
            "license-notices",
            "source-bundle",
        ])
    );
}

#[test]
fn transcode_region_is_a_separate_gpl_workspace() {
    let root = repository_root();
    let policy = fs::read_to_string(root.join("supply-chain/license-regions.toml"))
        .expect("license regions");
    assert!(policy.contains(
        "path = \"adapters/transcode\"\nlicense = \"GPL-3.0-or-later\"\nworkspace = \"adapter\""
    ));
}

#[test]
fn wireguard_region_is_an_isolated_apache_workspace() {
    let root = repository_root();
    let policy = fs::read_to_string(root.join("supply-chain/license-regions.toml"))
        .expect("license regions");
    assert!(policy.contains(
        "path = \"adapters/wireguard\"\nlicense = \"Apache-2.0\"\nworkspace = \"adapter\""
    ));
}
