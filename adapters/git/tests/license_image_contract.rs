// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

#[test]
fn wrapper_and_bundled_git_keep_distinct_license_boundaries() {
    let manifest: toml::Value = toml::from_str(include_str!("../Cargo.toml"))
        .expect("the adapter Cargo manifest must parse");
    assert_eq!(manifest["package"]["license"].as_str(), Some("Apache-2.0"));

    let policy: toml::Value = toml::from_str(include_str!("../supply-chain.toml"))
        .expect("the adapter supply-chain policy must parse");
    assert_eq!(
        policy["first_party"]["license"].as_str(),
        Some("Apache-2.0")
    );
    assert_eq!(policy["git"]["license"].as_str(), Some("GPL-2.0-only"));
    assert_eq!(
        policy["git"]["boundary"].as_str(),
        Some("separate-executable")
    );
    assert_eq!(
        policy["git"]["image_path"].as_str(),
        Some("/opt/filebelt-git/bin/git")
    );
    assert_eq!(policy["zlib"]["license"].as_str(), Some("Zlib"));
    assert_eq!(policy["zlib"]["admission"].as_str(), Some("blocked"));
    let minimum_expression = policy["image"]["minimum_license_expression"]
        .as_str()
        .expect("the aggregate image must define a minimum expression");
    for license in ["Apache-2.0", "GPL-2.0-only", "MIT", "Zlib"] {
        assert!(minimum_expression.contains(license));
    }

    let dependencies = manifest["dependencies"]
        .as_table()
        .expect("adapter dependencies must be a table")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for forbidden in ["git2", "libgit2-sys", "gix", "jgit", "dulwich"] {
        assert!(
            !dependencies.contains(forbidden),
            "the Apache wrapper must not link the Git implementation dependency {forbidden}"
        );
    }
}

#[test]
fn image_build_is_offline_and_fail_closed() {
    let dockerfile = include_str!("../Dockerfile");
    for forbidden in ["curl ", "wget ", "apt-get", "apk add", "dnf install"] {
        assert!(
            !dockerfile.contains(forbidden),
            "the release image recipe must not acquire inputs with {forbidden}"
        );
    }
    for required in [
        "COPY adapter-inputs/git/upstream/git-2.55.0.tar.xz",
        "COPY adapter-inputs/git/upstream/zlib-1.3.1.tar.gz",
        "COPY adapter-inputs/git/vendor",
        "COPY adapter-inputs/git/SOURCE-MANIFEST.json",
        "--network=none",
        "build --locked --offline --release",
        "test \"${LICENSE_QUALIFICATION}\" = \"qualified\"",
        "test \"${IMAGE_BUILD_STATE}\" = \"eligible\"",
        "FROM scratch",
        "io.filebelt.first-party-license=\"Apache-2.0\"",
        "io.filebelt.corresponding-source.sha256",
        "/usr/share/licenses/filebelt-git-adapter/Apache-2.0.txt",
        "/usr/share/licenses/git/GPL-2.0-only.txt",
        "/usr/share/doc/filebelt-git-adapter/SOURCE-MANIFEST.json",
    ] {
        assert!(
            dockerfile.contains(required),
            "the release image recipe is missing required contract {required}"
        );
    }

    let policy: toml::Value = toml::from_str(include_str!("../supply-chain.toml"))
        .expect("the adapter supply-chain policy must parse");
    assert_eq!(
        policy["source_qualification"]["state"].as_str(),
        Some("blocked")
    );
    assert_eq!(policy["image_build"]["state"].as_str(), Some("blocked"));
    assert_eq!(policy["publication"]["state"].as_str(), Some("blocked"));
    for table in ["source_qualification", "image_build", "publication"] {
        assert!(
            policy[table]["state_scope"]
                .as_str()
                .is_some_and(|value| value.contains("checked-in-default")),
            "{table} must distinguish the checked-in sentinel from derived release evidence"
        );
    }
}

#[test]
fn every_git_process_starts_from_a_closed_environment() {
    let source = include_str!("../src/lib.rs");
    assert_eq!(
        source
            .matches(".env_clear()\n            .envs(git_environment())")
            .count(),
        2,
        "both raw and repository-scoped Git commands must discard ambient Git variables",
    );
}
