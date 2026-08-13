// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fs;

use filebelt_fuzz::{
    COLLABORATION_WIRE_MAX_INPUT_BYTES, MCP_RUNNER_RELAY_MAX_INPUT_BYTES,
    NFS_VFS_BOUNDARY_MAX_INPUT_BYTES, REVISION_PROTOCOL_MAX_INPUT_BYTES,
    RUNTIME_CONFIG_MAX_INPUT_BYTES, sha256_hex,
};
use filebelt_repository_tests::repository_root;
use toml::Value;

fn document(path: &str) -> Value {
    let root = repository_root();
    let source = fs::read_to_string(root.join(path))
        .unwrap_or_else(|error| panic!("cannot read {path}: {error}"));
    toml::from_str::<Value>(&source).unwrap_or_else(|error| panic!("cannot parse {path}: {error}"))
}

#[test]
fn fuzz_catalog_matches_explicit_bins_and_limits() {
    let root = repository_root();
    let catalog = document("fuzz/targets.toml");
    assert_eq!(catalog["schema_version"].as_integer(), Some(1));
    assert_eq!(catalog["cargo_fuzz_version"].as_str(), Some("0.13.2"));
    assert_eq!(catalog["libfuzzer_sys_version"].as_str(), Some("0.4.13"));
    assert_eq!(catalog["stable_toolchain"].as_str(), Some("1.97.1"));
    assert_eq!(
        catalog["asan_toolchain"].as_str(),
        Some("nightly-2026-08-04")
    );
    assert_eq!(catalog["timeout_seconds"].as_integer(), Some(10));
    assert_eq!(catalog["rss_limit_mib"].as_integer(), Some(3_072));
    assert_eq!(catalog["malloc_limit_mib"].as_integer(), Some(512));
    assert_eq!(catalog["smoke_runs"].as_integer(), Some(256));

    let expected = BTreeSet::from([
        ("collaboration_wire", COLLABORATION_WIRE_MAX_INPUT_BYTES),
        ("mcp_runner_relay", MCP_RUNNER_RELAY_MAX_INPUT_BYTES),
        ("nfs_vfs_boundary", NFS_VFS_BOUNDARY_MAX_INPUT_BYTES),
        ("revision_protocol", REVISION_PROTOCOL_MAX_INPUT_BYTES),
        ("runtime_config", RUNTIME_CONFIG_MAX_INPUT_BYTES),
    ]);
    let targets = catalog["target"].as_array().expect("target array");
    let actual = targets
        .iter()
        .map(|target| {
            let name = target["name"].as_str().expect("target name");
            let maximum = usize::try_from(
                target["max_input_bytes"]
                    .as_integer()
                    .expect("target maximum"),
            )
            .expect("positive target maximum");
            let seed_directory = target["seed_directory"].as_str().expect("seed directory");
            assert!(root.join(seed_directory).is_dir());
            if let Some(dictionary) = target.get("dictionary") {
                assert!(
                    root.join(dictionary.as_str().expect("dictionary path"))
                        .is_file()
                );
            }
            (name, maximum)
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);

    let manifest = document("fuzz/Cargo.toml");
    assert_eq!(
        manifest["dependencies"]["libfuzzer-sys"]["workspace"].as_bool(),
        Some(true)
    );
    let bins = manifest["bin"]
        .as_array()
        .expect("explicit fuzz bins")
        .iter()
        .map(|bin| bin["name"].as_str().expect("bin name"))
        .collect::<BTreeSet<_>>();
    assert_eq!(bins, expected.iter().map(|(name, _)| *name).collect());
    for (name, _) in expected {
        assert!(root.join(format!("fuzz/fuzz_targets/{name}.rs")).is_file());
    }
}

#[test]
fn reviewed_seed_manifest_is_complete_and_digest_bound() {
    let root = repository_root();
    let seeds = document("fuzz/seeds.toml");
    assert_eq!(seeds["schema_version"].as_integer(), Some(1));
    let mut targets = BTreeSet::new();
    for seed in seeds["seed"].as_array().expect("seed array") {
        let target = seed["target"].as_str().expect("seed target");
        assert!(targets.insert(target), "duplicate seed target {target}");
        let path = seed["path"].as_str().expect("seed path");
        let expected = seed["sha256"].as_str().expect("seed digest");
        let bytes = fs::read(root.join(path)).expect("reviewed seed must exist");
        assert_eq!(sha256_hex(&bytes), expected);
        assert!(path.starts_with(&format!("fuzz/seeds/{target}/")));
    }
    assert_eq!(targets.len(), 5);
    assert_eq!(
        targets,
        BTreeSet::from([
            "collaboration_wire",
            "mcp_runner_relay",
            "nfs_vfs_boundary",
            "revision_protocol",
            "runtime_config",
        ])
    );
}

#[test]
fn runner_enforces_the_cataloged_resource_controls() {
    let root = repository_root();
    let runner = fs::read_to_string(root.join("tests/scripts/run-fuzz-target.sh"))
        .expect("fuzz runner must exist");
    for required in [
        "cargo fuzz --version",
        "-timeout=${timeout_seconds}",
        "-rss_limit_mb=${rss_limit_mib}",
        "-malloc_limit_mb=${malloc_limit_mib}",
        "-max_len=${max_input_bytes}",
        "-detect_leaks=${detect_leaks}",
        "-artifact_prefix=${artifact_prefix}",
        "--no-default-features",
        "--features",
        "fuzz-target",
    ] {
        assert!(runner.contains(required), "runner is missing {required}");
    }
    assert!(runner.contains("sanitizer=none"));
    assert!(runner.contains("sanitizer=address"));
    assert!(runner.contains("rm -rf -- \"${corpus}\" \"${artifact_directory}\""));
    assert!(runner.contains("rm -f -- \"${log}\""));
}

#[test]
fn native_fuzz_runtime_has_an_exact_test_only_audit() {
    let audits = document("supply-chain/audits.toml");
    for (name, version) in [("arbitrary", "1.4.2"), ("libfuzzer-sys", "0.4.13")] {
        let records = audits["audits"][name]
            .as_array()
            .unwrap_or_else(|| panic!("{name} audit array"));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["version"].as_str(), Some(version));
        assert_eq!(records[0]["criteria"].as_str(), Some("safe-to-run"));
    }

    let config = document("supply-chain/config.toml");
    for dependency in ["arbitrary", "libfuzzer-sys"] {
        assert!(config["exemptions"].get(dependency).is_none());
    }
    assert_eq!(
        config["policy"]["filebelt-fuzz"]["dependency-criteria"]["libfuzzer-sys"].as_str(),
        Some("safe-to-run")
    );

    let deny = document("deny.toml");
    assert!(
        !deny["licenses"]["allow"]
            .as_array()
            .expect("global license allowlist")
            .iter()
            .any(|license| license.as_str() == Some("NCSA"))
    );
    let exceptions = deny["licenses"]["exceptions"]
        .as_array()
        .expect("license exceptions");
    let matching = exceptions
        .iter()
        .filter(|exception| exception["crate"].as_str() == Some("libfuzzer-sys@0.4.13"))
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1);
    assert_eq!(
        matching[0]["allow"]
            .as_array()
            .expect("exception licenses")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        ["NCSA"]
    );
}
