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
    assert_eq!(catalog["schema_version"].as_integer(), Some(3));
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
fn collaboration_wire_quarantine_is_single_target_and_lockfile_pinned() {
    let catalog = document("fuzz/targets.toml");
    let quarantines = catalog["quarantine"].as_array().expect("quarantine array");
    assert_eq!(quarantines.len(), 1);
    let quarantine = &quarantines[0];
    assert_eq!(quarantine["target"].as_str(), Some("collaboration_wire"));
    assert_eq!(
        quarantine["target_source"].as_str(),
        Some("fuzz/fuzz_targets/collaboration_wire.rs")
    );
    assert_eq!(
        quarantine["target_sha256"].as_str(),
        Some("de7845d41dce16f42c6afaa0128426484c119e1d05af29f909e1e2bd4fdc7421")
    );
    assert_eq!(
        quarantine["target_manifest"].as_str(),
        Some("fuzz/Cargo.toml")
    );
    assert_eq!(
        quarantine["target_manifest_bin_path"].as_str(),
        Some("fuzz_targets/collaboration_wire.rs")
    );
    let expected_implementation_sources = [
        (
            "fuzz/src/lib.rs",
            "ff50f91441c6d445d0cd0d9abc6570165730255eaf1091388a8892c303a2ec69",
        ),
        (
            "source/apps/filebelt-collaboration/src/lib.rs",
            "552ada6729d16225429bf9a94e595b796b7507bc3c8685120bde564d2ed5dbd4",
        ),
        (
            "source/apps/filebelt-collaboration/src/update_decoder.rs",
            "96d9e159c99794465f469809bc157a11d3ae9aeb228b53c7f45085083cca83ab",
        ),
    ];
    let implementation_sources = quarantine["implementation_sources"]
        .as_array()
        .expect("quarantined implementation sources");
    assert_eq!(
        implementation_sources.len(),
        expected_implementation_sources.len()
    );
    for (implementation, (expected_path, expected_digest)) in implementation_sources
        .iter()
        .zip(expected_implementation_sources)
    {
        assert_eq!(implementation["path"].as_str(), Some(expected_path));
        assert_eq!(implementation["sha256"].as_str(), Some(expected_digest));
        let bytes = fs::read(repository_root().join(expected_path))
            .expect("quarantined implementation source must exist");
        assert_eq!(sha256_hex(&bytes), expected_digest);
    }
    assert_eq!(quarantine["status"].as_str(), Some("risk_accepted"));
    assert_eq!(quarantine["dependency_name"].as_str(), Some("yrs"));
    assert_eq!(quarantine["dependency_version"].as_str(), Some("0.27.4"));
    assert_eq!(
        quarantine["dependency_source"].as_str(),
        Some("registry+https://github.com/rust-lang/crates.io-index")
    );
    assert_eq!(
        quarantine["dependency_checksum"].as_str(),
        Some("3987db9bdbe6f0f49c58ec3d0daf4750a70b40019c190f6c6708abfcdfe6bea0")
    );
    assert_eq!(
        quarantine["tracker"].as_str(),
        Some("https://github.com/OxiBelt/FileBelt/issues/10")
    );
    assert_eq!(
        quarantine["review_required_on_change"].as_bool(),
        Some(true)
    );
    assert_eq!(
        quarantine["clearance_requires"]
            .as_array()
            .expect("clearance requirements")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        [
            "tracked_resolution",
            "dependency_identity_change",
            "private_validation"
        ]
    );

    let target_names = catalog["target"]
        .as_array()
        .expect("target array")
        .iter()
        .filter_map(|target| target["name"].as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        target_names,
        BTreeSet::from([
            "collaboration_wire",
            "mcp_runner_relay",
            "nfs_vfs_boundary",
            "revision_protocol",
            "runtime_config"
        ])
    );
    assert!(target_names.contains(quarantine["target"].as_str().expect("quarantined target")));
    let target_source = quarantine["target_source"]
        .as_str()
        .expect("quarantined target source");
    let target_bytes = fs::read(repository_root().join(target_source))
        .expect("quarantined target source must exist");
    assert_eq!(
        sha256_hex(&target_bytes),
        quarantine["target_sha256"]
            .as_str()
            .expect("quarantined target digest")
    );

    let manifest = document(
        quarantine["target_manifest"]
            .as_str()
            .expect("quarantined target manifest"),
    );
    let matching_bins = manifest["bin"]
        .as_array()
        .expect("explicit fuzz bins")
        .iter()
        .filter(|binary| binary["name"].as_str() == quarantine["target"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(matching_bins.len(), 1, "quarantined target manifest bin");
    assert_eq!(
        matching_bins[0]["path"].as_str(),
        quarantine["target_manifest_bin_path"].as_str()
    );

    let lockfile = document("Cargo.lock");
    let matching = lockfile["package"]
        .as_array()
        .expect("lockfile packages")
        .iter()
        .filter(|package| {
            package["name"].as_str() == quarantine["dependency_name"].as_str()
                && package["version"].as_str() == quarantine["dependency_version"].as_str()
        })
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1, "quarantined dependency identity");
    let package = matching[0];
    assert_eq!(
        package["source"].as_str(),
        quarantine["dependency_source"].as_str()
    );
    assert_eq!(
        package["checksum"].as_str(),
        quarantine["dependency_checksum"].as_str()
    );
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
    assert!(runner.contains("sanitizer_environment=()"));
    let asan_branch = runner
        .split_once("if [[ ${profile} == asan ]]; then")
        .expect("ASan profile branch")
        .1
        .split_once("fi\n\nengine=(")
        .expect("end of ASan profile branch")
        .0;
    assert!(asan_branch.contains("sanitizer=address"));
    assert_eq!(
        asan_branch
            .matches("ASAN_OPTIONS=allocator_may_return_null=1")
            .count(),
        1
    );
    assert_eq!(
        runner
            .matches("ASAN_OPTIONS=allocator_may_return_null=1")
            .count(),
        1
    );
    assert!(runner.contains(
        "env -u CUSTOM_LIBFUZZER_PATH -u CUSTOM_LIBFUZZER_STD_CXX -u RUST_LIBFUZZER_DEBUG_PATH \\\n  \"${sanitizer_environment[@]}\" \\\n  cargo"
    ));
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
