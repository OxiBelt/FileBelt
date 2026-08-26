// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fs;

use filebelt_fuzz::{
    collaboration_wire, mcp_runner_relay, nfs_vfs_boundary, revision_protocol, runtime_config,
    sha256_hex,
};
use filebelt_repository_tests::repository_root;
use toml::Value;

#[test]
fn committed_regressions_replay_through_fuzzer_exercises() {
    let root = repository_root();
    let source = fs::read_to_string(root.join("tests/fixtures/fuzz-regressions/manifest.toml"))
        .expect("regression manifest must exist");
    let manifest = toml::from_str::<Value>(&source).expect("regression manifest is TOML");
    assert_eq!(manifest["schema_version"].as_integer(), Some(1));

    let mut paths = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for case in manifest["case"].as_array().expect("case array") {
        let target = case["target"].as_str().expect("case target");
        targets.insert(target);
        let path = case["path"].as_str().expect("case path");
        assert!(paths.insert(path), "duplicate regression path {path}");
        let expected = case["sha256"].as_str().expect("case SHA-256");
        assert_eq!(
            path.rsplit('/').next(),
            Some(expected),
            "regression filename must be its SHA-256"
        );
        let bytes = fs::read(root.join(path)).expect("regression input must exist");
        assert_eq!(sha256_hex(&bytes), expected);
        match target {
            "nfs_vfs_boundary" => nfs_vfs_boundary(&bytes),
            "mcp_runner_relay" => mcp_runner_relay(&bytes),
            "collaboration_wire" => collaboration_wire(&bytes),
            "revision_protocol" => revision_protocol(&bytes),
            "runtime_config" => runtime_config(&bytes),
            other => panic!("unknown regression target {other}"),
        }
    }
    assert_eq!(paths.len(), 8);
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
