// SPDX-License-Identifier: Apache-2.0

use std::fs;

use filebelt_repository_tests::repository_root;

#[test]
fn canonical_license_files_are_vendored() {
    let root = repository_root();
    for license in [
        "Apache-2.0",
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
fn machine_map_contains_every_adapter_expression() {
    let root = repository_root();
    let policy = fs::read_to_string(root.join("supply-chain/license-regions.toml"))
        .expect("license regions");
    for license in [
        "Apache-2.0",
        "GPL-3.0-or-later",
        "LGPL-3.0-or-later",
        "AGPL-3.0-only",
    ] {
        assert!(policy.contains(license), "missing {license} mapping");
    }
}

#[test]
fn transcode_region_contains_only_governance_material() {
    let root = repository_root();
    let mut names = fs::read_dir(root.join("adapters/transcode"))
        .expect("transcode region")
        .map(|entry| entry.expect("directory entry").file_name())
        .collect::<Vec<_>>();
    names.sort();
    let expected = ["AGENTS.md", "LICENSE", "THIRD_PARTY_NOTICES.md"];
    assert_eq!(
        names,
        expected.map(std::ffi::OsString::from),
        "transcode implementation requires an accepted composition ADR"
    );
}
