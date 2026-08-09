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
fn transcode_region_is_a_separate_gpl_workspace() {
    let root = repository_root();
    let policy = fs::read_to_string(root.join("supply-chain/license-regions.toml"))
        .expect("license regions");
    assert!(policy.contains(
        "path = \"adapters/transcode\"\nlicense = \"GPL-3.0-or-later\"\nworkspace = \"adapter\""
    ));
}
