// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

use filebelt_repository_tests::repository_root;

#[test]
fn source_structure_checker_accepts_repository() {
    let root = repository_root();
    let status = Command::new("python3")
        .arg(root.join("tests/scripts/check-source-structure.py"))
        .arg("--repo-root")
        .arg(&root)
        .status()
        .expect("source-structure checker must run");
    assert!(status.success(), "source-structure checker failed");
}

#[test]
fn required_top_level_regions_exist() {
    let root = repository_root();
    for path in [
        "source",
        "protocol",
        "ui",
        "devops",
        "deploy",
        "tests",
        "docs",
        "supply-chain",
        "fuzz",
        "tools",
        "adapters",
    ] {
        assert!(root.join(path).is_dir(), "missing top-level region {path}");
    }
}
