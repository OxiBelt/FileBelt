// SPDX-License-Identifier: Apache-2.0

use std::fs;

use filebelt_repository_tests::repository_root;

fn contains_adapter_member(manifest: &str) -> bool {
    let mut in_members = false;
    manifest.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with("members") {
            in_members = true;
        } else if in_members && trimmed == "]" {
            in_members = false;
        }
        in_members && trimmed.starts_with('"') && trimmed.contains("adapters/")
    })
}

#[test]
fn root_workspace_does_not_contain_adapter_members() {
    let root = repository_root();
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("root Cargo.toml");
    assert!(!contains_adapter_member(&manifest));
}

#[test]
fn detector_rejects_an_adapter_member() {
    let fixture = "[workspace]\nmembers = [\n  \"adapters/smb\",\n]\n";
    assert!(contains_adapter_member(fixture));
}

#[test]
fn root_node_workspace_excludes_adapters() {
    let root = repository_root();
    let workspace = fs::read_to_string(root.join("pnpm-workspace.yaml")).expect("pnpm workspace");
    assert!(!workspace.contains("adapters/"));
}
