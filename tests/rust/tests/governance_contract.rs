// SPDX-License-Identifier: Apache-2.0

use std::fs;

use filebelt_repository_tests::repository_root;

#[test]
fn living_specifications_replace_decision_records() {
    let root = repository_root();
    for relative in [
        "docs/README.md",
        "docs/NamespaceAndAuthorization.md",
        "docs/InterfacesAndCapabilities.md",
        "docs/StorageAndDurability.md",
        "docs/RuntimeAndDeployment.md",
    ] {
        assert!(
            root.join(relative).is_file(),
            "missing living specification {relative}"
        );
    }
    assert!(
        !root.join("docs/adr").exists(),
        "legacy decision-record directory exists"
    );
}

#[test]
fn contributor_and_agent_guidance_have_explicit_audiences() {
    let root = repository_root();
    let contributing =
        fs::read_to_string(root.join("CONTRIBUTING.md")).expect("contributor guidance");
    let agents = fs::read_to_string(root.join("AGENTS.md")).expect("agent guidance");

    assert!(contributing.contains("human-facing source of truth"));
    assert!(contributing.contains("people do not need to read them"));
    assert!(contributing.contains("## Design and boundary review"));
    assert!(!contributing.contains("Enter Plan Mode"));

    assert!(agents.contains("automated-agent guidance"));
    assert!(agents.contains("CONTRIBUTING.md"));
    assert!(agents.contains("docs/README.md"));
    assert!(agents.contains("Enter Plan Mode"));
}

#[test]
fn governance_records_single_maintainer() {
    let root = repository_root();
    let codeowners = fs::read_to_string(root.join(".github/CODEOWNERS")).expect("CODEOWNERS");
    let governance = fs::read_to_string(root.join("GOVERNANCE.md")).expect("governance");
    assert!(codeowners.contains("@PiQuark6046"));
    assert!(governance.contains("single-maintainer"));
}
