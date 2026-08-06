// SPDX-License-Identifier: Apache-2.0

use std::fs;

use filebelt_repository_tests::repository_root;

#[test]
fn required_adrs_are_accepted_and_closed() {
    let root = repository_root();
    let directory = root.join("docs/adr");
    for number in 1..=6 {
        let prefix = format!("{number:04}-");
        let matches = fs::read_dir(&directory)
            .expect("ADR directory")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "expected one ADR-{number:04}");
        let content = fs::read_to_string(matches[0].path()).expect("ADR content");
        assert!(content.contains("- Status: Accepted"));
        assert!(content.contains("## Open questions\n\nNone."));
    }
}

#[test]
fn governance_records_single_maintainer() {
    let root = repository_root();
    let codeowners = fs::read_to_string(root.join(".github/CODEOWNERS")).expect("CODEOWNERS");
    let governance = fs::read_to_string(root.join("GOVERNANCE.md")).expect("governance");
    assert!(codeowners.contains("@PiQuark6046"));
    assert!(governance.contains("single-maintainer"));
}
