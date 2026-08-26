// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

use filebelt_repository_tests::repository_root;

fn rust_files(path: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).expect("source directory must be readable") {
        let path = entry.expect("source entry must be readable").path();
        if path.is_dir() {
            rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

#[test]
fn collaboration_panic_hook_preserves_the_containment_boundary() {
    let root = repository_root();
    let source_root = root.join("source/apps/filebelt-collaboration/src");
    let mut files = Vec::new();
    rust_files(&source_root, &mut files);
    files.sort();

    let hook_owners = files
        .iter()
        .filter(|path| {
            let source = fs::read_to_string(path).expect("Rust source must be UTF-8");
            source.contains("std::panic::set_hook") || source.contains("std::panic::take_hook")
        })
        .map(|path| path.strip_prefix(&root).unwrap().to_path_buf())
        .collect::<Vec<_>>();
    assert_eq!(
        hook_owners,
        [PathBuf::from(
            "source/apps/filebelt-collaboration/src/update_decoder.rs"
        )]
    );

    let main = fs::read_to_string(source_root.join("main.rs")).unwrap();
    assert!(main.contains("filebelt_collaboration::install_decoder_panic_containment_hook();"));

    let server = fs::read_to_string(source_root.join("server.rs")).unwrap();
    assert!(
        server
            .matches("freeze_corrupt_room(state, key).await;")
            .count()
            >= 3,
        "snapshot read, snapshot decode, and durable replay failures must freeze the epoch"
    );
    assert!(
        server.contains("let bytes = match state.io.read_object(claims, &snapshot.object).await")
    );
    assert!(
        server.contains(
            "collaboration_freeze(state.tenant_id, key.room_id, epoch, \"corrupt_state\")"
        )
    );
    assert!(server.contains("freeze_claimed_room(state, claims, \"corrupt_state\").await;"));

    let target = fs::read_to_string(root.join("fuzz/fuzz_targets/collaboration_wire.rs")).unwrap();
    assert!(target.contains("init: filebelt_fuzz::install_collaboration_panic_hook()"));
}
