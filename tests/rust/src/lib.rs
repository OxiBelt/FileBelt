// SPDX-License-Identifier: Apache-2.0

//! Repository-level contract test support.

#![deny(unsafe_code)]

use std::path::{Path, PathBuf};

/// Returns the repository root for integration tests.
#[must_use]
pub fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root must exist")
}
