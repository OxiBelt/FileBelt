// SPDX-License-Identifier: Apache-2.0

//! Internal library surface for the protocol-neutral mount VFS.

#![deny(unsafe_code)]

#[cfg(feature = "fuzzing")]
mod nfs;

/// Side-effect-free exercises for repository-owned fuzz targets.
#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    /// Exercises bounded NFS handle, principal, digest, and VFS wire behavior.
    pub fn exercise_nfs_vfs_boundary(input: &[u8]) {
        super::nfs::fuzz_exercise(input);
    }
}
