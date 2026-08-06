// SPDX-License-Identifier: Apache-2.0

//! Harness for future compile-time unsafe-code policy checks.

#![deny(unsafe_code)]

/// Identifies this package as a Phase 0 workspace placeholder.
pub const BOOTSTRAP_ONLY: bool = true;
