// SPDX-License-Identifier: GPL-2.0-only

#![allow(clippy::enum_variant_names, dead_code, unused_imports)]

// The Apache crate cannot run as a standalone Cargo package until the parent
// registers it in the root workspace. Compile its own unit tests through this
// adapter-local consumer meanwhile, so its bounds are exercised in CI.
#[path = "../../../source/crates/filebelt-revision-protocol/src/lib.rs"]
mod revision_protocol;
