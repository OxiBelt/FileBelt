// SPDX-License-Identifier: Apache-2.0

//! FileBelt administrative CLI smoke probe.

#![deny(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    filebelt_deployment_diagnostics::run_probe("filebelt-tools")
}
