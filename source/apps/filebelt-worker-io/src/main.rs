// SPDX-License-Identifier: Apache-2.0

//! FileBelt I/O worker role smoke probe.

#![deny(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    filebelt_deployment_diagnostics::run_probe("filebelt-worker-io")
}
