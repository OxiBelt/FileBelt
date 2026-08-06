// SPDX-License-Identifier: Apache-2.0

//! FileBelt MCP broker role smoke probe.

#![deny(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    filebelt_deployment_diagnostics::run_probe("filebelt-mcp-broker")
}
