// SPDX-License-Identifier: Apache-2.0

//! FileBelt media-controller entry point.

#![deny(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    filebelt_media_controller::run()
}
