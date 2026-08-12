// SPDX-License-Identifier: Apache-2.0

//! FileBelt Phase 2 control-plane API.

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use filebelt_control_protocol::Config;
use filebelt_runtime::{init_telemetry, install_crypto_provider};

mod app;
mod auth;
mod documents;
mod error;
mod mcp;
mod media;
mod mounts;
mod policy;
mod resources;
mod revisions;

#[derive(Debug, Parser)]
#[command(name = "filebelt-api", disable_version_flag = true)]
struct Arguments {
    /// Versioned FileBelt runtime configuration.
    #[arg(long, global = true, default_value = "/etc/filebelt/filebelt.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Copy, Debug, Subcommand)]
enum Command {
    /// Run the HTTP API service.
    Serve,
}

fn main() -> ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if matches!(arguments.as_slice(), [argument] if argument == "--version" || argument == "--build-info=json")
    {
        return filebelt_deployment_diagnostics::run_probe("filebelt-api");
    }
    let arguments = Arguments::parse();
    let _command = arguments.command.unwrap_or(Command::Serve);
    let config = match Config::load(&arguments.config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("filebelt-api: invalid FileBelt configuration: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = install_crypto_provider() {
        eprintln!("filebelt-api: {error}");
        return ExitCode::FAILURE;
    }
    let _telemetry = match init_telemetry(&config.telemetry, "filebelt-api") {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("filebelt-api: {error}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("filebelt-api: cannot initialize runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(app::serve(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error, "FileBelt API stopped");
            ExitCode::FAILURE
        }
    }
}
