// SPDX-License-Identifier: Apache-2.0

//! FileBelt Phase 2 control-plane API.

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod app;
mod auth;
mod error;
mod policy;
mod resources;

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
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
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
    match runtime.block_on(app::serve(&arguments.config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error, "FileBelt API stopped");
            ExitCode::FAILURE
        }
    }
}
