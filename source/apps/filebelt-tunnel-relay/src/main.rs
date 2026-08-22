// SPDX-License-Identifier: Apache-2.0

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use filebelt_runtime::install_crypto_provider;
use filebelt_tunnel_relay::{RelayConfig, serve};
use tracing::error;

const ROLE: &str = "filebelt-tunnel-relay";

#[derive(Debug, Parser)]
#[command(name = "filebelt-tunnel-relay", disable_version_flag = true)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "/etc/filebelt/tunnel-relay.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    if matches!(
        std::env::args().nth(1).as_deref(),
        Some("--version" | "--build-info=json")
    ) {
        return filebelt_deployment_diagnostics::run_probe(ROLE);
    }
    tracing_subscriber::fmt()
        .json()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    if install_crypto_provider().is_err() {
        error!(code = "tunnel_relay_crypto_provider_failed");
        return ExitCode::FAILURE;
    }
    let Arguments {
        command: Command::Serve { config },
    } = Arguments::parse();
    let Ok(config) = RelayConfig::load(&config) else {
        error!(code = "tunnel_relay_config_invalid");
        return ExitCode::FAILURE;
    };
    match serve(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            error!(code = "tunnel_relay_stopped");
            ExitCode::FAILURE
        }
    }
}
